#[derive(Debug, Clone)]
pub enum Observed {
    Cycles {
        total: u64,
        how: String,
    },

    Absent {
        why: String,
    },
}

impl Observed {
    pub fn per_hash(&self, hashes: u64) -> Option<f64> {
        match self {
            Observed::Cycles { total, .. } if hashes > 0 => Some(*total as f64 / hashes as f64),
            _ => None,
        }
    }
}

pub struct Probe {
    #[cfg(target_os = "windows")]
    pdh: Option<win::Pdh>,
}

impl Probe {
    pub fn start(cpus: &[usize]) -> Probe {
        #[cfg(target_os = "windows")]
        {
            Probe { pdh: win::Pdh::open(cpus) }
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = cpus;
            Probe {}
        }
    }

    pub fn finish(self, thread_cycles: &[Option<u64>], secs: f64) -> Observed {
        if !thread_cycles.is_empty() && thread_cycles.iter().all(|c| c.is_some()) {
            let total: u64 = thread_cycles.iter().map(|c| c.unwrap_or(0)).sum();
            if total > 0 {
                return Observed::Cycles {
                    total,
                    how: "core cycles from the PMU (perf_event_open, PERF_COUNT_HW_CPU_CYCLES, \
                          one counter per worker thread)"
                        .into(),
                };
            }
        }
        #[cfg(target_os = "windows")]
        {
            if let Some(pdh) = self.pdh {
                match pdh.finish(secs) {
                    Ok((total, how)) => return Observed::Cycles { total, how },
                    Err(why) => return Observed::Absent { why },
                }
            }
        }
        #[cfg(not(target_os = "windows"))]
        let _ = secs;
        Observed::Absent { why: absent_reason() }
    }
}

pub struct ThreadCounter {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fd: i32,
}

impl ThreadCounter {
    pub fn open() -> Option<ThreadCounter> {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            linux::open().map(|fd| ThreadCounter { fd })
        }
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        {
            None
        }
    }

    pub fn read(&self) -> Option<u64> {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            linux::read_counter(self.fd)
        }
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        {
            None
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
impl Drop for ThreadCounter {
    fn drop(&mut self) {
        linux::close(self.fd);
    }
}

pub fn absent_reason() -> String {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        linux::absent_reason()
    }
    #[cfg(target_os = "windows")]
    {
        "the PDH performance counters could not be opened, and Windows has no other \
         core-cycle source for an unprivileged process (QueryThreadCycleTime counts TSC \
         reference ticks, which are not core cycles under frequency scaling)"
            .to_string()
    }
    #[cfg(target_os = "macos")]
    {
        "macOS exposes no per-thread cycle counter to an unprivileged process; \
         mach_absolute_time is a reference clock, not a cycle count"
            .to_string()
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "windows",
        target_os = "macos"
    )))]
    {
        format!("no cycle counter is wired up for {}", std::env::consts::OS)
    }
}

pub fn invariant_tsc() -> Option<bool> {
    #[cfg(target_arch = "x86_64")]
    {
        use core::arch::x86_64::__cpuid;

        let max = __cpuid(0x8000_0000).eax;
        if max < 0x8000_0007 {
            return Some(false);
        }
        let edx = __cpuid(0x8000_0007).edx;
        Some(edx & (1 << 8) != 0)
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        None
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod linux {
    #[cfg(target_arch = "x86_64")]
    const NR_PERF_EVENT_OPEN: core::ffi::c_long = 298;
    #[cfg(target_arch = "aarch64")]
    const NR_PERF_EVENT_OPEN: core::ffi::c_long = 241;

    extern "C" {
        fn syscall(num: core::ffi::c_long, ...) -> core::ffi::c_long;

        #[link_name = "read"]
        fn sys_read(fd: i32, buf: *mut u8, count: usize) -> isize;
        #[link_name = "close"]
        fn sys_close(fd: i32) -> i32;
    }

    const ATTR_SIZE: usize = 64;

    fn attr(flags: u64) -> [u8; ATTR_SIZE] {
        let mut a = [0u8; ATTR_SIZE];

        a[4..8].copy_from_slice(&(ATTR_SIZE as u32).to_le_bytes());

        a[40..48].copy_from_slice(&flags.to_le_bytes());
        a
    }

    const EXCLUDE_KERNEL_HV: u64 = (1 << 5) | (1 << 6);

    fn open_with(flags: u64) -> Result<i32, std::io::Error> {
        let a = attr(flags);

        // SAFETY: perf_event_open reads ATTR_SIZE bytes from a, which is that long and live.
        let fd = unsafe {
            syscall(
                NR_PERF_EVENT_OPEN,
                a.as_ptr() as core::ffi::c_long,
                0 as core::ffi::c_long,
                -1 as core::ffi::c_long,
                -1 as core::ffi::c_long,
                8 as core::ffi::c_long,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(fd as i32)
    }

    pub fn open() -> Option<i32> {
        open_with(0).or_else(|_| open_with(EXCLUDE_KERNEL_HV)).ok()
    }

    pub fn read_counter(fd: i32) -> Option<u64> {
        let mut buf = [0u8; 8];

        // SAFETY: reads at most 8 bytes into an 8-byte local from a descriptor this module opened.
        let n = unsafe { sys_read(fd, buf.as_mut_ptr(), 8) };
        (n == 8).then(|| u64::from_le_bytes(buf))
    }

    pub fn close(fd: i32) {
        // SAFETY: closes a descriptor this module opened and is dropping.
        unsafe { sys_close(fd) };
    }

    pub fn absent_reason() -> String {
        let errno = match open_with(EXCLUDE_KERNEL_HV) {
            Ok(fd) => {
                close(fd);
                return "the cycle counter opened but read back nothing usable, which is what \
                        a guest with an unvirtualised PMU does"
                    .to_string();
            }
            Err(e) => e,
        };
        let paranoid = std::fs::read_to_string("/proc/sys/kernel/perf_event_paranoid")
            .ok()
            .and_then(|s| s.trim().parse::<i32>().ok());

        let context = match (errno.raw_os_error(), paranoid) {
            (Some(2 | 19 | 95), _) => {
                " - the hardware cycle event does not exist here, which is what a KVM or QEMU \
                 guest without a virtualised PMU looks like"
                    .to_string()
            }
            (_, Some(p)) if p > 2 => format!(
                " - /proc/sys/kernel/perf_event_paranoid is {p}; `sysctl \
                 kernel.perf_event_paranoid=2` permits a user-mode counter"
            ),
            (_, Some(p)) => format!(
                " - perf_event_paranoid is {p}, so the sysctl is not what refused: a seccomp \
                 filter, a container profile or a missing PMU is"
            ),
            (_, None) => " - and /proc/sys/kernel/perf_event_paranoid is unreadable".to_string(),
        };
        format!("perf_event_open(PERF_COUNT_HW_CPU_CYCLES): {errno}{context}")
    }
}

#[cfg(target_os = "windows")]
mod win {
    const FMT_DOUBLE: u32 = 0x0000_0200;

    #[link(name = "kernel32")]
    extern "system" {
        fn LoadLibraryA(name: *const u8) -> isize;
        fn GetProcAddress(module: isize, name: *const u8) -> *const core::ffi::c_void;
    }

    type OpenQuery = unsafe extern "system" fn(*const u16, usize, *mut isize) -> u32;
    type AddCounter = unsafe extern "system" fn(isize, *const u16, usize, *mut isize) -> u32;
    type Collect = unsafe extern "system" fn(isize) -> u32;
    type GetValue = unsafe extern "system" fn(isize, u32, *mut u32, *mut CounterValue) -> u32;
    type CloseQuery = unsafe extern "system" fn(isize) -> u32;

    #[repr(C)]
    #[derive(Default, Clone, Copy)]
    struct CounterValue {
        status: u32,
        _pad: u32,
        value: f64,
    }

    struct Api {
        open: OpenQuery,
        add: AddCounter,
        collect: Collect,
        get: GetValue,
        close: CloseQuery,
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(core::iter::once(0)).collect()
    }

    fn load() -> Option<Api> {
        // SAFETY: LoadLibraryA takes a NUL-terminated name, and c"..." is exactly that.
        let m = unsafe { LoadLibraryA(c"pdh.dll".to_bytes_with_nul().as_ptr()) };
        if m == 0 {
            return None;
        }

        type Raw = *const core::ffi::c_void;

        // SAFETY: each name is a NUL-terminated c"..." literal, and every symbol we transmute has
        // the ABI its fn-pointer type declares.
        unsafe {
            let sym = |n: &core::ffi::CStr| -> Option<Raw> {
                let p = GetProcAddress(m, n.to_bytes_with_nul().as_ptr());
                (!p.is_null()).then_some(p)
            };
            Some(Api {
                open: core::mem::transmute::<Raw, OpenQuery>(sym(c"PdhOpenQueryW")?),
                add: core::mem::transmute::<Raw, AddCounter>(sym(c"PdhAddEnglishCounterW")?),
                collect: core::mem::transmute::<Raw, Collect>(sym(c"PdhCollectQueryData")?),
                get: core::mem::transmute::<Raw, GetValue>(sym(c"PdhGetFormattedCounterValue")?),
                close: core::mem::transmute::<Raw, CloseQuery>(sym(c"PdhCloseQuery")?),
            })
        }
    }

    pub struct Pdh {
        api: Api,
        query: isize,
        counters: Vec<(usize, isize, isize)>,
    }

    impl Pdh {
        pub fn open(cpus: &[usize]) -> Option<Pdh> {
            let api = load()?;
            let mut query: isize = 0;

            // SAFETY: the documented call; a null data source means a live query, query is a live out.
            if unsafe { (api.open)(core::ptr::null(), 0, &mut query) } != 0 {
                return None;
            }
            let mut counters = Vec::new();
            for cpu in cpus {
                let inst = format!("{},{}", cpu / 64, cpu % 64);
                let mut pct: isize = 0;
                let mut hz: isize = 0;
                let p = wide(&format!("\\Processor Information({inst})\\% Processor Performance"));
                let f = wide(&format!("\\Processor Information({inst})\\Processor Frequency"));

                // SAFETY: both paths are live NUL-terminated UTF-16 buffers; pct/hz are live outs.
                let ok = unsafe {
                    (api.add)(query, p.as_ptr(), 0, &mut pct) == 0
                        && (api.add)(query, f.as_ptr(), 0, &mut hz) == 0
                };
                if !ok {
                    // SAFETY: unwind the half-built query before bailing.
                    unsafe { (api.close)(query) };
                    return None;
                }
                counters.push((*cpu, pct, hz));
            }

            // SAFETY: first sample of the query opened above.
            if unsafe { (api.collect)(query) } != 0 {
                // SAFETY: close on the failure path too - open() must not leak a handle.
                unsafe { (api.close)(query) };
                return None;
            }
            Some(Pdh { api, query, counters })
        }

        pub fn finish(self, secs: f64) -> Result<(u64, String), String> {
            // SAFETY: samples the query this Pdh owns.
            if unsafe { (self.api.collect)(self.query) } != 0 {
                self.close();
                return Err("PdhCollectQueryData failed on the closing sample".into());
            }
            let mut total = 0f64;
            let mut lowest = f64::MAX;
            let mut highest = 0f64;
            for (cpu, pct, hz) in &self.counters {
                let (Some(pct), Some(hz)) = (self.value(*pct), self.value(*hz)) else {
                    self.close();
                    return Err(format!("no counter value for CPU {cpu}"));
                };
                let ghz = hz * pct / 100.0 / 1000.0;

                if !(0.1..=8.0).contains(&ghz) {
                    self.close();
                    return Err(format!(
                        "PDH gave CPU {cpu} a nominal {hz:.0} MHz at {pct:.1}% of nominal, \
                         i.e. {ghz:.2} GHz, which is not a frequency this pairing should \
                         produce; refusing to derive cycles from it"
                    ));
                }
                lowest = lowest.min(ghz);
                highest = highest.max(ghz);
                total += ghz * 1e9 * secs;
            }
            self.close();
            if total <= 0.0 {
                return Err("PDH reported no processor activity across the window".into());
            }
            let spread = if lowest < highest {
                format!(", {lowest:.2}-{highest:.2} GHz across them")
            } else {
                format!(" at {lowest:.2} GHz")
            };
            Ok((
                total as u64,
                format!(
                    "core cycles from PDH: nominal frequency x % Processor Performance \
                     (the APERF/MPERF ratio) over {} processors{spread}",
                    self.counters.len()
                ),
            ))
        }

        fn value(&self, counter: isize) -> Option<f64> {
            let mut v = CounterValue::default();
            let mut kind: u32 = 0;

            // SAFETY: writes one PDH_FMT_COUNTERVALUE through the out pointer; kind/v are live locals.
            let rc = unsafe { (self.api.get)(counter, FMT_DOUBLE, &mut kind, &mut v) };
            (rc == 0 && v.status == 0).then_some(v.value)
        }

        fn close(&self) {
            // SAFETY: closes the query this Pdh owns; called once, from finish or the error paths.
            unsafe { (self.api.close)(self.query) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_clock_explains_itself() {
        let why = absent_reason();
        assert!(why.len() > 30, "the reason must be actionable, got {why:?}");
    }

    #[test]
    fn no_counters_is_absent_not_zero() {
        let p = Probe::start(&[]);
        let o = p.finish(&[], 1.0);
        assert!(o.per_hash(1000).is_none() || matches!(o, Observed::Cycles { .. }));
        if let Observed::Absent { why } = &o {
            assert!(!why.is_empty());
        }
    }

    #[test]
    fn one_missing_counter_voids_sum() {
        let o = Probe::start(&[]).finish(&[Some(1_000), None, Some(1_000)], 1.0);
        assert!(matches!(o, Observed::Absent { .. }), "a partial sum must not be reported");
    }

    #[test]
    fn cycles_per_hash_refuses_zero_divisor() {
        let o = Observed::Cycles { total: 4_000, how: "test".into() };
        assert_eq!(o.per_hash(2), Some(2_000.0));
        assert_eq!(o.per_hash(0), None);
    }
}
