use super::topo::Topology;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Placement {
    Pinned(usize),
    Restricted(Vec<usize>),
    Unsupported(&'static str),
    Failed(String),
}

impl Placement {
    pub fn describe(&self) -> String {
        match self {
            Placement::Pinned(c) => format!("pinned to CPU {c}"),
            Placement::Restricted(v) => {
                format!("confined to CPUs {} (the OS places threads inside that set)",
                    super::topo::fmt_list(v))
            }
            Placement::Unsupported(why) => format!("not pinned: {why}"),
            Placement::Failed(e) => format!("pin failed: {e}"),
        }
    }

    pub fn is_pinned(&self) -> bool {
        matches!(self, Placement::Pinned(_))
    }
}

pub const PRIORITY_LEVELS: u8 = 5;

pub fn set_priority(level: u8) -> Result<String, String> {
    if level > PRIORITY_LEVELS {
        return Err(format!("--cpu-priority takes 0..{PRIORITY_LEVELS}, not {level}"));
    }
    set_priority_impl(level)
}

pub fn page_size() -> usize {
    page_size_impl()
}

#[derive(Debug, Clone)]
pub struct HugePages {
    pub size_kib: Option<u32>,
    pub state: String,
    pub likely: bool,
}

pub fn huge_pages() -> HugePages {
    huge_pages_impl()
}

pub fn allowed_cpus() -> Option<Vec<usize>> {
    allowed_cpus_impl()
}

pub fn brand_string() -> Option<String> {
    #[cfg(target_arch = "x86_64")]
    {
        use core::arch::x86_64::__cpuid;

        let max = __cpuid(0x8000_0000).eax;
        if max < 0x8000_0004 {
            return None;
        }
        let mut bytes = Vec::with_capacity(48);
        for leaf in 0x8000_0002u32..=0x8000_0004 {
            let r = __cpuid(leaf);
            for reg in [r.eax, r.ebx, r.ecx, r.edx] {
                bytes.extend_from_slice(&reg.to_le_bytes());
            }
        }
        let s = String::from_utf8_lossy(&bytes).trim_matches(char::from(0)).trim().to_string();
        (!s.is_empty()).then_some(s)
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        None
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod sys {
    use super::{HugePages, Placement, Topology};

    extern "C" {
        fn sched_setaffinity(pid: i32, cpusetsize: usize, mask: *const u64) -> i32;
        fn sched_getaffinity(pid: i32, cpusetsize: usize, mask: *mut u64) -> i32;
        fn setpriority(which: i32, who: u32, prio: i32) -> i32;
        fn sysconf(name: i32) -> i64;
        fn sched_getcpu() -> i32;
    }

    pub fn current_cpu() -> Option<(u16, usize)> {
        // SAFETY: sched_getcpu is argument-free and reads this thread's scheduler state.
        let c = unsafe { sched_getcpu() };

        (c >= 0).then_some((0, c as usize))
    }

    const SC_PAGESIZE: i32 = 30;

    const PRIO_PROCESS: i32 = 0;

    const MASK_WORDS: usize = 16;

    fn mask_of(cpus: &[usize]) -> Result<[u64; MASK_WORDS], String> {
        let mut m = [0u64; MASK_WORDS];
        for c in cpus {
            let (w, b) = (c / 64, c % 64);
            if w >= MASK_WORDS {
                return Err(format!("CPU {c} is past the {} this build can address", MASK_WORDS * 64));
            }
            m[w] |= 1 << b;
        }
        Ok(m)
    }

    pub fn pin_current_thread(cpu: usize, _group: u16) -> Placement {
        let m = match mask_of(&[cpu]) {
            Ok(m) => m,
            Err(e) => return Placement::Failed(e),
        };

        // SAFETY: sched_setaffinity reads cpusetsize bytes from m; we pass m's exact size.
        if unsafe { sched_setaffinity(0, core::mem::size_of_val(&m), m.as_ptr()) } != 0 {
            return Placement::Failed(format!(
                "sched_setaffinity(cpu {cpu}): {}",
                std::io::Error::last_os_error()
            ));
        }
        Placement::Pinned(cpu)
    }

    pub fn restrict_process(cpus: &[usize], _topo: &Topology) -> Placement {
        let m = match mask_of(cpus) {
            Ok(m) => m,
            Err(e) => return Placement::Failed(e),
        };

        // SAFETY: as pin_current_thread; m is a live mask of the size we pass.
        if unsafe { sched_setaffinity(0, core::mem::size_of_val(&m), m.as_ptr()) } != 0 {
            return Placement::Failed(format!(
                "sched_setaffinity: {}",
                std::io::Error::last_os_error()
            ));
        }
        Placement::Restricted(cpus.to_vec())
    }

    pub fn allowed_cpus() -> Option<Vec<usize>> {
        let mut m = [0u64; MASK_WORDS];

        // SAFETY: sched_getaffinity writes at most cpusetsize bytes into m; we pass m's size.
        if unsafe { sched_getaffinity(0, core::mem::size_of_val(&m), m.as_mut_ptr()) } != 0 {
            return None;
        }
        let mut out = Vec::new();
        for (w, word) in m.iter().enumerate() {
            for b in 0..64 {
                if word >> b & 1 == 1 {
                    out.push(w * 64 + b);
                }
            }
        }
        Some(out)
    }

    pub fn set_priority(level: u8) -> Result<String, String> {
        let nice = [19, 10, 0, -5, -10, -15][level as usize];

        // SAFETY: three scalar args, no memory.
        if unsafe { setpriority(PRIO_PROCESS, 0, nice) } != 0 {
            let e = std::io::Error::last_os_error();
            return Err(format!(
                "setpriority(nice {nice}): {e} - a nice below 0 needs CAP_SYS_NICE or root"
            ));
        }
        Ok(format!("nice {nice}"))
    }

    pub fn page_size() -> usize {
        // SAFETY: one scalar in, one out; sysconf touches nothing.
        let n = unsafe { sysconf(SC_PAGESIZE) };
        if n > 0 { n as usize } else { 4096 }
    }

    pub fn huge_pages() -> HugePages {
        let meminfo = std::fs::read_to_string("/proc/meminfo").unwrap_or_default();
        let field = |k: &str| -> Option<u64> {
            meminfo
                .lines()
                .find(|l| l.starts_with(k))?
                .split_whitespace()
                .nth(1)?
                .parse()
                .ok()
        };
        let size_kib = field("Hugepagesize:").map(|k| k as u32);
        let free = field("HugePages_Free:").unwrap_or(0);
        let thp = std::fs::read_to_string("/sys/kernel/mm/transparent_hugepage/enabled")
            .unwrap_or_default();
        let thp_always = thp.contains("[always]");
        let thp_madvise = thp.contains("[madvise]");

        let (state, likely) = match (free > 0, thp_always, thp_madvise) {
            (true, _, _) => (
                format!("{free} explicit huge pages free in the pool (vm.nr_hugepages)"),
                true,
            ),
            (false, true, _) => (
                "no hugetlb pool, but transparent huge pages are [always]".to_string(),
                true,
            ),
            (false, false, true) => (
                "no hugetlb pool; transparent huge pages are [madvise], so an allocation \
                 gets them only if it asks with madvise(MADV_HUGEPAGE)"
                    .to_string(),
                true,
            ),
            (false, false, false) => (
                "no hugetlb pool and transparent huge pages are off; a request cannot be \
                 served without `sysctl vm.nr_hugepages=N` or enabling THP"
                    .to_string(),
                false,
            ),
        };
        HugePages { size_kib, state, likely }
    }
}

#[cfg(target_os = "windows")]
mod sys {
    use super::{HugePages, Placement, Topology};

    use core::ffi::c_void;

    #[link(name = "kernel32")]
    extern "system" {
        fn GetCurrentThread() -> isize;

        fn GetCurrentProcess() -> *mut c_void;
        fn SetThreadGroupAffinity(
            thread: isize,
            affinity: *const GroupAffinity,
            previous: *mut GroupAffinity,
        ) -> i32;
        fn SetProcessAffinityMask(process: *mut c_void, mask: usize) -> i32;
        fn SetPriorityClass(process: *mut c_void, class: u32) -> i32;
        fn GetLogicalProcessorInformationEx(rel: u32, buf: *mut u8, len: *mut u32) -> i32;
        fn GetSystemInfo(info: *mut SystemInfo);
        fn GetLargePageMinimum() -> usize;
        fn GetLastError() -> u32;

        fn GetCurrentProcessorNumberEx(n: *mut ProcessorNumber);
    }

    #[repr(C)]
    #[derive(Default, Clone, Copy)]
    struct ProcessorNumber {
        group: u16,
        number: u8,
        reserved: u8,
    }

    pub fn current_cpu() -> Option<(u16, usize)> {
        let mut n = ProcessorNumber::default();

        // SAFETY: writes one PROCESSOR_NUMBER through a live out pointer.
        unsafe { GetCurrentProcessorNumberEx(&mut n) };

        Some((n.group, n.number as usize))
    }

    #[repr(C)]
    #[derive(Default, Clone, Copy)]
    struct GroupAffinity {
        mask: usize,
        group: u16,
        reserved: [u16; 3],
    }

    #[repr(C)]
    #[derive(Default)]
    struct SystemInfo {
        oem_id: u32,
        page_size: u32,
        min_app_address: usize,
        max_app_address: usize,
        active_processor_mask: usize,
        number_of_processors: u32,
        processor_type: u32,
        allocation_granularity: u32,
        processor_level: u16,
        processor_revision: u16,
    }

    const RELATION_ALL: u32 = 0xffff;

    const ERROR_INSUFFICIENT_BUFFER: u32 = 122;

    pub fn pin_current_thread(cpu: usize, group: u16) -> Placement {
        let a = GroupAffinity { mask: 1usize << (cpu % 64), group, reserved: [0; 3] };

        // SAFETY: reads one GROUP_AFFINITY through a live pointer; the thread handle is a pseudo-handle.
        let ok = unsafe { SetThreadGroupAffinity(GetCurrentThread(), &a, core::ptr::null_mut()) };
        if ok == 0 {
            // SAFETY: GetLastError reads a per-thread slot, no args.
            let e = unsafe { GetLastError() };
            return Placement::Failed(format!(
                "SetThreadGroupAffinity(group {group}, CPU {cpu}) failed with error {e}"
            ));
        }
        Placement::Pinned(cpu)
    }

    pub fn restrict_process(cpus: &[usize], topo: &Topology) -> Placement {
        if cpus.iter().any(|c| topo.cpu(*c).map(|x| x.group).unwrap_or(0) != 0) {
            return Placement::Failed(
                "this pin list spans more than one Windows processor group, and \
                 SetProcessAffinityMask can only address the group the process is in; \
                 use --bench, which pins each worker individually, or keep the list \
                 inside CPUs 0-63"
                    .into(),
            );
        }
        let mut mask = 0usize;
        for c in cpus {
            if *c >= usize::BITS as usize {
                return Placement::Failed(format!("CPU {c} is outside a 64-bit affinity mask"));
            }
            mask |= 1usize << c;
        }

        // SAFETY: pseudo-handle plus a scalar mask, no pointers.
        if unsafe { SetProcessAffinityMask(GetCurrentProcess(), mask) } == 0 {
            // SAFETY: last-error read, nothing dereferenced.
            let e = unsafe { GetLastError() };
            return Placement::Failed(format!("SetProcessAffinityMask failed with error {e}"));
        }
        Placement::Restricted(cpus.to_vec())
    }

    pub fn allowed_cpus() -> Option<Vec<usize>> {
        None
    }

    pub fn set_priority(level: u8) -> Result<String, String> {
        const CLASSES: [(u32, &str); 6] = [
            (0x0000_0040, "IDLE_PRIORITY_CLASS"),
            (0x0000_4000, "BELOW_NORMAL_PRIORITY_CLASS"),
            (0x0000_0020, "NORMAL_PRIORITY_CLASS"),
            (0x0000_8000, "ABOVE_NORMAL_PRIORITY_CLASS"),
            (0x0000_0080, "HIGH_PRIORITY_CLASS"),
            (0x0000_0080, "HIGH_PRIORITY_CLASS (5 is capped here; REALTIME starves the \
                            input and paging threads and the machine stops answering)"),
        ];
        let (class, name) = CLASSES[level as usize];

        // SAFETY: pseudo-handle and a class constant, both scalars.
        if unsafe { SetPriorityClass(GetCurrentProcess(), class) } == 0 {
            // SAFETY: GetLastError, again - pure read of thread state.
            let e = unsafe { GetLastError() };
            return Err(format!("SetPriorityClass({name}) failed with error {e}"));
        }
        Ok(name.to_string())
    }

    pub fn page_size() -> usize {
        let mut info = SystemInfo::default();

        // SAFETY: writes one SYSTEM_INFO through a live out pointer.
        unsafe { GetSystemInfo(&mut info) };
        if info.page_size > 0 { info.page_size as usize } else { 4096 }
    }

    pub fn huge_pages() -> HugePages {
        // SAFETY: takes and touches nothing; returns 0 where large pages are unsupported.
        let min = unsafe { GetLargePageMinimum() };
        if min == 0 {
            return HugePages {
                size_kib: None,
                state: "this Windows or this processor does not support large pages".into(),
                likely: false,
            };
        }
        HugePages {
            size_kib: Some((min / 1024) as u32),

            state: format!(
                "Windows supports {} KiB large pages; using them needs the \
                 \"Lock pages in memory\" right (SeLockMemoryPrivilege), which is off \
                 for a normal account, so the allocation is what finds out",
                min / 1024
            ),
            likely: true,
        }
    }

    pub fn logical_processor_information() -> Result<Vec<u8>, String> {
        let mut len: u32 = 0;

        // SAFETY: documented two-call idiom - a null buffer just reports the length into len.
        unsafe { GetLogicalProcessorInformationEx(RELATION_ALL, core::ptr::null_mut(), &mut len) };

        // SAFETY: last-error read.
        let err = unsafe { GetLastError() };
        if len == 0 {
            return Err(format!("size probe returned nothing (error {err})"));
        }
        if err != ERROR_INSUFFICIENT_BUFFER {
            return Err(format!("size probe failed with error {err}"));
        }
        let mut buf = vec![0u8; len as usize];

        // SAFETY: buf is len bytes and len is the count the probe asked for.
        let ok = unsafe {
            GetLogicalProcessorInformationEx(RELATION_ALL, buf.as_mut_ptr(), &mut len)
        };
        if ok == 0 {
            // SAFETY: same last-error read as everywhere else in this module.
            return Err(format!("failed with error {}", unsafe { GetLastError() }));
        }
        buf.truncate(len as usize);
        Ok(buf)
    }
}

#[cfg(target_os = "macos")]
mod sys {
    use super::{HugePages, Placement, Topology};

    extern "C" {
        fn setpriority(which: i32, who: u32, prio: i32) -> i32;
        fn sysconf(name: i32) -> i64;
        fn sysctlbyname(
            name: *const core::ffi::c_char,
            oldp: *mut core::ffi::c_void,
            oldlenp: *mut usize,
            newp: *mut core::ffi::c_void,
            newlen: usize,
        ) -> i32;
    }

    const SC_PAGESIZE: i32 = 29;
    const PRIO_PROCESS: i32 = 0;

    const NO_AFFINITY: &str =
        "macOS has no affinity API - THREAD_AFFINITY_POLICY is a cache-sharing hint, not a \
         placement, and Apple Silicon ignores it entirely";

    pub fn pin_current_thread(_cpu: usize, _group: u16) -> Placement {
        Placement::Unsupported(NO_AFFINITY)
    }

    pub fn current_cpu() -> Option<(u16, usize)> {
        None
    }

    pub fn restrict_process(_cpus: &[usize], _topo: &Topology) -> Placement {
        Placement::Unsupported(NO_AFFINITY)
    }

    pub fn allowed_cpus() -> Option<Vec<usize>> {
        None
    }

    pub fn set_priority(level: u8) -> Result<String, String> {
        let nice = [19, 10, 0, -5, -10, -15][level as usize];

        // SAFETY: scalars only.
        if unsafe { setpriority(PRIO_PROCESS, 0, nice) } != 0 {
            return Err(format!(
                "setpriority(nice {nice}): {} - a nice below 0 needs root",
                std::io::Error::last_os_error()
            ));
        }
        Ok(format!("nice {nice}"))
    }

    pub fn page_size() -> usize {
        // SAFETY: sysconf, one scalar each way.
        let n = unsafe { sysconf(SC_PAGESIZE) };
        if n > 0 { n as usize } else { 4096 }
    }

    pub fn huge_pages() -> HugePages {
        HugePages {
            size_kib: Some(2048),
            state: "macOS has no hugetlb pool; the only large-page facility is \
                    VM_FLAGS_SUPERPAGE_SIZE_2MB, which is x86_64-only and gone on Apple \
                    Silicon, where the kernel's own 16 KiB base page already covers four \
                    times the ground a 4 KiB page does"
                .into(),
            likely: false,
        }
    }

    pub fn sysctl_i64(name: &str) -> Option<i64> {
        let c = std::ffi::CString::new(name).ok()?;
        let mut v: i64 = 0;
        let mut len = core::mem::size_of::<i64>();

        // SAFETY: name is a live NUL-terminated string; v/len are live locals of matching size.
        let rc = unsafe {
            sysctlbyname(
                c.as_ptr(),
                &mut v as *mut i64 as *mut core::ffi::c_void,
                &mut len,
                core::ptr::null_mut(),
                0,
            )
        };
        if rc != 0 {
            return None;
        }

        Some(v)
    }

    pub fn sysctl_string(name: &str) -> Option<String> {
        let c = std::ffi::CString::new(name).ok()?;
        let mut len = 0usize;

        // SAFETY: the documented size probe; a null oldp writes only the needed length into len.
        if unsafe {
            sysctlbyname(c.as_ptr(), core::ptr::null_mut(), &mut len, core::ptr::null_mut(), 0)
        } != 0
            || len == 0
        {
            return None;
        }
        let mut buf = vec![0u8; len];

        // SAFETY: buf is len bytes and len is what the probe asked for; name stays live.
        if unsafe {
            sysctlbyname(
                c.as_ptr(),
                buf.as_mut_ptr() as *mut core::ffi::c_void,
                &mut len,
                core::ptr::null_mut(),
                0,
            )
        } != 0
        {
            return None;
        }
        buf.truncate(len);
        let s = String::from_utf8_lossy(&buf).trim_matches(char::from(0)).trim().to_string();
        (!s.is_empty()).then_some(s)
    }
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "windows",
    target_os = "macos"
)))]
mod sys {
    use super::{HugePages, Placement, Topology};

    pub fn pin_current_thread(_cpu: usize, _group: u16) -> Placement {
        Placement::Unsupported("no affinity API is wired up for this platform")
    }
    pub fn current_cpu() -> Option<(u16, usize)> {
        None
    }
    pub fn restrict_process(_cpus: &[usize], _topo: &Topology) -> Placement {
        Placement::Unsupported("no affinity API is wired up for this platform")
    }
    pub fn allowed_cpus() -> Option<Vec<usize>> {
        None
    }
    pub fn set_priority(_level: u8) -> Result<String, String> {
        Err("no priority API is wired up for this platform".into())
    }
    pub fn page_size() -> usize {
        4096
    }
    pub fn huge_pages() -> HugePages {
        HugePages { size_kib: None, state: "unknown on this platform".into(), likely: false }
    }
}

pub fn pin_current_thread(cpu: usize, group: u16) -> Placement {
    sys::pin_current_thread(cpu, group)
}

pub fn current_cpu() -> Option<(u16, usize)> {
    sys::current_cpu()
}

pub fn resolve_pins(cpus: &[usize], topo: &Topology) -> Vec<(usize, u16)> {
    cpus.iter()
        .map(|&c| (c, topo.cpu(c).map(|x| x.group).unwrap_or(0)))
        .collect()
}

pub fn restrict_process(cpus: &[usize], topo: &Topology) -> Placement {
    sys::restrict_process(cpus, topo)
}

fn set_priority_impl(level: u8) -> Result<String, String> {
    sys::set_priority(level)
}

fn page_size_impl() -> usize {
    sys::page_size()
}

fn huge_pages_impl() -> HugePages {
    sys::huge_pages()
}

fn allowed_cpus_impl() -> Option<Vec<usize>> {
    sys::allowed_cpus()
}

#[cfg(target_os = "windows")]
pub use sys::logical_processor_information;

#[cfg(target_os = "macos")]
pub use sys::{sysctl_i64, sysctl_string};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_size_is_power_of_two() {
        let p = page_size();
        assert!(p >= 4096, "page size {p}");
        assert!(p.is_power_of_two(), "page size {p}");
    }

    #[test]
    fn huge_page_state_is_actionable() {
        let h = huge_pages();
        assert!(!h.state.is_empty());
    }

    #[test]
    fn pin_works_or_says_why() {
        let p = pin_current_thread(0, 0);
        let d = p.describe();
        assert!(!d.is_empty());
        match p {
            Placement::Pinned(c) => assert_eq!(c, 0),
            Placement::Unsupported(w) => assert!(!w.is_empty()),
            Placement::Failed(e) => assert!(!e.is_empty()),
            Placement::Restricted(_) => panic!("pinning one thread is not a restriction"),
        }
    }

    #[test]
    fn out_of_range_priority_is_refused() {
        assert!(set_priority(6).is_err());
        assert!(set_priority(200).is_err());
    }

    #[test]
    fn resolve_pins_keeps_order_and_length() {
        let t = Topology::detect();
        let asked = [3usize, 0, 1, 0];
        let got = resolve_pins(&asked, &t);
        assert_eq!(got.len(), asked.len(), "one pin per worker, repeats included");
        assert_eq!(
            got.iter().map(|(c, _)| *c).collect::<Vec<_>>(),
            asked.to_vec(),
            "the CPU column must be the list, untouched"
        );
    }

    #[test]
    fn unknown_cpu_keeps_its_slot() {
        let t = Topology::detect();
        let got = resolve_pins(&[0, 100_000, 0], &t);
        assert_eq!(got.len(), 3);
        assert_eq!(got[1], (100_000, 0), "unknown id, group 0, still in slot 1");
        assert_eq!(got[2].0, 0);
    }

    #[test]
    fn pinned_thread_runs_where_asked() {
        if current_cpu().is_none() {
            return;
        }
        let t = Topology::detect();

        let ids: Vec<usize> = t.cpus.iter().map(|c| c.id).take(4).collect();
        assert!(!ids.is_empty(), "a machine with no CPUs is not a machine");
        for id in ids {
            let group = t.cpu(id).map(|c| c.group).unwrap_or(0);
            let got = std::thread::spawn(move || {
                let placed = pin_current_thread(id, group);
                assert!(placed.is_pinned(), "cpu {id} group {group}: {}", placed.describe());

                for _ in 0..64 {
                    if current_cpu() == Some((group, id % 64)) {
                        return current_cpu();
                    }
                    std::thread::yield_now();
                }
                current_cpu()
            })
            .join()
            .expect("the pinning thread panicked");
            assert_eq!(
                got,
                Some((group, id % 64)),
                "asked for cpu {id} in group {group}; the OS says the thread ran elsewhere"
            );
        }
    }

    #[test]
    fn known_cpu_carries_its_group() {
        let t = Topology::detect();
        let ids: Vec<usize> = t.cpus.iter().map(|c| c.id).collect();
        for (id, (got_id, got_group)) in ids.iter().zip(resolve_pins(&ids, &t)) {
            assert_eq!(*id, got_id);
            let want = t.cpu(*id).map(|c| c.group).expect("this id came from the topology");
            assert_eq!(got_group, want, "cpu {id} group");
        }
    }
}
