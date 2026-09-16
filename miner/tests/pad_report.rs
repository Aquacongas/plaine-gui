use plaine_pow_mine::{pad, Pads, BATCH};

const PAD_BYTES: usize = 65_536;

const PAGE: usize = 65_536;

const WORKERS: usize = 6;

#[cfg(windows)]
mod query {
    use std::ffi::c_void;

    #[repr(C)]
    #[derive(Default)]
    pub struct Mbi {
        pub base_address: usize,
        pub allocation_base: usize,
        pub allocation_protect: u32,
        _pad0: u32,
        pub region_size: usize,
        pub state: u32,
        pub protect: u32,
        pub typ: u32,
        _pad1: u32,
    }

    const MEM_FREE: u32 = 0x0001_0000;

    extern "system" {
        fn VirtualQuery(addr: *const c_void, buf: *mut Mbi, len: usize) -> usize;
    }

    pub fn is_mapped(addr: usize) -> bool {
        let mut mbi = Mbi::default();

        let n = unsafe {
            VirtualQuery(addr as *const c_void, &mut mbi, core::mem::size_of::<Mbi>())
        };
        assert_ne!(n, 0, "VirtualQuery({addr:#x}) failed");
        mbi.state != MEM_FREE
    }
}

#[cfg(unix)]
mod query {
    use std::ffi::c_void;

    extern "C" {
        fn mincore(addr: *mut c_void, len: usize, vec: *mut u8) -> i32;
    }

    pub fn is_mapped(addr: usize) -> bool {
        let mut v = [0u8; 1];

        let r = unsafe { mincore(addr as *mut c_void, 4096, v.as_mut_ptr()) };
        r == 0
    }
}

#[test]
fn six_workers_six_regions() {
    assert_eq!(
        pad::observed_now(),
        pad::Summary::default(),
        "something in this process mapped pads before the test did; the tallies are \
         process-wide and this test can only be trusted when it is alone"
    );
    assert_eq!(
        pad::observed_ever(),
        pad::Summary::default(),
        "this process has already mapped pads; the lifetime tally is not this test's"
    );
    assert_eq!(pad::status_field(), "pads -", "nothing is mapped, so there is nothing to name");

    let (pads, err) = Pads::many(WORKERS, BATCH, true);
    assert!(err.is_none(), "the ordinary-page fallback must never fail: {err:?}");
    assert_eq!(pads.len(), WORKERS);

    let now = pad::observed_now();
    let (kind, huge, total) = (now.kind(), now.huge(), now.total());
    assert_eq!(total, WORKERS, "one region per worker, whatever the mapping count was");
    assert_eq!(pad::observed_ever(), now, "nothing has been dropped yet, so the two agree");

    let by_pad = pads.iter().filter(|p| p.pages().is_huge()).count();
    assert_eq!(huge, by_pad, "the region tally disagrees with what the pads say they got");
    assert_eq!(
        pad::Summary::of(pads.iter().map(|p| p.pages())),
        now,
        "the tally is not mechanism-for-mechanism what the pads themselves report"
    );
    if by_pad > 0 {
        assert!(kind.is_huge(), "regions on huge pages but the reported kind is Base");
    }

    let field = pad::status_field();
    assert!(
        field.contains(&format!("{huge}/{total}")),
        "the status field must name huge AND total regions; it said {field:?}"
    );
    assert_ne!(field, "pads -");

    if huge > 0 && huge < total {
        assert!(
            !field.contains(&format!("{total}/{total}")),
            "a partial success reported as complete: {field:?}"
        );
    }

    eprintln!("pad_report: {field} ({kind:?}, {huge} of {total} regions on huge pages)");

    let ends = |p: &Pads| -> [usize; 2] {
        let first = p.words(0).as_ptr() as usize;
        let last_pad = p.words(BATCH - 1).as_ptr() as usize;
        [first, last_pad + PAD_BYTES - PAGE]
    };
    let bases: Vec<[usize; 2]> = pads.iter().map(ends).collect();
    for (w, b) in bases.iter().enumerate() {
        assert!(query::is_mapped(b[0]), "worker {w}'s pads are not mapped while it holds them");
        assert!(query::is_mapped(b[1]), "worker {w}'s LAST page is not mapped while it holds it");
    }

    let keep = WORKERS / 2;
    let mut pads = pads;
    let survivor = pads.remove(keep);
    drop(pads);
    for (w, b) in bases.iter().enumerate() {
        for (end, a) in b.iter().enumerate() {
            let what = if end == 0 { "first" } else { "last" };
            if w == keep {
                assert!(
                    query::is_mapped(*a),
                    "the surviving worker's own {what} page was released with a neighbour's"
                );
            } else {
                assert!(
                    !query::is_mapped(*a),
                    "worker {w}'s {what} page at {a:#x} is still mapped after its Pads dropped"
                );
            }
        }
    }

    assert_eq!(ends(&survivor), bases[keep]);
    let last = bases[keep];
    drop(survivor);
    for (end, a) in last.iter().enumerate() {
        let what = if end == 0 { "first" } else { "last" };
        assert!(
            !query::is_mapped(*a),
            "the last worker's {what} page at {a:#x} is still mapped after its Pads dropped"
        );
    }

    assert_eq!(
        pad::observed_now(),
        pad::Summary::default(),
        "every region has been dropped and the live tally still counts them"
    );
    assert_eq!(
        pad::observed_ever().total(),
        WORKERS,
        "the lifetime tally lost regions when they were dropped; `--bench` reports after \
         joining its workers and would print a blank page line"
    );
    assert_eq!(
        pad::status_field(),
        "pads -",
        "nothing is mapped between two sessions, and the field must not describe the last one"
    );

    assert!(
        pad::log_startup(false),
        "the startup line said nothing about {WORKERS} regions this process obtained"
    );

    assert!(!pad::log_startup(false), "the startup line printed twice");
    assert!(!pad::log_startup(false), "the startup line printed a third time");

    let (again, err) = Pads::many(WORKERS, BATCH, true);
    assert!(err.is_none(), "{err:?}");
    let now = pad::observed_now();
    assert_eq!(
        now.total(),
        WORKERS,
        "after a reconnect the live tally reports {} regions for {WORKERS} workers",
        now.total()
    );
    assert_eq!(
        pad::observed_ever().total(),
        2 * WORKERS,
        "the lifetime tally must still hold both sessions"
    );
    let field = pad::status_field();
    assert!(
        field.ends_with(&format!("/{WORKERS}")),
        "the status line after a reconnect says {field:?}, not a count of the live workers"
    );

    let words: Vec<&str> = field.split_whitespace().collect();
    assert_eq!(words.len(), 3, "the status field is three words: {words:?}");
    assert_eq!(words[0], "pads");
    assert_eq!(words[2], format!("{}/{}", now.huge(), now.total()));
    eprintln!("pad_report: after a reconnect, {field}");
    drop(again);
}
