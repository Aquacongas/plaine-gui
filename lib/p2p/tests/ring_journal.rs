use plaine_p2p::net::node::Ring;

const CAP: usize = 8;

#[test]
fn keeping_up_sees_each_entry_once() {
    let mut r: Ring<u64> = Ring::default();
    let mut cursor = 0u64;
    let mut got = Vec::new();
    for i in 0..(CAP as u64 * 3) {
        r.push(i, CAP);
        let (fresh, next, missed) = r.since(cursor);
        assert_eq!(missed, 0, "a reader draining every push can never miss one");
        cursor = next;
        got.extend(fresh);
    }
    assert_eq!(got, (0..(CAP as u64 * 3)).collect::<Vec<_>>());
}

#[test]
fn saturated_ring_yields_new_entries() {
    let mut r: Ring<u64> = Ring::default();
    for i in 0..(CAP as u64) {
        r.push(i, CAP);
    }

    let (_, mut cursor, _) = r.since(0);
    assert_eq!(cursor, CAP as u64);
    assert_eq!(r.len(), CAP, "precondition: ring is saturated");

    for i in 0..100u64 {
        r.push(1_000 + i, CAP);
        let (fresh, next, missed) = r.since(cursor);
        assert_eq!(
            fresh,
            vec![1_000 + i],
            "one push must yield exactly one entry"
        );
        assert_eq!(missed, 0);
        cursor = next;
    }
    assert!(r.len() <= CAP, "ring stays bounded");
}

#[test]
fn eviction_keeps_unread_entries() {
    let mut r: Ring<u64> = Ring::default();

    for i in 0..(CAP as u64) {
        r.push(i, CAP);
    }
    let (first, cursor, _) = r.since(0);
    assert_eq!(first.len(), CAP);

    for i in 0..3u64 {
        r.push(100 + i, CAP);
    }
    let (fresh, next, missed) = r.since(3);
    assert_eq!(missed, 0, "entries 3.. are all still held");
    assert_eq!(next, cursor + 3);
    assert_eq!(
        fresh,
        vec![3, 4, 5, 6, 7, 100, 101, 102],
        "everything from seq 3 up, nothing skipped"
    );
}

#[test]
fn lagging_reader_told_missed_count() {
    let mut r: Ring<u64> = Ring::default();
    for i in 0..(CAP as u64 * 2) {
        r.push(i, CAP);
    }
    let (fresh, next, missed) = r.since(0);
    assert_eq!(
        missed, CAP as u64,
        "the first CAP entries were evicted unread"
    );
    assert_eq!(next, CAP as u64 * 2);
    assert_eq!(fresh, (CAP as u64..CAP as u64 * 2).collect::<Vec<_>>());

    r.push(999, CAP);
    let (fresh, _, missed) = r.since(next);
    assert_eq!((fresh, missed), (vec![999], 0));
}

#[test]
fn sequence_never_decreases() {
    let mut r: Ring<u64> = Ring::default();
    let mut last = 0u64;
    for i in 0..(CAP as u64 * 5) {
        r.push(i, CAP);
        let s = r.seq();
        assert!(s >= last, "seq went backwards: {last} -> {s}");
        assert_eq!(s, i + 1, "seq counts every entry ever pushed");
        last = s;
    }
}

#[test]
fn cursor_beyond_ring_yields_nothing() {
    let mut r: Ring<u64> = Ring::default();
    for i in 0..4u64 {
        r.push(i, CAP);
    }
    let (fresh, next, missed) = r.since(1_000_000);
    assert!(fresh.is_empty());
    assert_eq!(missed, 0);
    assert_eq!(next, 4);
}
