use std::collections::HashMap;

mod common;

const COMMITTER: &str = include_str!("../src/committer.rs");
const READER: &str = include_str!("../src/reader.rs");

fn count(hay: &str, needle: &str) -> usize {
    hay.matches(needle).count()
}

#[test]
fn begin_write_in_one_file() {
    let mut per_file: HashMap<&str, usize> = HashMap::new();
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    for e in std::fs::read_dir(&dir).expect("src dir").flatten() {
        let p = e.path();
        if p.extension().and_then(|s| s.to_str()) != Some("rs") {
            continue;
        }
        let src = std::fs::read_to_string(&p).expect("read source");

        let calls = src
            .lines()
            .filter(|l| !l.trim_start().starts_with("//") && !l.trim_start().starts_with("///"))
            .map(|l| count(l, "begin_write("))
            .sum::<usize>();
        if calls > 0 {
            let name: &'static str = Box::leak(
                p.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned()
                    .into_boxed_str(),
            );
            per_file.insert(name, calls);
        }
    }

    let mut files: Vec<&&str> = per_file.keys().collect();
    files.sort();
    assert_eq!(
        files,
        vec![&"committer.rs", &"recover.rs"],
        "begin_write escaped its two allowed files: {per_file:?}"
    );
}

#[test]
fn reader_has_no_write_txn() {
    for pat in ["begin_write", "WriteTransaction", "&mut self"] {
        let hits = READER
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .filter(|l| l.contains(pat))
            .count();
        assert_eq!(hits, 0, "reader.rs contains `{pat}` outside comments");
    }
}

#[test]
fn committer_cell_makes_it_unsync() {
    assert!(
        COMMITTER.contains("seq: Cell<u64>"),
        "the Cell that makes Committer !Sync is gone"
    );
}

#[test]
fn read_shared_write_once() {
    let _g = common::serial();
    fn shareable<T: Send + Sync + Clone>() {}
    shareable::<plaine_storage::StoreReader>();

    let s = common::Scratch::new("single-writer");
    let (committer, reader, _r) = plaine_storage::open(s.cfg()).expect("open");

    match plaine_storage::open(s.cfg()) {
        Err(plaine_storage::StoreError::AlreadyOpen) => {}
        Err(e) => panic!("second open failed for the wrong reason: {e:?}"),
        Ok(_) => panic!("second open must be refused"),
    }
    drop(committer);
    drop(reader);

    let (c2, _r2, _) = plaine_storage::open(s.cfg()).expect("reopen after drop");
    drop(c2);
}
