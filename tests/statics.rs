//! A library keeps no process-wide state, and this one holds no `unsafe`: neither appears in
//! `src/`.

use std::fs;
use std::path::Path;

const MARKERS: &[&str] = &[
    "static ",
    "OnceLock",
    "LazyLock",
    "thread_local!",
    "unsafe ",
];

#[test]
fn the_source_holds_no_process_wide_state_and_no_unsafe() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut found = Vec::new();
    for entry in fs::read_dir(root).expect("src/ is readable") {
        let path = entry.expect("a directory entry").path();
        let text = fs::read_to_string(&path).expect("a source file is UTF-8");
        for line in text.lines() {
            let code = line.split("//").next().unwrap_or_default();
            if MARKERS.iter().any(|marker| code.contains(marker)) && !code.contains("'static") {
                found.push(format!("{}: {}", path.display(), line.trim()));
            }
        }
    }
    assert!(found.is_empty(), "{found:#?}");
}
