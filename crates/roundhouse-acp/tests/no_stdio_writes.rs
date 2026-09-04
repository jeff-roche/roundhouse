//! Fix round 5 (Item 3): pins the "this crate never writes to stdout or
//! stderr" invariant that fix round 4 established and left untested.
//!
//! Round 4 removed every `eprintln!` from `roundhouse-acp` — a library
//! embedded in-process by `roundhouse-daemon` must not write to a stream the
//! daemon owns and shares with the `round` TUI, and `eprintln!` additionally
//! *panics* if the write fails, which in a `Deserialize` impl is a panic
//! inside a pure operation with no `Result` path for it. Round 4 then reported
//! that no dependency-free test could catch a re-added one. That was wrong:
//! `roundhouse-core/tests/no_io_no_async.rs` is exactly this pattern — walk
//! the crate's own `src/` with `std::fs` and assert a forbidden substring does
//! not appear — and a reviewer confirmed the gap was real by mutating
//! `Registry::deserialize` to re-add an `eprintln!` with the whole suite still
//! green.
//!
//! Scope and limits, stated rather than implied: this is a source-text scan,
//! so it catches the macro spelled literally in this crate's `src/` (the way
//! it was written, and the way it would be written again) and nothing else —
//! not `std::io::stderr().write_all(..)`, not a write from a dependency, not
//! one introduced by a macro this crate expands. It is a regression guard on
//! the specific removal, not a proof of silence. The measured proof that the
//! current code is silent is in `task-29-report.md` (three 1 MiB hostile
//! bodies through the public API produced 0 bytes on stderr).

use std::fs;
use std::path::{Path, PathBuf};

/// Macros that write to the process's stdout/stderr. `eprintln!` contains
/// `println!` as a substring, so the `println!` entry alone would catch both;
/// both are listed anyway so a failure names the macro that was actually
/// added.
const FORBIDDEN: [&str; 5] = ["eprintln!", "println!", "eprint!", "print!", "dbg!"];

#[test]
fn src_tree_contains_no_stdout_or_stderr_writes() {
    let src_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let files = rust_sources(&src_dir);
    assert!(
        files.len() >= 2,
        "the walk found {} source files under {src_dir:?} -- it must be reaching the real \
         src/ tree, otherwise this test passes vacuously",
        files.len()
    );

    for path in files {
        let text = fs::read_to_string(&path).unwrap();
        for (line_number, line) in text.lines().enumerate() {
            // Doc comments discuss these macros at length -- that is the
            // point of the round-4 write-up -- so they are skipped. Ordinary
            // `//` comments are *not* skipped: a commented-out write is still
            // a write waiting to be uncommented, and no such comment exists
            // in this crate today.
            let trimmed = line.trim_start();
            if trimmed.starts_with("///") || trimmed.starts_with("//!") {
                continue;
            }
            for macro_name in FORBIDDEN {
                assert!(
                    !line.contains(macro_name),
                    "{}:{} writes to stdout/stderr with `{macro_name}`: {}\n\
                     roundhouse-acp is embedded in-process by roundhouse-daemon and must not \
                     write to a stream the daemon owns -- return the text to the caller \
                     instead (see RegistryRefresh::warnings).",
                    path.display(),
                    line_number + 1,
                    line.trim()
                );
            }
        }
    }
}

fn rust_sources(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            out.extend(rust_sources(&path));
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
    out
}
