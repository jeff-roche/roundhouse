use std::fs;
use std::path::Path;

/// S-LOG constraint from §5.2: "roundhouse-core has no async and no I/O."
/// Enforced two ways: (1) Cargo.toml must not depend on tokio/async-std/std::fs-only
/// crates; (2) no source file may reference std::fs, std::net, or the `async` keyword.
#[test]
fn cargo_toml_has_no_async_runtime_or_fs_crates() {
    let manifest_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    let manifest = fs::read_to_string(manifest_path).unwrap();
    for forbidden in ["tokio", "async-std", "smol", "mio"] {
        assert!(
            !manifest.contains(forbidden),
            "roundhouse-core/Cargo.toml must not depend on {forbidden} (zero-I/O, zero-async crate)"
        );
    }
}

#[test]
fn source_tree_contains_no_io_or_async_keywords() {
    let src_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    for entry in walk(&src_dir) {
        let text = fs::read_to_string(&entry).unwrap();
        assert!(
            !text.contains("std::fs"),
            "{entry:?} touches std::fs — core must have zero I/O"
        );
        assert!(
            !text.contains("std::net"),
            "{entry:?} touches std::net — core must have zero I/O"
        );
        assert!(
            !text.contains("async fn") && !text.contains("async move") && !text.contains("async {"),
            "{entry:?} uses `async` — core must have zero async"
        );
    }
}

fn walk(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut out = vec![];
    for entry in fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.is_dir() {
            out.extend(walk(&path));
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
    out
}
