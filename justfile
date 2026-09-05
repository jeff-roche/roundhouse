# Run `just` to list recipes.
default:
    @just --list

# Build the whole workspace.
build:
    cargo build --workspace

# Run every test in the workspace (includes xtask's architectural-invariant scans).
test:
    cargo test --workspace

# Run tests for a single crate, e.g. `just test-crate roundhouse-store`.
test-crate crate:
    cargo test -p {{crate}}

# Type-check everything (including tests/benches/examples) without producing artifacts.
check:
    cargo check --workspace --all-targets

# Format the whole workspace in place.
fmt:
    cargo fmt --all

# Fail if anything isn't formatted, without changing files.
fmt-check:
    cargo fmt --all -- --check

# Lint with clippy, denying warnings.
clippy:
    cargo clippy --workspace --all-targets -- -D warnings

# Everything CI runs, in one shot.
ci: fmt-check clippy test

# Build docs for the workspace and open them.
doc:
    cargo doc --workspace --no-deps --open

# Run the `round` CLI with any extra args, e.g. `just run daemon`.
run *args:
    cargo run -p roundhouse-cli --bin round -- {{args}}

# Remove build artifacts.
clean:
    cargo clean

# Rebuild the web frontend into crates/roundhouse-web/assets/dist/, which is
# committed (`rust-embed` needs it at Rust compile time, and CI has no npm
# step — see `.gitignore`'s comment on the same directory).
web-build:
    cd crates/roundhouse-web/frontend && npm ci && npm run build

# Run the web frontend's Vitest suite.
web-test:
    cd crates/roundhouse-web/frontend && npm ci && npm test
