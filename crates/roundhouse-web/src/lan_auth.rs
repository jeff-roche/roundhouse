//! §11.3's opt-in LAN bind and its shared per-device token.
//!
//! §11.3: *"Binding beyond `127.0.0.1` is opt-in (a flag, off by default —
//! loopback-only remains what you get with no configuration), and when enabled
//! it's gated by a **shared token** entered once per device, generated into the
//! state dir […] — no login system, no session management, no TLS by default."*
//!
//! The `[…]` is not cosmetic and is named here so a reader checking the quote
//! does not trip over it. What it elides is *"the same way the existing
//! loopback token already is (§6.4's approval-flow token pattern)"*
//! (`docs/architecture/08-ui-design.md:125`) — the clause ruling P84 §E
//! identified as unresolvable: a `grep` over `crates/` finds **neither
//! referent**, no "existing loopback token" and no §6.4 approval-flow token.
//! The elision is therefore a dropped false premise, not a shortened sentence,
//! and the file hygiene below is this module's own design rather than a pattern
//! it copied from somewhere.
//!
//! Four things about that sentence drive everything below, and each one is a
//! decision this module makes rather than inherits.
//!
//! # 1. The token is carried in `Authorization: Bearer`, or in a query parameter
//!
//! §11.3 chose SSE *specifically* because `Last-Event-ID` maps onto the
//! `(session_id, seq)` cursor — and only the browser's native `EventSource`
//! sets that header on its own. **`EventSource` cannot set request headers at
//! all.** A token accepted only in some bespoke header would therefore be
//! unsettable by the exact client [`crate::sse`] exists to serve.
//!
//! So both are accepted. `Authorization: Bearer` is preferred, and is this
//! workspace's existing spelling for a bearer token
//! (`roundhouse-net/src/proxy.rs`'s `Authorization: Bearer ` /
//! `Proxy-Authorization: Bearer ` strip). The `?access_token=` query parameter
//! is the documented `EventSource` accommodation, and takes the name RFC 6750
//! §2.3 gives that method.
//!
//! RFC 6750 §2.3 also says the query form SHOULD NOT be used, and its reason is
//! the one that applies here: query strings land in logs. **Residual, named for
//! whoever adds request logging to this crate:** there is no request logging
//! today, and when it arrives it must not log `uri().query()` — logging the
//! path is fine, logging the query writes the LAN token to disk in a file with
//! none of [`LanToken`]'s permissions. Nothing in this module can enforce that
//! for a logger that does not exist yet.
//!
//! **A second residual of the same shape, and it is the client author's, not a
//! logger author's.** Since ruling P85 the gate sits on `/api` and the shell is
//! ungated, but the token still has to reach the browser somehow, and the only
//! carrier a **top-level navigation** has is the query string:
//! `http://host:port/?access_token=…` is how a device is paired. A URL typed or
//! opened in a browser lands in **browser history, in browser account sync
//! (Chrome/Firefox/Safari all sync history across a signed-in user's devices),
//! and in URL-bar autocomplete**, where it will be offered back long after the
//! tab is gone. **No server-side code closes this** — the server cannot see, let
//! alone edit, the client's history. The mitigation is the `history.replaceState`
//! step of the client contract below, it runs in the client, and it belongs to
//! whoever writes the client. It is recorded here so that person inherits a
//! stated obligation rather than discovering it — see *The client contract*
//! below for the whole of it.
//!
//! A second bound worth stating plainly rather than implying: §11.3 specifies
//! **no TLS by default**, so the token is already plaintext on the wire on the
//! trusted LAN this deliberately assumes. Header-versus-query is a marginal
//! difference *on the wire* and a real one *in logs*; the paragraph above is
//! about the logs.
//!
//! # 2. Loopback is UNAUTHENTICATED — and §6.4 can be read as saying otherwise
//!
//! `docs/architecture/03-security-and-sandboxing.md` §6.4 says *"the HTTP
//! surface binds loopback only with a token from the state dir"*, which reads
//! as requiring the token on loopback too. §11.3 says loopback-only is what you
//! get *"with no configuration"*. **These two do not agree, and this module
//! implements §11.3's reading.** Recording the tension here rather than picking
//! silently, because a later reader will otherwise find this module
//! contradicting a frozen document with no explanation:
//!
//! 1. A browser **cannot read the state dir**. Requiring a token on loopback
//!    therefore means pasting one in to use the local UI — which is the "login
//!    system" the same sentence of §11.3 forbids.
//! 2. It matches the rest of the daemon's posture. The Unix socket accepts any
//!    local connection with no authentication at all
//!    (`roundhouse-daemon/src/socket_server.rs`, an open Phase-2 `TODO`), and a
//!    same-uid local process can already read the state dir, the socket and the
//!    database directly.
//! 3. A local-process adversary is consequently already outside the daemon's
//!    threat model, and this module is not the place to change that
//!    unilaterally.
//!
//! **One thing this reasoning does not cover, and now does not have to.** "A
//! same-uid local process can already read everything" is an argument about a
//! local *process*. It says nothing about a remote *web page*, which after a
//! DNS rebind reaches the loopback bind as its own origin — so the ungated arm
//! is exactly the arm that needs `crate::host_guard`'s `Host` check, and that
//! check is always on rather than gated behind this module's `Some(gate)`. See
//! that module for the attack and for why CORS cannot answer it (ruling P93 §A).
//!
//! **The cost, stated rather than assumed away:** Task 32 gave
//! [`crate::sse::SseHub`] a replay ring, so an unauthenticated *local* reader of
//! `/api/sessions/{id}/events` now gets up to the ring's retained **history**
//! (see [`crate::sse::Retention`] for the configured bound), not merely events
//! published after it connected. If anyone later decides §6.4's stricter
//! reading wins, that is a deliberate reversal of a stated cost, not a
//! discovery.
//!
//! # 3. "Bound to the LAN with no gate" is unconstructable, not merely wrong
//!
//! [`BindConfig`] has private fields and exactly two constructors:
//! [`BindConfig::loopback`], which takes no token and pins the address to
//! `127.0.0.1`, and [`BindConfig::lan`], which **cannot be called without a
//! [`LanToken`]**. There is no way to spell "a non-loopback address, gate not
//! mounted" — [`crate::build_router`] matches on the same value that carries
//! the token, so mounting the gate and choosing a non-loopback address are one
//! decision rather than two fields a typo can separate.
//!
//! # 4. The gate is per-bind, not per-peer — and it covers `/api`, not the shell
//!
//! When LAN binding is on, **every `/api` request is gated**, including one
//! arriving over loopback. This module never inspects the peer address to
//! decide whether to authenticate. That would make the security decision depend
//! on socket-level information a handler behind any future reverse proxy sees
//! wrongly, and it would split one gate into two code paths with different
//! behaviour. One gate, mounted or not, decided once at bind time.
//!
//! *Which* routes it is mounted over is [`crate::build_router`]'s decision and
//! is argued in full there: the gate goes on the `/api` nest, so the embedded
//! client shell is served ungated. The short version is that a subresource
//! fetch (`/app.css`, and the real client's hashed `/assets/*.js`) carries
//! neither the header nor the query parameter, so a whole-surface gate leaves
//! the LAN bind with no working browser at all — while `assets/dist/` is
//! compile-time-constant public content whose disclosure is "an instance is
//! here", which the open port already gives away.
//!
//! # The client contract
//!
//! The browser's half of §1 and of the history residual above. Stated here for
//! completeness and stated **again** in `assets/dist/index.html` and
//! [`crate::assets`]'s module docs, because ruling P12 hands the client to
//! someone who "touches no Rust" and will therefore never open this file. On
//! boot the client must:
//!
//! 1. read `access_token` from `location.search` — pairing a device is opening
//!    `http://host:port/?access_token=<64 hex>`, and a top-level navigation has
//!    no other way to carry a credential;
//! 2. keep it in `sessionStorage`, not `localStorage`: it should not outlive
//!    the tab;
//! 3. `history.replaceState` it out of the URL immediately — the mitigation for
//!    the history/sync/autocomplete residual above, and the only one there is;
//! 4. send it as an `Authorization: Bearer` header on every `fetch`, and as an
//!    `?access_token=` query parameter on `EventSource`, which cannot set
//!    request headers at all (§1).
//!
//! Step 3 is also what §11.3's *"entered once per device"* means in practice:
//! nothing server-side remembers a device, so "once" is the client keeping what
//! the pairing URL delivered.
//!
//! # What is *not* here
//!
//! No CORS layer, no cookie, and no per-session authorization: the token
//! authenticates the *device*, and any authenticated device may read any
//! session, exactly as §11.3's "shared token" says. All three absences are
//! deliberate.
//!
//! **Nothing in this workspace binds a listener yet**, so nothing calls
//! [`BindConfig::bind_addr`]. See [`crate`]'s module docs for what wiring the
//! daemon up costs.

use std::fmt;
use std::fs::{DirBuilder, OpenOptions, Permissions};
use std::io::{self, ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use subtle::ConstantTimeEq;

/// The token's entropy, in bytes, before hex encoding. 32 bytes is the size
/// this workspace already uses for a content address (`Blake3Hash`), and is far
/// past any brute-force reach over a LAN.
const TOKEN_BYTES: usize = 32;

/// The token file's name inside the state dir. Prefixed `web_` because the
/// state dir is shared with `roundhouse-policy`'s trust store
/// (`workspaces/<hash>/policy_trust.toml`) and whatever else lands there.
const TOKEN_FILE: &str = "web_lan_token";

/// The largest token file [`read_token_file`] will read at all. A generated
/// token is 64 bytes; this is two orders of magnitude past that, and exists so
/// the read is bounded by a constant rather than by whatever the file turned
/// out to be — not because any legitimate file approaches it.
const MAX_TOKEN_FILE_BYTES: u64 = 4096;

/// The state dir's required mode. Same value and same reasoning as
/// `roundhouse-daemon`'s `prepare_runtime_dir`: anything group- or
/// world-writable lets someone else drop a symlink *inside* it for us to open.
const STATE_DIR_MODE: u32 = 0o700;

/// RFC 6750 §2.3's name for the URI-query form of a bearer token, including its
/// `=`, so the lookup below is a single `strip_prefix` with no splitting.
const QUERY_PARAM_PREFIX: &str = "access_token=";

/// Where the LAN token, and the rest of the daemon's persistent per-user state,
/// live: `$XDG_STATE_HOME/roundhouse`, or `~/.local/state/roundhouse`.
///
/// **This introduces the persistent state dir; it did not exist before.** The
/// only per-user directory the workspace resolved until now was
/// `roundhouse_tui::paths::default_runtime_dir`, which prefers `$XDG_RUNTIME_DIR`
/// — and `$XDG_RUNTIME_DIR` is **tmpfs, wiped at logout**. A token there is a
/// different token after every reboot, which would break §11.3's "entered once
/// per device" and would make [`LanToken::load_or_create`]'s idempotence
/// meaningless: every already-paired phone would stop working on Monday. The
/// path chosen here is the one `03-security-and-sandboxing.md` §6.2 already
/// names in prose (`~/.local/state/roundhouse/workspaces/<hash>/config.toml`),
/// so this resolves a location the frozen design had already assumed and no
/// code had yet computed.
///
/// Returns `None` rather than falling back to a temp directory when neither
/// variable gives an absolute path. A fallback would silently reinstate exactly
/// the "token regenerated out from under paired devices" failure this function
/// exists to avoid, and a caller can report a missing `$HOME` far better than
/// this can guess around it. A relative path is rejected for
/// `default_runtime_dir`'s reason: it would resolve against a working directory
/// that differs between processes.
///
/// **Residual: this must move, and the trigger is nearer than it looks.** It is
/// the only *definition* today, but it is not the only *claim*:
/// `roundhouse-policy/src/trust.rs:94` already names `~/.local/state/roundhouse`
/// in prose as the root of the trust store, and `TrustStore::new` takes that
/// path from its caller rather than computing it. So the accurate trigger is
/// **the moment the daemon constructs a `TrustStore`** — at that point one
/// process needs the trust store and the LAN token rooted at the same
/// directory, and it would be resolving that directory twice, once here and
/// once wherever the daemon spells it.
///
/// The destination is **`roundhouse-config`**: it already reads the environment
/// (`loader.rs:108` resolves `$HOME`), and both `roundhouse-web` and
/// `roundhouse-policy`'s caller can depend on it. `roundhouse-core` is ruled
/// out — it is the zero-I/O root, and `std::env` is I/O for its purposes.
///
/// Worth naming the layering too, because it is the part that makes this a
/// residual rather than a preference: `roundhouse-web` is a leaf, and a path
/// policy that is not web-specific living in a leaf means the daemon would
/// reach **up** into it for something the daemon owns. Two definitions of
/// "where the state dir is" drift silently, and the symptom is a daemon reading
/// a token some other component never wrote.
pub fn default_state_dir() -> Option<PathBuf> {
    state_dir_from(
        std::env::var_os("XDG_STATE_HOME").map(PathBuf::from),
        std::env::var_os("HOME").map(PathBuf::from),
    )
}

/// [`default_state_dir`]'s rule, with the environment passed in.
///
/// Split out so the precedence and the absolute-path filter are testable
/// without `set_var`. Mutating the environment from a test would race every
/// other thread in the binary that reads it — `tempfile` reads `TMPDIR` on
/// every `tempdir()` call in this very test suite — and the rule is pure
/// anyway.
fn state_dir_from(xdg_state_home: Option<PathBuf>, home: Option<PathBuf>) -> Option<PathBuf> {
    if let Some(xdg) = xdg_state_home {
        if xdg.is_absolute() {
            return Some(xdg.join("roundhouse"));
        }
    }
    let home = home?;
    if !home.is_absolute() {
        return None;
    }
    Some(home.join(".local").join("state").join("roundhouse"))
}

/// The token file's path inside `state_dir`. Public so an operator-facing
/// message ("enter the token in `<path>` on your phone") can name it without
/// re-deriving the file name.
pub fn token_path(state_dir: &Path) -> PathBuf {
    state_dir.join(TOKEN_FILE)
}

/// The shared per-device token from §11.3, loaded into memory once.
///
/// Holds the hex text rather than the raw bytes because that is what a client
/// presents and what the comparison therefore has to be against; decoding the
/// presented value first would add a parser to the unauthenticated path for no
/// gain.
pub struct LanToken {
    /// The 64-character lowercase hex encoding of [`TOKEN_BYTES`] random bytes.
    hex: String,
}

impl fmt::Debug for LanToken {
    /// Hand-written, not derived. A derived `Debug` puts the token in every
    /// `{:?}` of anything containing it — including [`BindConfig`], which a
    /// future daemon is very likely to log at startup.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LanToken(<redacted>)")
    }
}

impl LanToken {
    /// Loads the token from `state_dir`, generating it on first use.
    ///
    /// Idempotent, and that is the point rather than a nicety: §11.3's token is
    /// "entered once per device", so a restart that minted a new one would
    /// unpair every device that had already been paired.
    ///
    /// # Why the create comes first, and there is no `exists()` check
    ///
    /// `Path::exists()` **follows symlinks**, so an `exists()`-then-create shape
    /// treats a planted `web_lan_token -> /home/victim/.ssh/id_ed25519` as "the
    /// token is already there" and reads it, or — worse, on the write side —
    /// opens and truncates the target. `roundhouse-daemon`'s
    /// `prepare_runtime_dir` names symlink pre-planting as the class it defends
    /// against, so this is a live concern in this codebase and not a
    /// hypothetical.
    ///
    /// `create_new(true)` instead asks the kernel for "create, and fail if
    /// anything is already at this name" in one atomic step, `O_EXCL` refusing a
    /// symlink outright. `AlreadyExists` then means "read it", which also makes
    /// the two-daemons-starting-at-once race correct rather than merely
    /// unlikely: one wins the create, the other reads.
    ///
    /// # Cost
    ///
    /// One directory check, one `open`, and one `read` — at construction. The
    /// request path ([`require_lan_token`]) touches the filesystem zero times,
    /// because it compares against this already-loaded value. The alternative
    /// shape, re-reading per request, has a second defect beyond the syscalls:
    /// a load-or-*create* on the request path means an **unauthenticated request
    /// against a fresh state dir makes the daemon mint the token file as a side
    /// effect.**
    pub fn load_or_create(state_dir: &Path) -> io::Result<Self> {
        ensure_state_dir(state_dir)?;
        let path = token_path(state_dir);
        match create_token_file(&path) {
            Ok(hex) => Ok(Self { hex }),
            Err(err) if err.kind() == ErrorKind::AlreadyExists => {
                let hex = read_token_file(&path)?;
                Ok(Self { hex })
            }
            Err(err) => Err(err),
        }
    }

    /// Whether `presented` is this token, compared in constant time.
    ///
    /// `subtle::ConstantTimeEq` rather than a hand-rolled `fold(0, |a, (x, y)| a
    /// | (x ^ y)) == 0`: the hand-rolled version is only constant-time if the
    /// optimiser leaves it alone, and nothing in the source says it must.
    /// `subtle` exists to carry that guarantee through codegen, and it is
    /// already in `Cargo.lock`, so declaring it fetches nothing new.
    ///
    /// Length is not secret and `ct_eq` short-circuits on it: a token of the
    /// wrong length is rejected without a byte comparison. What must not leak is
    /// *how many leading bytes matched*, which is what a byte-at-a-time `==`
    /// would give away and what this does not.
    fn verify(&self, presented: &str) -> bool {
        self.hex.as_bytes().ct_eq(presented.as_bytes()).into()
    }
}

/// Creates `path` as a fresh `0600` file holding a new random token, returning
/// the hex text. Fails with [`ErrorKind::AlreadyExists`] if anything is already
/// at that name — see [`LanToken::load_or_create`] for why that is the whole
/// design and not an inconvenience.
fn create_token_file(path: &Path) -> io::Result<String> {
    let mut bytes = [0u8; TOKEN_BYTES];
    // `getrandom` is the OS CSPRNG (`getrandom(2)` / `/dev/urandom`) with no
    // userspace generator state between it and the kernel. A seeded userspace
    // PRNG would work too; this has strictly less that can be wrong with it.
    getrandom::fill(&mut bytes).map_err(io::Error::other)?;
    let hex = hex::encode(bytes);

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(hex.as_bytes())?;

    // `OpenOptions::mode` is masked by the process umask, which can only *clear*
    // bits — so it cannot make the file more permissive than `0600`, but it can
    // and does make it less. A umask of `0o277` yields `0o400`, a token file we
    // cannot rewrite and whose mode does not match what this function claims.
    // Setting the mode explicitly after the write makes the file's mode a
    // property of this code rather than of the ambient umask. Done through the
    // open `File` (an `fchmod`) rather than by path, so it cannot land on a
    // different inode than the one just written.
    file.set_permissions(Permissions::from_mode(0o600))?;
    Ok(hex)
}

/// Reads an existing token file, refusing it unless it is ours and private.
///
/// Mirrors `roundhouse-secrets`' `read_permission_checked_file`, including the
/// detail that matters most: the metadata comes from `File::metadata` — an
/// `fstat` on the **open descriptor** — not `std::fs::metadata` on the path, so
/// the permission check and the read are guaranteed to concern the same inode
/// with no window between them.
///
/// The five refusals, in the order they run:
///
/// 1. **`O_NOFOLLOW`**. [`LanToken::load_or_create`]'s `create_new` is what
///    refuses to *write* through a symlink, but this open would happily *read*
///    through one — and checks 2 and 3 only reject a target that is someone
///    else's or is loose, not a symlink to another `0600` file of ours holding
///    attacker-chosen hex. [`ensure_state_dir`] already makes that plant require
///    write access to a `0700` directory we own, so this is defence in depth
///    rather than the primary control; it costs one flag.
/// 2. **Owned by another uid**. Mode bits alone do not mean what they look like.
///    A `0600` file owned by `attacker` is unreadable to us *normally* — but as
///    root, or with `CAP_DAC_OVERRIDE`, we would read it happily and then trust a
///    token we never generated.
/// 3. **`0o077` bits set**: someone other than the owner can reach the token.
/// 4. **Larger than [`MAX_TOKEN_FILE_BYTES`]**, refused from the `fstat` above
///    rather than by reading and then judging. The read itself is *also*
///    capped at that constant with `Read::take`, and the two are not redundant:
///    the `fstat` is what produces a refusal with a message naming the size,
///    and `take` is what makes "the read is bounded" true of the read rather
///    than of the check in front of it. A file that grows between the `fstat`
///    and the read — or a `/proc`-style file whose `st_size` is 0 and whose
///    contents are not — would otherwise be an unbounded `read_to_string` into
///    memory. Neither is reachable for a `0600` regular file inside a `0700`
///    directory this uid owns; the cap costs one call and removes the caveat.
/// 5. **Not [`TOKEN_BYTES`] of hex**, which covers a different failure entirely:
///    two daemons starting together race, one creates the file and the other
///    opens it between the `O_EXCL` create and the `write_all`, reading zero
///    bytes. An empty token must be an error, because the alternative — treating
///    `""` as the token — authenticates every request presenting an empty
///    string. The same check rejects anything else this daemon would not have
///    generated; a token hand-written in the file's own format still works, and
///    §11.3's token is generated rather than chosen, so nothing here is meant to
///    be typed in by hand.
///
fn read_token_file(path: &Path) -> io::Result<String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)?;
    let meta = file.metadata()?;

    check_token_metadata(meta.uid(), meta.permissions().mode(), meta.len())
        // The predicate says *what* is wrong; only this frame knows *which
        // file*. Prefixing here keeps the messages exactly as they read before
        // the split — "<path> is not owned by…", "<path> permissions too
        // open…" — while leaving the predicate free of a path argument it
        // would only ever interpolate.
        .map_err(|err| io::Error::new(err.kind(), format!("{} {err}", path.display())))?;

    let mut contents = String::new();
    // Bounded by the same constant the `fstat` above judged against — see
    // refusal 4 for why both, and why neither is redundant.
    (&file)
        .take(MAX_TOKEN_FILE_BYTES)
        .read_to_string(&mut contents)?;
    let hex = contents.trim().to_string();
    match hex::decode(&hex) {
        Ok(bytes) if bytes.len() == TOKEN_BYTES => Ok(hex),
        _ => Err(io::Error::other(format!(
            "{} does not hold {TOKEN_BYTES} bytes of hex; refusing a token this daemon did not \
             generate",
            path.display()
        ))),
    }
}

/// [`read_token_file`]'s refusals 2, 3 and 4, as a predicate over the three
/// `fstat` fields they read — file owner, mode, size — in that order.
///
/// # Why this is split out rather than inlined
///
/// **So the uid refusal is reachable at values no real file supplies.** A
/// `cargo test` run has exactly one uid and cannot make itself own a file it
/// does not own, so it cannot *manufacture* a fixture for the uid branch. As a
/// free function over three integers the *predicate* is reachable with
/// `uid = getuid().wrapping_add(1)`, which is what
/// `a_token_file_owned_by_another_uid_is_refused` does.
///
/// **The wiring — that [`read_token_file`] passes `meta.uid()` and not the
/// process's own uid — is tested too, and an earlier version of this comment
/// wrongly said it could not be.** It confused "a fixture cannot be created"
/// with "no fixture exists": `/etc/passwd` is owned by another uid on every
/// non-root run, and pointing [`read_token_file`] straight at it exercises the
/// whole path. See `read_token_file_judges_the_files_owner_and_not_the_processes`
/// (ruling P88 §B).
///
/// The messages deliberately carry no path: they are written to be read with
/// the file name prefixed by the caller, which is the only frame that knows it.
fn check_token_metadata(uid: u32, mode: u32, len: u64) -> io::Result<()> {
    if uid != rustix::process::getuid().as_raw() {
        return Err(io::Error::other(
            "is not owned by the current user, refusing to use it as the LAN token",
        ));
    }
    if mode & 0o077 != 0 {
        return Err(io::Error::other(
            "permissions too open, refusing to use it as the LAN token",
        ));
    }
    if len > MAX_TOKEN_FILE_BYTES {
        return Err(io::Error::other(format!(
            "is {len} bytes, past the {MAX_TOKEN_FILE_BYTES}-byte limit for a token file; \
             refusing to read it"
        )));
    }
    Ok(())
}

/// Creates the state dir `0700`, or verifies an existing one is a directory,
/// `0700`, and ours.
///
/// A direct port of `roundhouse-daemon`'s `prepare_runtime_dir`, for the same
/// three reasons it gives, checked against one `symlink_metadata` result so
/// there is no window between them:
/// 1. **Not a directory** — catches a `roundhouse -> /somewhere/else` pre-plant.
///    `symlink_metadata` does not follow symlinks, so the symlink itself is what
///    gets rejected.
/// 2. **Mode != `0700`** — a group- or world-writable directory lets anyone drop
///    a symlink *inside* it for the token open to follow.
/// 3. **Owned by another uid** — mode alone is not enough; root traverses a
///    foreign `0700` directory freely.
///
/// Parent directories (`~/.local/state`) are created with ordinary permissions:
/// they are shared, conventional locations, and demanding `0700` of `~/.local`
/// would fail on most systems for no gain — the privacy property belongs to the
/// leaf, which is the directory the token is in.
///
/// # The mode is set after the create, and it is not redundant with `DirBuilder::mode`
///
/// Same asymmetry [`create_token_file`] fixes one function over, and for the
/// same reason: `DirBuilder::mode` is masked by the process umask, which can
/// only *clear* bits — so it cannot make the directory more permissive than
/// `0700`, but it can and does make it less. What makes it worth a line here is
/// that the failure is **permanent**, not transient. A daemon first started
/// under `umask 0o277` creates a `0500` directory; check 2 below then rejects
/// it — its own directory, at its own path — on every subsequent start, forever,
/// with no `umask` the operator can set to undo it. Re-chmodding at creation
/// means the mode is a property of this function rather than of whatever umask
/// the daemon happened to inherit the first time it ran.
///
/// Through an open descriptor (`fchmod`), like the token file's, so the chmod
/// cannot land on a different inode than the `create` just made; `O_NOFOLLOW |
/// O_DIRECTORY` refuses to open anything swapped in between the two.
fn ensure_state_dir(dir: &Path) -> io::Result<()> {
    if let Some(parent) = dir.parent() {
        std::fs::create_dir_all(parent)?;
    }
    match DirBuilder::new().mode(STATE_DIR_MODE).create(dir) {
        // Freshly created by us: a directory and ours by construction; 0700
        // only once the umask's contribution is undone.
        Ok(()) => {
            let created = OpenOptions::new()
                .read(true)
                .custom_flags(
                    (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::DIRECTORY).bits() as i32,
                )
                .open(dir)?;
            created.set_permissions(Permissions::from_mode(STATE_DIR_MODE))
        }
        Err(err) if err.kind() == ErrorKind::AlreadyExists => {
            let meta = std::fs::symlink_metadata(dir)?;
            if !meta.file_type().is_dir() {
                return Err(io::Error::new(
                    ErrorKind::AlreadyExists,
                    format!(
                        "{} exists but is not a directory; refusing to use it as the state dir",
                        dir.display()
                    ),
                ));
            }
            let mode = meta.permissions().mode() & 0o777;
            if mode != STATE_DIR_MODE {
                return Err(io::Error::new(
                    ErrorKind::PermissionDenied,
                    // The remedy is in the message on purpose. A plain
                    // `create_dir_all` from any other component, under a normal
                    // 0022 umask, leaves 0755 here — and then LAN opt-in fails
                    // permanently with no hint of what to do. Failing closed is
                    // right; failing closed silently is a bug report.
                    format!(
                        "{} has mode {mode:04o}, expected {STATE_DIR_MODE:04o}; refusing to keep \
                         the LAN token in a directory others can reach. Fix it with: chmod 700 {}",
                        dir.display(),
                        dir.display()
                    ),
                ));
            }
            if meta.uid() != rustix::process::getuid().as_raw() {
                return Err(io::Error::other(format!(
                    "{} is not owned by the current user; refusing to use it as the state dir",
                    dir.display()
                )));
            }
            Ok(())
        }
        Err(err) => Err(err),
    }
}

/// Which address the HTTP surface binds, and — inseparably — whether the LAN
/// token gate is mounted.
///
/// The two are one value on purpose. See this module's docs, §3: the previous
/// shape was two public fields, where `BindConfig { lan_enabled: false,
/// bind_addr: "0.0.0.0".parse().unwrap() }` compiled and meant "serve every
/// session's history to the LAN with no gate". With private fields and these two
/// constructors that sentence cannot be written, because the only way to supply
/// a non-loopback address is [`BindConfig::lan`], and it will not compile
/// without a [`LanToken`].
#[derive(Debug, Clone)]
pub struct BindConfig {
    inner: Bind,
}

/// The two states of [`BindConfig`]. Private: exposing it would hand back the
/// ability to construct the `Lan` variant's address without its token, which is
/// the property the wrapper exists to hold.
#[derive(Debug, Clone)]
enum Bind {
    /// §11.3's "loopback-only remains what you get with no configuration".
    Loopback,
    Lan {
        addr: IpAddr,
        /// `Arc` because [`LanGate`] is cloned per request by `axum`'s state
        /// machinery, and the token is immutable once loaded.
        token: Arc<LanToken>,
    },
}

impl Default for BindConfig {
    /// §11.3: *"loopback-only remains what you get with no configuration."*
    /// The default being the unauthenticated variant is safe precisely because
    /// unauthenticated is only reachable *together with* the loopback address.
    fn default() -> Self {
        Self::loopback()
    }
}

impl BindConfig {
    /// Bind `127.0.0.1` with no gate — the zero-configuration default.
    pub fn loopback() -> Self {
        Self {
            inner: Bind::Loopback,
        }
    }

    /// Bind `addr` with the LAN token gate mounted. Opting in past loopback is
    /// exactly this call, and it cannot be made without a token.
    ///
    /// A loopback `addr` is accepted and is not a mistake: it *narrows* — the
    /// gate is still mounted, so it means "listen locally, still require the
    /// token". Only the other direction (a non-loopback address without a gate)
    /// is the thing this type forbids.
    pub fn lan(addr: IpAddr, token: LanToken) -> Self {
        Self {
            inner: Bind::Lan {
                addr,
                token: Arc::new(token),
            },
        }
    }

    /// The address a listener should bind. **Nothing calls this yet** — no crate
    /// in this workspace binds a listener; see [`crate`]'s module docs.
    pub fn bind_addr(&self) -> IpAddr {
        match &self.inner {
            Bind::Loopback => IpAddr::V4(Ipv4Addr::LOCALHOST),
            Bind::Lan { addr, .. } => *addr,
        }
    }

    /// Which `Host` values this bind answers to — the DNS-rebinding defence
    /// [`crate::api_router`] layers on unconditionally (ruling P93 §A).
    ///
    /// Derived from the same value that decides the address, so "what we bind"
    /// and "what we answer to" cannot drift apart. See [`crate::host_guard`]
    /// for the attack, for why a missing `Host` is refused, and for the
    /// hostname residual on the LAN arm.
    ///
    /// Loopback admits the three names a browser reaches loopback by. A LAN
    /// bind admits the literal it was given — except the **unspecified**
    /// address, which names no interface: there the operator's address is
    /// whatever DHCP handed the machine and is not in this config, so any IP
    /// literal is admitted and every *name* is still refused, which is the half
    /// that stops rebinding.
    pub(crate) fn allowed_hosts(&self) -> crate::host_guard::AllowedHosts {
        use crate::host_guard::AllowedHosts;

        match &self.inner {
            Bind::Loopback => AllowedHosts::Named(
                vec![
                    Ipv4Addr::LOCALHOST.to_string(),
                    format!("[{}]", Ipv6Addr::LOCALHOST),
                    "localhost".to_string(),
                ]
                .into(),
            ),
            Bind::Lan { addr, .. } if addr.is_unspecified() => AllowedHosts::AnyIpLiteral,
            Bind::Lan { addr, .. } => AllowedHosts::Named(vec![host_literal(*addr)].into()),
        }
    }

    /// The gate [`crate::build_router`] layers on, or `None` for loopback.
    pub(crate) fn gate(&self) -> Option<LanGate> {
        match &self.inner {
            Bind::Loopback => None,
            Bind::Lan { token, .. } => Some(LanGate {
                token: Arc::clone(token),
            }),
        }
    }
}

/// An address as it is spelled in a `Host` header: bare for IPv4, bracketed
/// for IPv6 (RFC 3986 §3.2.2, which is what makes an IPv6 address's own colons
/// distinguishable from the port separator).
fn host_literal(addr: IpAddr) -> String {
    match addr {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => format!("[{v6}]"),
    }
}

/// The middleware's state: the one token, loaded once.
#[derive(Debug, Clone)]
pub(crate) struct LanGate {
    token: Arc<LanToken>,
}

/// Rejects any request that does not present the LAN token.
///
/// The first parameter must be a `State` extractor: `axum`'s
/// `middleware::from_fn_with_state` requires it, and a bare `Arc<T>` does not
/// implement `FromRequestParts`, so it cannot stand in.
///
/// Layered by [`crate::build_router`] onto the **`/api` nest**, so the routes
/// it guards are exactly the ones [`crate::sse::router`] registers and the
/// embedded client assets are served ungated. See that function for why the
/// whole-surface alternative was tried and abandoned, and why the exemption is
/// structural rather than a path-prefix test in here.
pub(crate) async fn require_lan_token(
    State(gate): State<LanGate>,
    request: Request,
    next: Next,
) -> Response {
    match presented_token(&request) {
        Some(presented) if gate.token.verify(presented) => next.run(request).await,
        // One rejection for "absent" and "wrong" alike. Distinguishing them
        // would tell an unauthenticated caller which of the two it got, and the
        // body is read by a browser, not a debugger.
        _ => unauthorized(),
    }
}

/// The token as this request presents it: `Authorization: Bearer <token>`
/// first, then `?access_token=<token>`.
///
/// Header first because it is the preferred form; the query parameter is only
/// consulted when there is no usable header, so a client that sends both and
/// disagrees with itself is judged on the header.
///
/// **No percent-decoding of the query value.** The token is lowercase hex, which
/// needs none, and a decoder on the unauthenticated path is a parser an attacker
/// controls the input to. A percent-encoded presentation simply fails to match,
/// which is the fail-closed direction.
fn presented_token(request: &Request) -> Option<&str> {
    if let Some(raw) = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
    {
        // RFC 7235: the scheme name is case-insensitive. The value is trimmed
        // because whitespace is never part of a hex token, so trimming can only
        // accept a sloppy client, never a wrong token.
        if let Some((scheme, value)) = raw.split_once(' ') {
            if scheme.eq_ignore_ascii_case("Bearer") {
                return Some(value.trim());
            }
        }
        // A non-`Bearer` `Authorization` header is not a token; fall through to
        // the query parameter rather than treating the whole header as one.
    }

    request
        .uri()
        .query()?
        .split('&')
        .find_map(|pair| pair.strip_prefix(QUERY_PARAM_PREFIX))
}

/// `401` with the `WWW-Authenticate` challenge RFC 7235 §3.1 requires of one.
/// `Bearer` rather than `Basic` is also what keeps a browser from popping its
/// native credential dialog: browsers do not implement the `Bearer` scheme, so
/// the 401 stays the page's problem, which is what §11.3's "no login system"
/// means in practice.
fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, "Bearer")],
        "LAN access requires the shared token from the state dir\n",
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `$XDG_STATE_HOME` wins when it is usable.
    #[test]
    fn xdg_state_home_takes_precedence_over_home() {
        assert_eq!(
            state_dir_from(Some("/xdg".into()), Some("/home/u".into())),
            Some(PathBuf::from("/xdg/roundhouse"))
        );
    }

    /// A relative `$XDG_STATE_HOME` resolves against a working directory that
    /// differs between processes, so it is ignored rather than joined — the
    /// same rule `roundhouse_tui::paths::default_runtime_dir` applies to
    /// `$XDG_RUNTIME_DIR`.
    #[test]
    fn a_relative_xdg_state_home_falls_through_to_home() {
        assert_eq!(
            state_dir_from(Some("relative/path".into()), Some("/home/u".into())),
            Some(PathBuf::from("/home/u/.local/state/roundhouse"))
        );
    }

    /// The location `03-security-and-sandboxing.md` §6.2 already names in prose.
    #[test]
    fn home_gives_the_documented_dot_local_state_path() {
        assert_eq!(
            state_dir_from(None, Some("/home/u".into())),
            Some(PathBuf::from("/home/u/.local/state/roundhouse"))
        );
    }

    /// `None`, not a temp-directory fallback: a fallback would put the token
    /// somewhere that gets wiped, silently unpairing every paired device.
    #[test]
    fn nothing_usable_yields_none_rather_than_a_guess() {
        assert_eq!(state_dir_from(None, None), None);
        assert_eq!(state_dir_from(Some("rel".into()), Some("rel".into())), None);
    }

    /// This uid, so the metadata a legitimate token file presents.
    fn our_uid() -> u32 {
        rustix::process::getuid().as_raw()
    }

    /// The refusal that has no end-to-end test and can have none: a `cargo
    /// test` run has one uid, and every token file it reads is one it created.
    /// The predicate is reachable where the path through [`read_token_file`] is
    /// not — see [`check_token_metadata`] for why it is a free function.
    #[test]
    fn a_token_file_owned_by_another_uid_is_refused() {
        // `wrapping_add` rather than `+ 1`: at `u32::MAX` this must still name
        // *a* different uid, not panic in a debug build.
        let other = our_uid().wrapping_add(1);

        let error = check_token_metadata(other, 0o600, 64)
            .expect_err("a token file owned by another uid is refused");
        assert!(
            error.to_string().contains("not owned by the current user"),
            "the refusal must name the owner, not some other check; got {error}"
        );
    }

    /// The three refusals run in a fixed order, and this pins it: a file that
    /// is *both* foreign and loose is refused as foreign. If the owner check
    /// were moved below the mode check, a `0600` file owned by someone else
    /// would pass the mode check and this would still refuse it — but with the
    /// wrong reason, and the reason is what an operator acts on.
    #[test]
    fn the_owner_check_runs_before_the_mode_check() {
        let error = check_token_metadata(our_uid().wrapping_add(1), 0o644, 64)
            .expect_err("foreign and loose is still refused");
        assert!(
            error.to_string().contains("not owned by the current user"),
            "got {error}"
        );
    }

    #[test]
    fn a_token_file_others_can_reach_is_refused_by_the_predicate() {
        let error = check_token_metadata(our_uid(), 0o640, 64)
            .expect_err("a group-readable token file is refused");
        assert!(
            error.to_string().contains("permissions too open"),
            "got {error}"
        );
    }

    /// The limit is inclusive: exactly [`MAX_TOKEN_FILE_BYTES`] is accepted and
    /// one byte past it is not. Asserted at the boundary because an off-by-one
    /// here is invisible at any other size.
    #[test]
    fn the_size_refusal_is_exclusive_at_the_limit() {
        check_token_metadata(our_uid(), 0o600, MAX_TOKEN_FILE_BYTES)
            .expect("exactly the limit is not past it");

        let error = check_token_metadata(our_uid(), 0o600, MAX_TOKEN_FILE_BYTES + 1)
            .expect_err("one byte past the limit is refused");
        assert!(error.to_string().contains("past the"), "got {error}");
    }

    /// The metadata a file this module just wrote presents, so that a mutation
    /// tightening any of the three checks — `!=` for `==`, `0o077` for `0o777`,
    /// `>` for `>=` — fails here rather than only in the negative cases.
    #[test]
    fn a_token_file_this_daemon_wrote_passes_every_check() {
        check_token_metadata(our_uid(), 0o600, 64).expect("0600, ours, 64 bytes is the good case");
    }

    /// The uid **wiring**: that [`read_token_file`] hands
    /// [`check_token_metadata`] the *file's* owner and not the process's.
    ///
    /// # This was called untestable by three readers, and the reasoning error is worth keeping
    ///
    /// [`check_token_metadata`]'s own doc says the wiring "stays untestable",
    /// and ruling P88 §B records that the implementer, the code review and the
    /// adjudicator all agreed. All three accepted the true premise — *a test
    /// cannot make this process own a file it does not own* — and never asked
    /// the adjacent question: **does a suitable file already exist?** The
    /// constraint was on *manufacturing* the fixture; it was read as a
    /// constraint on *having* one.
    ///
    /// `/etc/passwd` is that fixture: uid 0, mode `0644`, a regular file,
    /// world-readable, present on every Linux and macOS box. [`read_token_file`]
    /// is not restricted to files a test created, so it can simply be pointed at
    /// it. The mutation this kills is passing `getuid()` where `meta.uid()`
    /// belongs, which turns the check into the tautology
    /// `getuid() == getuid()` — under it, execution falls through to the mode
    /// check and the refusal becomes *"permissions too open"*. Asserting on
    /// **which** refusal fires is therefore the whole test; asserting merely
    /// that it is refused would pass under the mutation.
    ///
    /// Two things this deliberately does not do. It does not read `/etc/passwd`
    /// — the refusal comes before the read, which is the point. And it does not
    /// replace [`a_token_file_owned_by_another_uid_is_refused`]: that one covers
    /// the *predicate* at `u32::MAX` and other values no real file supplies.
    ///
    /// Guarded for root, which owns `/etc/passwd` and would take the
    /// mode branch legitimately — the same refusal the mutation produces, so the
    /// assertion would be vacuous rather than wrong. On a distro where
    /// `/etc/passwd` is a symlink the `O_NOFOLLOW` open returns `ELOOP` and this
    /// fails loudly, which is the acceptable direction: a clear failure, never a
    /// wrong pass.
    #[test]
    fn read_token_file_judges_the_files_owner_and_not_the_processes() {
        if our_uid() == 0 {
            // Running as root: root owns `/etc/passwd`, so the uid check passes
            // legitimately and the mode check refuses — indistinguishable from
            // the mutation this test exists to kill.
            return;
        }
        let foreign = Path::new("/etc/passwd");
        assert!(
            foreign.exists(),
            "this test needs a readable regular file owned by another uid; /etc/passwd is the \
             portable one and it is missing"
        );

        let error = read_token_file(foreign)
            .expect_err("a token file owned by another uid is refused by the real read path");
        assert!(
            error.to_string().contains("not owned by the current user"),
            "the uid refusal must come from the FILE's owner: a check reading the process's own \
             uid is the tautology `getuid() == getuid()`, falls through, and refuses with \
             `permissions too open` instead. Got: {error}"
        );
    }
}
