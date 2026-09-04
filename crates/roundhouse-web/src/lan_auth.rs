//! §11.3's opt-in LAN bind and its shared per-device token.
//!
//! §11.3, in full: *"Binding beyond `127.0.0.1` is opt-in (a flag, off by
//! default — loopback-only remains what you get with no configuration), and
//! when enabled it's gated by a **shared token** entered once per device,
//! generated into the state dir […] — no login system, no session management,
//! no TLS by default."*
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
//! # 4. The gate is per-bind, not per-peer
//!
//! When LAN binding is on, **every** request is gated, including one arriving
//! over loopback. This module never inspects the peer address to decide whether
//! to authenticate. That would make the security decision depend on socket-level
//! information a handler behind any future reverse proxy sees wrongly, and it
//! would split one gate into two code paths with different behaviour. One gate,
//! mounted or not, decided once at bind time.
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
use std::net::{IpAddr, Ipv4Addr};
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
/// **Residual:** this is the only definition, and `roundhouse-web` is linked by
/// one binary. The moment a second crate needs the state dir, this must move to
/// a crate both depend on — the way `default_runtime_dir` lives in
/// `roundhouse-tui` because both binaries need it — rather than being copied.
/// Two definitions of "where the state dir is" drift silently, and the symptom
/// is a daemon reading a token some other component never wrote.
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
///    rather than by reading and then judging, so the read below is bounded by
///    something other than what the file turned out to be.
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
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)?;
    let meta = file.metadata()?;

    if meta.uid() != rustix::process::getuid().as_raw() {
        return Err(io::Error::other(format!(
            "{} is not owned by the current user, refusing to use it as the LAN token",
            path.display()
        )));
    }
    if meta.permissions().mode() & 0o077 != 0 {
        return Err(io::Error::other(format!(
            "{} permissions too open, refusing to use it as the LAN token",
            path.display()
        )));
    }

    if meta.len() > MAX_TOKEN_FILE_BYTES {
        return Err(io::Error::other(format!(
            "{} is {} bytes, past the {MAX_TOKEN_FILE_BYTES}-byte limit for a token file; \
             refusing to read it",
            path.display(),
            meta.len()
        )));
    }

    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
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
fn ensure_state_dir(dir: &Path) -> io::Result<()> {
    if let Some(parent) = dir.parent() {
        std::fs::create_dir_all(parent)?;
    }
    match DirBuilder::new().mode(STATE_DIR_MODE).create(dir) {
        // Freshly created by us: a directory, 0700, and ours by construction.
        Ok(()) => Ok(()),
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
                    format!(
                        "{} has mode {mode:04o}, expected {STATE_DIR_MODE:04o}; refusing to keep \
                         the LAN token in a directory others can reach",
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
/// Layered by [`crate::build_router`] over the **whole** router — the embedded
/// client assets as well as `/api` — see that function for why that is one
/// `.layer` and not a per-route guard.
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
}
