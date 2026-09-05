// The app shell: router wiring (ruling R17), the inbox/session-view switch,
// and the "open session by id" control ruling R19 asks for.
//
// **There is no way to discover a session id in-band (ruling R7/R19).**
// `RunSummaryJson` carries no `session_id`, and no route lists sessions.
// Rather than fabricate a link from a run to a session, this shell gives
// the user a manual control and says why it exists.

import { createMemo, createSignal, Show, type JSX } from "solid-js";

import { RunsInbox } from "./RunsInbox";
import { SessionView } from "./SessionView";
import {
  currentPath,
  DEFAULT_WORKSPACE,
  inboxPath,
  isUuidShaped,
  matchRoute,
  navigate,
  sessionPath,
  type Route,
} from "./router";

/** An in-app link: same-origin, client-side navigation via `router.ts`'s `navigate`. */
function Link(props: { href: string; class?: string; children: JSX.Element }) {
  return (
    <a
      href={props.href}
      class={props.class}
      onClick={(event) => {
        event.preventDefault();
        navigate(props.href);
      }}
    >
      {props.children}
    </a>
  );
}

function OpenSessionForm(props: { workspace: string }) {
  const [value, setValue] = createSignal("");
  const [error, setError] = createSignal<string | null>(null);

  function submit(event: Event): void {
    event.preventDefault();
    const trimmed = value().trim();
    if (!isUuidShaped(trimmed)) {
      setError("That is not a session id (expected a UUID, e.g. 8-4-4-4-12 hex digits).");
      return;
    }
    setError(null);
    setValue("");
    navigate(sessionPath(props.workspace, trimmed));
  }

  return (
    <form class="open-session-form" onSubmit={submit}>
      <label>
        Open session by id
        <input
          type="text"
          value={value()}
          onInput={(event) => setValue(event.currentTarget.value)}
          // Deliberately not a UUID-*shaped* example string (even an
          // all-zeros one): this directory is compile-time-constant public
          // content shipped to any unauthenticated LAN peer, and
          // `dist_public_content.rs`'s own guard forbids anything shaped
          // like a real session/workspace id appearing in it — an example
          // that merely LOOKS like one is indistinguishable from a real one
          // to that guard, for good reason.
          placeholder="session id (8-4-4-4-12 hex digits)"
        />
      </label>
      <button type="submit">Open</button>
      <Show when={error()}>{(message) => <p class="open-session-error">{message()}</p>}</Show>
      <p class="open-session-note">
        Runs do not link to sessions here: a run summary carries no session id, and nothing in
        this daemon lists sessions. If you already know a session's id, open it above.
      </p>
    </form>
  );
}

function NotFoundView() {
  return (
    <p class="not-found">
      No such view. <Link href={inboxPath(DEFAULT_WORKSPACE)}>Go to the inbox</Link>.
    </p>
  );
}

function MainView(props: { route: Route }) {
  return (
    <>
      <Show when={props.route.kind === "inbox"}>
        <RunsInbox />
      </Show>
      <Show when={props.route.kind === "session"}>
        <SessionView sessionId={(props.route as Extract<Route, { kind: "session" }>).sessionId} />
      </Show>
      <Show when={props.route.kind === "not-found"}>
        <NotFoundView />
      </Show>
    </>
  );
}

export function App() {
  const route = createMemo(() => matchRoute(currentPath()));
  const workspace = createMemo(() => {
    const current = route();
    return current.kind === "not-found" ? DEFAULT_WORKSPACE : current.workspace;
  });

  return (
    <div class="app-shell">
      <header class="app-header">
        <h1>Roundhouse</h1>
        <nav>
          <Link href={inboxPath(workspace())}>Inbox</Link>
        </nav>
        <OpenSessionForm workspace={workspace()} />
      </header>
      <main>
        <Show when={route()}>{(current) => <MainView route={current()} />}</Show>
      </main>
    </div>
  );
}
