import { defineConfig } from "vitest/config";
import solid from "vite-plugin-solid";

// Task 10 slice A (Phase 5, Subsystem D — web frontend). See
// `.superpowers/sdd/W2/task-10a-brief.md` and `crates/roundhouse-web/src/assets.rs`
// for the contract this build output has to satisfy.
export default defineConfig({
  plugins: [solid()],
  build: {
    // `rust-embed` compiles `crates/roundhouse-web/assets/dist/` into the
    // daemon binary at compile time (see `src/assets.rs`), and CI has no npm
    // step — so the build output is committed there directly. There is no
    // `build.rs` shelling out to `npm`; see ruling R1 in `progress.md`.
    outDir: "../assets/dist",
    // `assets/dist/` is replaced wholesale on every build, never merged. A
    // stale file left over from a previous build (a renamed or removed
    // component's old chunk) would otherwise stay embedded and served
    // forever, since `serve_asset` has no notion of "no longer produced".
    emptyOutDir: true,
    // Deliberately off. A source map embeds absolute filesystem paths from
    // the machine that built it into a file `assets/dist/` ships to every
    // unauthenticated LAN peer (see `src/assets.rs`'s module docs on why that
    // directory is public content) — and `tests/dist_public_content.rs`'s
    // `sourceMappingURL` guard exists to catch exactly that if it comes back.
    sourcemap: false,
  },
  server: {
    proxy: {
      // Dev-only: talks to whatever binds the daemon's HTTP port locally.
      // Nothing in this workspace binds one yet (see `lan_auth.rs`'s module
      // docs) — update the target when it does.
      "/api": {
        target: "http://127.0.0.1:7420",
        // `host_guard::require_expected_host` (`src/host_guard.rs`) checks
        // the `Host` header unconditionally, even on the loopback bind, and
        // admits only `127.0.0.1` / `[::1]` / `localhost`. Without
        // `changeOrigin`, the proxy forwards the browser's own `Host` (e.g.
        // `localhost:5173`, which the daemon never bound), and every `/api`
        // request 403s. This rewrites `Host` to the proxy target's.
        changeOrigin: true,
      },
    },
  },
  test: {
    environment: "jsdom",
    // A fixed, portless origin so `token.test.ts` can navigate with plain
    // `http://localhost/...` URLs — jsdom's own default origin carries a
    // port, and `history.replaceState` refuses to cross origins.
    environmentOptions: {
      jsdom: {
        url: "http://localhost/",
      },
    },
  },
});
