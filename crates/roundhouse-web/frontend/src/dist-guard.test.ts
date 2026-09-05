import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

// A fast LOCAL CANARY, mirroring `crates/roundhouse-web/tests/dist_public_content.rs`.
// It is NOT the gate — `cargo test -p roundhouse-web` is, and it is the only
// thing CI's `Test` job runs. This file exists because slice A's brief asked
// for exactly this Vitest mirror "for fast local feedback" and it was never
// built (see `.superpowers/sdd/W2/task-10b-brief.md`'s Step 0). It reads the
// same directory the Rust test reads — `crates/roundhouse-web/assets/dist/`,
// two levels up from `frontend/` — from disk, post-build, so `npm test`
// alone (no `cargo` invocation) catches an obvious regression before a push
// round-trips through CI.
//
// Keep this file's six checks textually close to `dist_public_content.rs`'s
// checks so a reader can see the two lists agree. If one grows a pattern the
// other should grow too, even though only the Rust one is binding.

const DIST_DIR = join(__dirname, "..", "..", "assets", "dist");

/** Every file under `DIST_DIR`, as `[relativePath, contents]` pairs. */
function distFiles(): Array<[string, Buffer]> {
  const files: Array<[string, Buffer]> = [];

  function walk(dir: string, prefix: string): void {
    for (const entry of readdirSync(dir)) {
      const full = join(dir, entry);
      const rel = prefix ? `${prefix}/${entry}` : entry;
      if (statSync(full).isDirectory()) {
        walk(full, rel);
      } else {
        files.push([rel, readFileSync(full)]);
      }
    }
  }

  walk(DIST_DIR, "");
  return files;
}

/** A LAN token is 64 lowercase hex characters (`lan_auth.rs`'s `TOKEN_BYTES = 32`, hex-encoded). */
const HEX_RUN_LEN_THAT_LOOKS_LIKE_A_TOKEN = 64;

function containsHexRun(bytes: Buffer, runLen: number): boolean {
  let run = 0;
  for (const byte of bytes) {
    const isHex =
      (byte >= 0x30 && byte <= 0x39) || // 0-9
      (byte >= 0x41 && byte <= 0x46) || // A-F
      (byte >= 0x61 && byte <= 0x66); // a-f
    if (isHex) {
      run += 1;
      if (run >= runLen) return true;
    } else {
      run = 0;
    }
  }
  return false;
}

function isHexByte(byte: number): boolean {
  return (byte >= 0x30 && byte <= 0x39) || (byte >= 0x41 && byte <= 0x46) || (byte >= 0x61 && byte <= 0x66);
}

/** `8-4-4-4-12` hex digits, hyphen-separated. */
function containsUuid(bytes: Buffer): boolean {
  if (bytes.length < 36) return false;
  outer: for (let start = 0; start + 36 <= bytes.length; start++) {
    for (let i = 0; i < 36; i++) {
      const byte = bytes[start + i];
      const mustBeHyphen = i === 8 || i === 13 || i === 18 || i === 23;
      if (mustBeHyphen ? byte !== 0x2d : !isHexByte(byte)) {
        continue outer;
      }
    }
    return true;
  }
  return false;
}

describe("dist/ public-content canary (mirrors dist_public_content.rs)", () => {
  const files = distFiles();

  it("is non-vacuous", () => {
    expect(files.length).toBeGreaterThan(0);
  });

  it("carries no LAN-token-shaped run of 64+ hex characters", () => {
    for (const [path, bytes] of files) {
      expect(
        containsHexRun(bytes, HEX_RUN_LEN_THAT_LOOKS_LIKE_A_TOKEN),
        `${path} contains a 64+ hex-character run, the shape of a LAN token`,
      ).toBe(false);
    }
  });

  it("carries no UUID-shaped string", () => {
    for (const [path, bytes] of files) {
      expect(containsUuid(bytes), `${path} contains a UUID-shaped string`).toBe(false);
    }
  });

  it("never references the browser's persistent key-value store", () => {
    for (const [path, bytes] of files) {
      expect(bytes.includes("localStorage"), `${path} references localStorage`).toBe(false);
    }
  });

  it("never references a generated config.json", () => {
    for (const [path, bytes] of files) {
      expect(bytes.includes("config.json"), `${path} references config.json`).toBe(false);
    }
  });

  it("carries no sourceMappingURL reference", () => {
    for (const [path, bytes] of files) {
      expect(bytes.includes("sourceMappingURL"), `${path} references sourceMappingURL`).toBe(false);
    }
  });

  it("embeds no key ending in .map", () => {
    for (const [path] of files) {
      expect(path.endsWith(".map"), `${path} is a source map`).toBe(false);
    }
  });
});
