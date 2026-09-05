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
// Keep this file's checks textually close to `dist_public_content.rs`'s
// checks so a reader can see the two lists agree. If one grows a pattern the
// other should grow too, even though only the Rust one is binding. Slice B's
// security review added three more Rust-side checks (S4: absolute origin,
// build-machine path, an `sk-`-prefixed key shape) in the same commit that
// built this file — mirrored below for the same reason.

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

// ── S4 additions (mirroring dist_public_content.rs's three newer checks) ──

function findAll(haystack: Buffer, needle: string): number[] {
  const indices: number[] = [];
  let from = 0;
  for (;;) {
    const index = haystack.indexOf(needle, from, "latin1");
    if (index === -1) break;
    indices.push(index);
    from = index + 1;
  }
  return indices;
}

function startsWithAscii(bytes: Buffer, offset: number, literal: string): boolean {
  if (offset < 0 || offset + literal.length > bytes.length) return false;
  for (let i = 0; i < literal.length; i++) {
    if (bytes[offset + i] !== literal.charCodeAt(i)) return false;
  }
  return true;
}

function isAsciiDigit(byte: number | undefined): boolean {
  return byte !== undefined && byte >= 0x30 && byte <= 0x39;
}

function isDigitOrDot(byte: number | undefined): boolean {
  return isAsciiDigit(byte) || byte === 0x2e;
}

/**
 * ASCII-lowercases a copy of `bytes`, byte-for-byte (so length and every
 * other offset are unchanged) — used only for case-insensitive matching,
 * never for anything that reads back as text.
 */
function toAsciiLowerCopy(bytes: Buffer): Buffer {
  const copy = Buffer.from(bytes);
  for (let i = 0; i < copy.length; i++) {
    const byte = copy[i];
    if (byte >= 0x41 && byte <= 0x5a) {
      copy[i] = byte + 0x20;
    }
  }
  return copy;
}

/**
 * `http://`/`https://` not immediately followed by `www.w3.org/`, matched
 * case-insensitively (fix round 1, D6 — mirrors
 * `dist_public_content.rs::contains_disallowed_scheme`: URL schemes are
 * case-insensitive per RFC 3986, and a lowercase-only match let
 * `Http://evil.example.com/` slip past this guard entirely).
 */
function containsDisallowedScheme(bytes: Buffer, scheme: string): boolean {
  const lower = toAsciiLowerCopy(bytes);
  const lowerScheme = scheme.toLowerCase();
  return findAll(lower, lowerScheme).some((index) => !startsWithAscii(lower, index + lowerScheme.length, "www.w3.org/"));
}

/** `://` immediately followed by an ASCII digit — an IP-literal host under any scheme. */
function containsSchemeWithDigitHost(bytes: Buffer): boolean {
  return findAll(bytes, "://").some((index) => isAsciiDigit(bytes[index + 3]));
}

/** A bare dotted quad: four 1-3-digit groups separated by `.`, bounded on both sides. */
function matchDottedQuadAt(bytes: Buffer, start: number): number | null {
  let pos = start;
  for (let group = 0; group < 4; group++) {
    let len = 0;
    while (pos < bytes.length && isAsciiDigit(bytes[pos]) && len < 3) {
      pos += 1;
      len += 1;
    }
    if (len === 0) return null;
    if (isAsciiDigit(bytes[pos])) return null;
    if (group < 3) {
      if (bytes[pos] !== 0x2e) return null;
      pos += 1;
    }
  }
  return pos;
}

function containsDottedQuad(bytes: Buffer): boolean {
  for (let index = 0; index < bytes.length; index++) {
    const boundedBefore = index === 0 || !isDigitOrDot(bytes[index - 1]);
    if (isAsciiDigit(bytes[index]) && boundedBefore) {
      const end = matchDottedQuadAt(bytes, index);
      if (end !== null && (end >= bytes.length || !isDigitOrDot(bytes[end]))) {
        return true;
      }
    }
  }
  return false;
}

function isWordByte(byte: number | undefined): boolean {
  if (byte === undefined) return false;
  return (byte >= 0x30 && byte <= 0x39) || (byte >= 0x41 && byte <= 0x5a) || (byte >= 0x61 && byte <= 0x7a) || byte === 0x5f;
}

/** `sk-` not preceded by a word byte, followed by `ant-` or 16+ further word bytes. */
function containsSkPrefixedKey(bytes: Buffer): boolean {
  const MIN_KEY_TAIL = 16;
  return findAll(bytes, "sk-").some((index) => {
    if (isWordByte(bytes[index - 1])) return false;
    if (startsWithAscii(bytes, index + 3, "ant-")) return true;
    let run = 0;
    let pos = index + 3;
    while (isWordByte(bytes[pos])) {
      run += 1;
      pos += 1;
    }
    return run >= MIN_KEY_TAIL;
  });
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

  it("names no absolute origin (S4)", () => {
    for (const [path, bytes] of files) {
      expect(containsDisallowedScheme(bytes, "http://"), `${path} contains a disallowed http:// reference`).toBe(
        false,
      );
      expect(containsDisallowedScheme(bytes, "https://"), `${path} contains an https:// reference`).toBe(false);
      expect(containsSchemeWithDigitHost(bytes), `${path} contains a scheme://<digit> reference`).toBe(false);
      expect(containsDottedQuad(bytes), `${path} contains a bare dotted-quad IP address`).toBe(false);
    }
  });

  it("discloses no build-machine path (S4)", () => {
    for (const [path, bytes] of files) {
      for (const needle of ["/home/", "/Users/", "C:\\"]) {
        expect(bytes.includes(needle), `${path} contains ${JSON.stringify(needle)}`).toBe(false);
      }
    }
  });

  it("contains no sk-prefixed key shape (S4)", () => {
    for (const [path, bytes] of files) {
      expect(containsSkPrefixedKey(bytes), `${path} contains an sk--prefixed key shape`).toBe(false);
    }
  });
});

describe("self_tests (mirroring dist_public_content.rs's self_tests module)", () => {
  it("containsDisallowedScheme allows only the w3.org SVG namespace", () => {
    expect(containsDisallowedScheme(Buffer.from("xmlns=http://www.w3.org/2000/svg"), "http://")).toBe(false);
    expect(containsDisallowedScheme(Buffer.from('fetch("http://evil.example.com/")'), "http://")).toBe(true);
    expect(containsDisallowedScheme(Buffer.from('fetch("https://evil.example.com/")'), "https://")).toBe(true);
  });

  it("containsDisallowedScheme matches case-insensitively (fix round 1, D6)", () => {
    expect(containsDisallowedScheme(Buffer.from('fetch("Http://evil.example.com/")'), "http://")).toBe(true);
    expect(containsDisallowedScheme(Buffer.from('fetch("HTTPS://EVIL.EXAMPLE.COM/")'), "https://")).toBe(true);
    expect(containsDisallowedScheme(Buffer.from("xmlns=HTTP://WWW.W3.ORG/2000/svg"), "http://")).toBe(false);
  });

  it("containsSchemeWithDigitHost matches any scheme over an IP literal", () => {
    expect(containsSchemeWithDigitHost(Buffer.from("ws://192.168.1.5:9000"))).toBe(true);
    expect(containsSchemeWithDigitHost(Buffer.from("http://www.w3.org/2000/svg"))).toBe(false);
  });

  it("containsDottedQuad matches a bare IP but not a semver string", () => {
    expect(containsDottedQuad(Buffer.from("target host 192.168.1.5 reached"))).toBe(true);
    expect(containsDottedQuad(Buffer.from("solid-js 1.9.15"))).toBe(false);
    expect(containsDottedQuad(Buffer.from("9.192.168.1.5.9"))).toBe(false);
  });

  it("containsSkPrefixedKey is anchored against ordinary hyphenated identifiers", () => {
    expect(containsSkPrefixedKey(Buffer.from('class="task-row"'))).toBe(false);
    expect(containsSkPrefixedKey(Buffer.from("sk-ant-api03-abcdefghijklmnop"))).toBe(true);
    expect(containsSkPrefixedKey(Buffer.from("sk-1234567890abcdef1234567890"))).toBe(true);
    expect(containsSkPrefixedKey(Buffer.from("sk-short"))).toBe(false);
  });
});
