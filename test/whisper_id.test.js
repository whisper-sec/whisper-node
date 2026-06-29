// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
import { test } from "node:test";
import assert from "node:assert/strict";
import { writeFileSync, chmodSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { register, egress, withEgress, verify, ip, WhisperError, firstAddr } from "../index.js";

// A fake `whisper` so tests exercise the real execFile path with no live box.
const dir = mkdtempSync(join(tmpdir(), "wid-"));
const fake = join(dir, "whisper");
writeFileSync(
  fake,
  `#!/usr/bin/env bash
args="$*"
if [[ "$args" == *create* ]]; then echo '{"agent":"2a04:2a01:b69a:6717:dead:beef:1:2","id":"ag_123"}'; exit 0; fi
if [[ "$args" == *connect* ]]; then echo "whisper: connection up on 127.0.0.1:36123"; exit 0; fi
if [[ "$args" == *verify* ]]; then case "$args" in *2a04:2a01*) exit 0;; *) exit 3;; esac; fi
if [[ "$args" == *" ip"* ]]; then echo '{"agent":"2a04:2a01:1::a","ip":"2a04:2a01:1::a","verified":true}'; exit 0; fi
echo "unknown" >&2; exit 2
`,
);
chmodSync(fake, 0o755);
process.env.WHISPER_BIN = fake;
for (const k of ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"]) delete process.env[k];

test("register parses the /128 and id", async () => {
  const a = await register("my-bot");
  assert.equal(a.address, "2a04:2a01:b69a:6717:dead:beef:1:2");
  assert.equal(a.id, "ag_123");
  assert.equal(a.name, "my-bot");
});

test("register rejects an empty name", async () => {
  await assert.rejects(() => register("  "), WhisperError);
});

test("egress reports the port and sets/restores env", async () => {
  process.env.HTTP_PROXY = "http://old:1";
  const e = await egress();
  assert.equal(e.port, 36123);
  assert.equal(e.proxyUrl, "http://127.0.0.1:36123");
  assert.equal(e.socksUrl, "socks5h://127.0.0.1:36123");
  assert.equal(process.env.HTTP_PROXY, "http://127.0.0.1:36123");
  assert.equal(process.env.ALL_PROXY, "socks5h://127.0.0.1:36123");
  e.close();
  assert.equal(process.env.HTTP_PROXY, "http://old:1"); // restored
  assert.equal(process.env.ALL_PROXY, undefined); // was unset → unset again
  delete process.env.HTTP_PROXY;
});

test("withEgress restores env after the callback", async () => {
  const seen = await withEgress(async (e) => {
    assert.equal(process.env.HTTP_PROXY, e.proxyUrl);
    return e.port;
  });
  assert.equal(seen, 36123);
  assert.equal(process.env.HTTP_PROXY, undefined);
});

test("verify is true for a whisper agent, false otherwise", async () => {
  assert.equal(await verify("2a04:2a01:1::1"), true);
  assert.equal(await verify("2001:db8::1"), false);
});

test("ip returns the address", async () => {
  assert.equal(await ip(), "2a04:2a01:1::a");
});

test("missing binary raises WhisperError", async () => {
  const saved = process.env.WHISPER_BIN;
  process.env.WHISPER_BIN = join(dir, "does-not-exist");
  await assert.rejects(() => ip(), WhisperError);
  process.env.WHISPER_BIN = saved;
});

test("firstAddr pulls a /128 from any shape", () => {
  assert.equal(firstAddr({ x: { y: "2a04:2a01:9::1" } }), "2a04:2a01:9::1");
  assert.equal(firstAddr({ nope: true }), null);
});
