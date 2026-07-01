// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
import { test } from "node:test";
import assert from "node:assert/strict";
import { writeFileSync, chmodSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { register, egress, withEgress, verify, verifyDetails, rdap, egressIp, ip, WhisperError, firstAddr, list, policy, logs, revoke, identity, agent } from "../index.js";

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

// verify/rdap/egressIp are keyless HTTP now — stub global fetch.
function stubFetch(status, body) {
  globalThis.fetch = async () => ({ status, json: async () => body });
}

test("verify is true for an agent (200), false for non-agent (404) and non-agent body", async () => {
  stubFetch(200, { is_whisper_agent: true, operator: "tABC", dane_ok: true });
  assert.equal(await verify("2a04:2a01:1::1"), true);
  stubFetch(404, { is_whisper_agent: false });
  assert.equal(await verify("2001:db8::1"), false);
  stubFetch(200, { is_whisper_agent: false });
  assert.equal(await verify("2001:db8::1"), false);
});

test("verifyDetails returns the verdict or null", async () => {
  stubFetch(200, { is_whisper_agent: true, fqdn: "x.agents.whisper.online", jws_ok: true });
  const d = await verifyDetails("2a04:2a01:1::1");
  assert.equal(d.jws_ok, true);
  stubFetch(404, {});
  assert.equal(await verifyDetails("2001:db8::1"), null);
});

test("rdap returns the record or null; egressIp returns the ip", async () => {
  stubFetch(200, { handle: "ag1", name: "scout", status: ["active"] });
  assert.equal((await rdap("2a04:2a01:1::1")).name, "scout");
  stubFetch(404, null);
  assert.equal(await rdap("2001:db8::1"), null);
  stubFetch(200, { ip: "2a04:2a01:1::a" });
  assert.equal(await egressIp(), "2a04:2a01:1::a");
});

test("verify rejects an empty address", async () => {
  await assert.rejects(() => verify("  "), WhisperError);
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

// ── Control plane (pure HTTP) ───────────────────────────────────────────────────────
// A capturing fetch stub: records the last request and returns a canned envelope.
let lastReq = null;
function stubControl(status, body) {
  lastReq = null;
  globalThis.fetch = async (url, init) => {
    lastReq = { url, init, sent: init && init.body ? JSON.parse(init.body) : null };
    return { status, json: async () => body };
  };
}
process.env.WHISPER_API_KEY = "whisper_live_TESTKEY"; // control tests: a key is present

// The two documented envelope shapes.
const liveList = {
  columns: ["op", "ok", "status", "result", "error", "retry_after"],
  rows: [
    {
      op: "list",
      ok: true,
      status: 200,
      result: { columns: ["kind", "item"], rows: [["agents", { label: "scout", address: "2a04:2a01:1::1", agent: "ag_1", state: "active" }]] },
      error: null,
      retry_after: null,
    },
  ],
};
const flatPolicy = { ok: true, status: 200, result: { columns: ["key", "value"], rows: [["default", "allow"], ["block", "ads.example"]] }, error: null };

test("list: decodes the live row-envelope, unwraps items, sends X-API-Key + op:list", async () => {
  stubControl(200, liveList);
  const items = await list();
  assert.equal(items.length, 1);
  assert.equal(items[0].label, "scout");
  assert.equal(items[0].address, "2a04:2a01:1::1");
  // request shape
  assert.equal(lastReq.init.method, "POST");
  assert.equal(lastReq.init.headers["X-API-Key"], "whisper_live_TESTKEY");
  assert.equal(lastReq.init.headers["Content-Type"], "application/json");
  assert.match(lastReq.sent.query, /CALL whisper\.agents\(\{op:'list', args:\{kind:'agents'\}\}\)/);
});

test("list accepts a bare kind string", async () => {
  stubControl(200, liveList);
  await list("identities");
  assert.match(lastReq.sent.query, /args:\{kind:'identities'\}/);
});

test("policy: no args READS; the query carries empty args", async () => {
  stubControl(200, flatPolicy);
  const pol = await policy();
  assert.equal(pol[0].key, "default");
  assert.equal(pol[0].value, "allow");
  assert.match(lastReq.sent.query, /op:'policy', args:\{\}\}/);
});

test("policy: set renders args with SORTED keys + doubled-quote escaping", async () => {
  stubControl(200, flatPolicy);
  await policy({ default: "deny", block: ["x.com", "y.com"], allow: ["z.com"] });
  assert.equal(lastReq.sent.query, "CALL whisper.agents({op:'policy', args:{allow:['z.com'],block:['x.com','y.com'],default:'deny'}})");
});

test("logs: filters map to args; returns event records", async () => {
  stubControl(200, { ok: true, result: { columns: ["ts", "kind", "qname"], rows: [[123, "dns", "a.example"]] } });
  const evs = await logs({ kind: "dns", limit: 50, agent: "ag_1" });
  assert.equal(evs[0].qname, "a.example");
  assert.match(lastReq.sent.query, /args:\{agent:'ag_1',kind:'dns',limit:50\}/);
});

test("identity: allocate escapes an apostrophe in the label (Tim O'Reilly → 'Tim O''Reilly')", async () => {
  stubControl(200, { ok: true, result: { columns: ["agent", "address"], rows: [["ag_9", "2a04:2a01:2::9"]] } });
  const id = await identity({ label: "Tim O'Reilly" });
  assert.equal(id.address, "2a04:2a01:2::9");
  assert.match(lastReq.sent.query, /label:'Tim O''Reilly'/);
});

test("identity: release form requires an address", async () => {
  await assert.rejects(() => identity({ release: true }), WhisperError);
});

test("agent: a colon selector is an address, else an id", async () => {
  stubControl(200, { ok: true, result: { columns: ["agent", "address", "state"], rows: [["ag_1", "2a04:2a01:1::1", "active"]] } });
  await agent("2a04:2a01:1::1");
  assert.match(lastReq.sent.query, /args:\{address:'2a04:2a01:1::1'\}/);
  stubControl(200, { ok: true, result: { columns: ["agent"], rows: [["ag_1"]] } });
  await agent("ag_1");
  assert.match(lastReq.sent.query, /args:\{agent:'ag_1'\}/);
});

test("revoke: bare id → {status}; ok:false throws WhisperError with the server detail", async () => {
  stubControl(200, { ok: true, result: { columns: ["status"], rows: [["revoked"]] } });
  const r = await revoke("ag_1");
  assert.equal(r.status, "revoked");
  // ok:false path
  stubControl(403, { ok: false, status: 403, error: { title: "forbidden", status: 403, detail: "scope admin:dns required" } });
  await assert.rejects(
    () => revoke("ag_1"),
    (err) => err instanceof WhisperError && err.message === "scope admin:dns required" && err.status === 403
  );
});

test("control calls require a key (opts.apiKey or WHISPER_API_KEY)", async () => {
  const saved = process.env.WHISPER_API_KEY;
  delete process.env.WHISPER_API_KEY;
  await assert.rejects(() => list(), WhisperError);
  // opts.apiKey satisfies it (never falls back to env)
  stubControl(200, liveList);
  await list({ apiKey: "whisper_live_VIAOPTS" });
  assert.equal(lastReq.init.headers["X-API-Key"], "whisper_live_VIAOPTS");
  process.env.WHISPER_API_KEY = saved;
});

test("revoke rejects an empty selector", async () => {
  await assert.rejects(() => revoke("  "), WhisperError);
});
