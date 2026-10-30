// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
import { test } from "node:test";
import assert from "node:assert/strict";
import { writeFileSync, chmodSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { register, egress, withEgress, verify, verifyDetails, rdap, egressIp, ip, WhisperError, NotFoundError, firstAddr, list, policy, logs, revoke, identity, agent, graph } from "../index.js";

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

// verify/rdap/egressIp are keyless HTTP now, so stub global fetch.
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

// Nothing revoked: the plane says it two ways, and both must throw NotFoundError
// with the server's own message. Never a bare 404, never a success.
const notFoundErr = { code: "NOT_FOUND", message: "nothing was revoked: no agent of yours matches 'ag_gone'", retryable: false };
const rowCols = ["op", "ok", "status", "result", "error", "retry_after", "elapsed_ms"];
const isNotFoundErr = (err) =>
  err instanceof NotFoundError && err instanceof WhisperError &&
  err.code === "NOT_FOUND" && err.status === 404 && err.retryable === false;

for (const [name, status, body] of [
  ["front door, object row", 200, { columns: rowCols, rows: [{ op: "revoke", ok: false, status: 404, result: null, error: notFoundErr, retry_after: null, elapsed_ms: 3 }] }],
  ["front door, positional row", 200, { columns: rowCols, rows: [["revoke", false, 404, null, notFoundErr, null, 3]] }],
  ["flat envelope on HTTP 404", 404, { ok: false, status: 404, result: null, error: notFoundErr }],
]) {
  test(`revoke: NOT_FOUND (${name}) throws NotFoundError with the server's message`, async () => {
    stubControl(status, body);
    await assert.rejects(() => revoke("ag_gone"), (err) => isNotFoundErr(err) && err.message === notFoundErr.message);
  });
}

for (const [name, cols, row] of [
  ["status", ["agent", "status"], ["ag_gone", "not_found"]],
  ["under item", ["item"], [{ agent: "ag_gone", status: "NOT_FOUND" }]],
]) {
  test(`revoke: an older plane's ok row with not_found (${name}) throws NotFoundError`, async () => {
    stubControl(200, { ok: true, status: 200, result: { columns: cols, rows: [row] } });
    await assert.rejects(() => revoke("ag_gone"), (err) => isNotFoundErr(err) && /nothing was revoked.*ag_gone/.test(err.message));
  });
}

test("revoke: a bare 404 with no NOT_FOUND code is a plain WhisperError, not NotFoundError", async () => {
  stubControl(404, { title: "Not Found", status: 404, detail: "no such route" });
  await assert.rejects(() => revoke("ag_gone"), (err) => err instanceof WhisperError && !(err instanceof NotFoundError) && err.message === "no such route");
});

test("revoke: the NOT_FOUND code on a 403 is not NotFoundError", async () => {
  stubControl(403, { ok: false, status: 403, error: { code: "NOT_FOUND", message: "odd", retryable: false } });
  await assert.rejects(() => revoke("ag_gone"), (err) => err instanceof WhisperError && !(err instanceof NotFoundError) && err.status === 403);
});

test("control errors carry the server's code, message and retryable", async () => {
  stubControl(200, { columns: rowCols, rows: [{ op: "policy", ok: false, status: 403, result: null, error: { code: "FORBIDDEN", message: "this key lacks dns:policy:write", retryable: false } }] });
  await assert.rejects(
    () => policy({ default: "deny" }),
    (err) => err instanceof WhisperError && err.code === "FORBIDDEN" && err.status === 403 && err.retryable === false && err.message === "this key lacks dns:policy:write"
  );
});

test("revoke: a real revoke in the front-door row still resolves", async () => {
  stubControl(200, { columns: rowCols, rows: [{ op: "revoke", ok: true, status: 200, result: { columns: ["agent", "status"], rows: [["ag_1", "revoked"]] }, error: null }] });
  const r = await revoke("ag_1");
  assert.equal(r.status, "revoked");
  assert.equal(r.agent, "ag_1");
});

test("revoke rejects an empty selector", async () => {
  await assert.rejects(() => revoke("  "), WhisperError);
});

// ── Graph namespace (two-tier Cypher, /api/query contract) ──────────────────────────
// The graph envelope: {columns, rows:[{col:val}], statistics}. Rows are already keyed
// objects (NOT the whisper.agents row-envelope). stubControl (above) captures lastReq.
// Every graph verb proxies up with a key or without one; the graph owns the keyless
// policy and decides what to answer. The SDK never refuses a graph call on the caller's
// behalf. Only the control plane (whisper.agents) requires a key client-side.
const graphEnvelope = {
  columns: ["host", "vendor_id", "canonical_name"],
  rows: [{ host: "api.openai.com", vendor_id: "openai", canonical_name: "OpenAI" }],
  statistics: { rowCount: 1, executionTimeMs: 7 },
};

test("graph.identify: posts {query,parameters} (NOT whisper.agents), sends X-API-Key, keyed rows come back", async () => {
  stubControl(200, graphEnvelope);
  const res = await graph.identify("api.openai.com");
  // request shape: the raw graph contract, not the control wrapper
  assert.equal(lastReq.init.method, "POST");
  assert.equal(lastReq.init.headers["X-API-Key"], "whisper_live_TESTKEY");
  assert.equal(lastReq.init.headers["Content-Type"], "application/json");
  assert.match(lastReq.sent.query, /CALL whisper\.identify\(\[\$v\]\) YIELD host, vendor_id/);
  assert.ok(!/whisper\.agents/.test(lastReq.sent.query)); // never the control wrapper
  assert.deepEqual(lastReq.sent.parameters, { v: "api.openai.com" });
  // result: normalized {columns,rows,statistics}; rows keyed by column name
  assert.deepEqual(res.columns, ["host", "vendor_id", "canonical_name"]);
  assert.equal(res.rows[0].vendor_id, "openai");
  assert.equal(res.statistics.rowCount, 1);
});

test("graph direct methods bind $v and carry their catalog Cypher", async () => {
  stubControl(200, { columns: ["apex"], rows: [{ apex: "foo.co.uk" }] });
  await graph.pslTldplusone("www.foo.co.uk");
  assert.match(lastReq.sent.query, /CALL whisper\.psl\.tldPlusOne\(\$v\) YIELD apex/);
  assert.deepEqual(lastReq.sent.parameters, { v: "www.foo.co.uk" });

  stubControl(200, { columns: ["asSetName", "memberAsn"], rows: [] });
  await graph.asset("AS-CLOUDFLARE");
  assert.match(lastReq.sent.query, /CALL whisper\.asSet\(\$v\)/);
  assert.deepEqual(lastReq.sent.parameters, { v: "AS-CLOUDFLARE" });
});

test("graph.dbSchema: no input, empty parameters", async () => {
  stubControl(200, { columns: ["type", "name"], rows: [{ type: "node", name: "HOSTNAME" }] });
  const res = await graph.dbSchema();
  assert.equal(lastReq.sent.query, "CALL db.schema()");
  assert.deepEqual(lastReq.sent.parameters, {});
  assert.equal(res.rows[0].name, "HOSTNAME");
});

test("graph.submit: builds the catalog map-call with SORTED $-bound fields; needs a kind", async () => {
  stubControl(200, { columns: ["status"], rows: [{ status: "accepted" }] });
  await graph.submit({ kind: "indicator", identifier_kind: "ip", value: "203.0.113.5" });
  assert.equal(lastReq.sent.query, "CALL whisper.submit({identifier_kind:$identifier_kind, kind:$kind, value:$value})");
  assert.deepEqual(lastReq.sent.parameters, { kind: "indicator", identifier_kind: "ip", value: "203.0.113.5" });
  await assert.rejects(() => graph.submit({ value: "x" }), WhisperError); // no kind
});

test("graph.submit: accepts camelCase field spellings and normalises them to the wire form", async () => {
  stubControl(200, { columns: ["status"], rows: [{ status: "accepted" }] });
  await graph.submit({ kind: "feedback", observationId: "obs-1", comment: "false positive" });
  assert.equal(lastReq.sent.query, "CALL whisper.submit({comment:$comment, kind:$kind, observation_id:$observation_id})");
  assert.deepEqual(lastReq.sent.parameters, { kind: "feedback", observation_id: "obs-1", comment: "false positive" });
  // a hostile field name can never reach the Cypher
  await assert.rejects(() => graph.submit({ kind: "indicator", "x}) CALL evil(": 1 }), WhisperError);
});

test("graph.query: raw escape hatch passes cypher + params through", async () => {
  stubControl(200, { columns: ["n"], rows: [{ n: 1 }], statistics: { rowCount: 1 } });
  const res = await graph.query("MATCH (n) RETURN n LIMIT $lim", { lim: 1 });
  assert.equal(lastReq.sent.query, "MATCH (n) RETURN n LIMIT $lim");
  assert.deepEqual(lastReq.sent.parameters, { lim: 1 });
  assert.equal(res.rows[0].n, 1);
  await assert.rejects(() => graph.query("  "), WhisperError); // empty cypher
});

test("graph accepts positional-array rows and aligns them to columns", async () => {
  stubControl(200, { columns: ["ip", "confidence"], rows: [["1.2.3.4", 0.9]], statistics: null });
  const res = await graph.origins("cloudflare.com");
  assert.deepEqual(res.rows[0], { ip: "1.2.3.4", confidence: 0.9 });
});

test("graph: an empty value is rejected with a clear WhisperError", async () => {
  await assert.rejects(() => graph.identify("  "), WhisperError);
});

test("graph two-tier: a keyless read verb with NO key does not throw and omits the auth header", async () => {
  const saved = process.env.WHISPER_API_KEY;
  delete process.env.WHISPER_API_KEY;
  stubControl(200, graphEnvelope);
  const res = await graph.identify("api.openai.com"); // keyless taste: no key, real answer
  assert.equal(res.rows[0].vendor_id, "openai");
  assert.ok(!("X-API-Key" in lastReq.init.headers), "keyless call must not send X-API-Key");
  // the same holds for the no-input read
  stubControl(200, { columns: ["type"], rows: [{ type: "node" }] });
  await graph.dbSchema();
  assert.ok(!("X-API-Key" in lastReq.init.headers));
  // a key, when present, is still sent (it lifts the rate limit)
  stubControl(200, graphEnvelope);
  await graph.identify("api.openai.com", { apiKey: "whisper_live_VIAOPTS" });
  assert.equal(lastReq.init.headers["X-API-Key"], "whisper_live_VIAOPTS");
  process.env.WHISPER_API_KEY = saved;
});

test("graph flow: a keyless call sends NO X-API-Key header at all", async () => {
  // An empty credential is not the same as no credential. A server handed "" refuses
  // instead of applying keyless policy, so the header must be absent, not blank.
  const savedKey = process.env.WHISPER_API_KEY;
  const realFetch = globalThis.fetch;
  let seen = null;
  globalThis.fetch = async (_url, init) => {
    seen = Object.keys(init.headers).map((h) => h.toLowerCase());
    throw new Error("intercepted");
  };
  try {
    delete process.env.WHISPER_API_KEY;
    try { await graph.typosquat("paypal.com"); } catch (e) {}
    assert.ok(!seen.includes("x-api-key"), "keyless flow must omit X-API-Key");
    seen = null;
    try { await graph.typosquat("paypal.com", { apiKey: "whisper_live_K" }); } catch (e) {}
    assert.ok(seen.includes("x-api-key"), "keyed flow must send X-API-Key");
  } finally {
    globalThis.fetch = realFetch;
    if (savedKey !== undefined) process.env.WHISPER_API_KEY = savedKey;
  }
});

test("graph: no verb is gated client-side; every one is sent for the graph to decide", async () => {
  // The SDK must not refuse a graph call on the caller's behalf. raw query, submit and the
  // flows were gated here once; that was self-inflicted friction. They now go out with an
  // empty key and the graph answers or refuses. Only whisper.agents still requires a key.
  const saved = process.env.WHISPER_API_KEY;
  delete process.env.WHISPER_API_KEY;
  stubControl(200, graphEnvelope);
  await graph.query("CALL db.schema()");
  assert.equal(lastReq.init.headers["X-API-Key"], undefined, "keyless: no X-API-Key header");
  stubControl(200, graphEnvelope);
  await graph.submit({ kind: "indicator", identifier_kind: "ip", value: "203.0.113.5" });
  assert.ok(lastReq.sent.query.includes("whisper.submit"), "submit was sent, not refused");
  process.env.WHISPER_API_KEY = saved;
});

test("graph.recipes: keyless, no-network catalog discovery of all 29 methods", () => {
  const recs = graph.recipes();
  assert.equal(recs.length, 29);
  const by = Object.fromEntries(recs.map((r) => [r.method, r]));
  // the two-tier split, straight from the catalog
  assert.equal(recs.filter((r) => r.keyless).length, 13);
  assert.equal(by.assess.keyless, true);
  assert.equal(by.assess.mode, "direct");
  assert.deepEqual(by.assess.params, ["v"]);
  assert.equal(by.typosquat.keyless, false);
  assert.equal(by.typosquat.mode, "flow");
  assert.deepEqual(by.typosquat.params, ["domain"]);
  assert.equal(by.submit.keyless, false);
  assert.ok(by.submit.params.includes("kind"));
  for (const r of recs) {
    assert.equal(typeof r.summary, "string");
    assert.ok(r.summary.length > 0, `${r.method} has no summary`);
    assert.match(r.docsUrl, /^https:\/\/www\.whisper\.security\/docs\//, `${r.method} has no docsUrl`);
    assert.equal(typeof graph[r.method], "function", `recipe ${r.method} is not callable on graph`);
  }
  // each call returns a fresh copy: mutating one never poisons the catalog
  recs[0].method = "clobbered";
  assert.notEqual(graph.recipes()[0].method, "clobbered");
});

test("graph: a server error body throws WhisperError carrying detail + status", async () => {
  stubControl(429, { error: { status: 429, detail: "rate limit exceeded", retry_after: 30 } });
  await assert.rejects(
    () => graph.assess("8.8.8.8"),
    (err) => err instanceof WhisperError && err.message === "rate limit exceeded" && err.status === 429 && err.retryAfter === 30
  );
});

// ── Flow methods (gallery/run, Server-Sent Events) ──────────────────────────────────
// A capturing fetch stub that streams an SSE body, like the live workflow runner.
function stubFlow(text, { status = 200, contentType = "text/event-stream; charset=utf-8" } = {}) {
  lastReq = null;
  globalThis.fetch = async (url, init) => {
    lastReq = { url, init, sent: init && init.body ? JSON.parse(init.body) : null };
    return {
      status,
      headers: { get: (h) => (h.toLowerCase() === "content-type" ? contentType : null) },
      body: (async function* () {
        yield new TextEncoder().encode(text);
      })(),
      json: async () => JSON.parse(text),
    };
  };
}

const sseStream =
  'event: start\ndata: {"slug":"typosquat"}\n\n' +
  'event: step-start\ndata: {"id":"registered","index":0}\n\n' +
  'event: step\ndata: {"id":"registered","status":"done","columns":["variant"],"rows":[{"variant":"paypa1.com"}]}\n\n' +
  'event: complete\ndata: {"slug":"typosquat","totalLatencyMs":9562,"context":{"registered":[{"variant":"paypa1.com"}]}}\n\n';

test("graph flow: a bare value binds the primary input and streams to {steps, complete, events}", async () => {
  stubFlow(sseStream);
  const res = await graph.typosquat("paypal.com");
  // request shape: the gallery/run contract
  assert.equal(lastReq.url, "https://console.whisper.security/api/gallery/run");
  assert.equal(lastReq.init.method, "POST");
  assert.equal(lastReq.init.headers["X-API-Key"], "whisper_live_TESTKEY");
  assert.equal(lastReq.init.headers.Accept, "text/event-stream");
  assert.deepEqual(lastReq.sent, { slug: "typosquat", value: "paypal.com" });
  // result: the collected stream
  assert.equal(res.slug, "typosquat");
  assert.equal(res.steps.length, 1);
  assert.equal(res.steps[0].rows[0].variant, "paypa1.com");
  assert.equal(res.complete.totalLatencyMs, 9562);
  assert.equal(res.events.length, 4);
  assert.equal(res.events[0].event, "start");
});

test("graph flow: a knob rides in paramValues and the primary input becomes value", async () => {
  stubFlow(sseStream.replaceAll("typosquat", "attack-surface"));
  await graph.attackSurface({ domain: "github.com", level: "deep" });
  assert.deepEqual(lastReq.sent, { slug: "attack-surface", value: "github.com", paramValues: { level: "deep" } });
  // explicit { inputs, params } wrapper: first input -> value, the rest + knobs -> paramValues
  stubFlow(sseStream.replaceAll("typosquat", "attack-path"));
  await graph.attackPath({ inputs: { value: "paypal.com", other: "paypa1.com" }, params: { level: "quick" } });
  assert.deepEqual(lastReq.sent, { slug: "attack-path", value: "paypal.com", paramValues: { other: "paypa1.com", level: "quick" } });
});

test("graph flow: an HTTP error surfaces the runner's message as WhisperError", async () => {
  stubFlow('{"error":"FlowNotFound","message":"No runnable flow for slug \\"x\\"."}', { status: 404, contentType: "application/json" });
  await assert.rejects(
    () => graph.blastRadius("ns1.example.com"),
    (err) => err instanceof WhisperError && /No runnable flow/.test(err.message) && err.status === 404
  );
});

test("graph flow: an error event with no complete rejects with the detail (events kept)", async () => {
  stubFlow('event: start\ndata: {"slug":"route-health"}\n\nevent: error\ndata: {"message":"step 2 failed"}\n\n');
  await assert.rejects(
    () => graph.routeHealth("1.1.1.0/24"),
    (err) => err instanceof WhisperError && err.message === "step 2 failed" && err.events.length === 2
  );
});

test("graph flow: an empty bare input is rejected with a clear error", async () => {
  // Input validation is ours (fail fast, clear message). Access is not: a flow with no key
  // is still sent, and the flow runner decides. See the no-client-side-gate test above.
  await assert.rejects(() => graph.typosquat("  "), /needs a value/);
});

test("graph namespace has exactly the 29 catalog methods + query + recipes (drift guard)", () => {
  const names = Object.keys(graph).filter((k) => typeof graph[k] === "function");
  assert.equal(names.length, 31); // 14 direct + 15 flow + query + recipes
  for (const m of ["query", "recipes", "identify", "assess", "dbSchema", "submit", "typosquat", "attackPath"]) {
    assert.ok(names.includes(m), `missing graph.${m}`);
  }
});

test("graph: every method carries its canonical docs URL as .docs (docsBase + docPath)", () => {
  for (const [name, fn] of Object.entries(graph)) {
    if (typeof fn !== "function") continue;
    assert.match(fn.docs, /^https:\/\/www\.whisper\.security\/docs\//, `graph.${name} has no docs link`);
  }
});

// ---------------------------------------------------------------------------
// The graph size this README states.
//
// The opening line is the first claim a reader meets on the package page, and it
// once carried a figure roughly half the real one. Read the live totals from
// https://nic.whisper.online/stats/data.json, which is keyless and public.
//
// The guard is a FLOOR rather than an exact match, and it is deliberately
// offline: it cannot fail because a network is down, and it cannot go stale as
// the graph grows. It fails only if the stated size drops far below what the
// graph has already reached.
// ---------------------------------------------------------------------------
test("the README states the graph size the graph actually has", () => {
  const here = dirname(fileURLToPath(import.meta.url));
  const body = readFileSync(join(here, "..", "README.md"), "utf8");
  // The control: the file really was read, so an empty read cannot pass.
  assert.ok(body.includes("Whisper security graph"), "README did not read as expected");

  const nodes = body.match(/([\d.]+)B nodes/);
  // Liberal in the word: "edges" and "relationships" are the same quantity, and a
  // guard that only knew one of them would read the other as "no figure at all".
  const edges = body.match(/([\d.]+)B (?:edges|relationships)/);
  assert.ok(nodes, "the README no longer states a node count");
  assert.ok(edges, "the README no longer states an edge count");
  assert.ok(
    parseFloat(nodes[1]) >= 7.0,
    `README states ${nodes[1]}B nodes; the graph passed 7.0B. Read the live figure from https://nic.whisper.online/stats/data.json.`,
  );
  assert.ok(
    parseFloat(edges[1]) >= 39.0,
    `README states ${edges[1]}B edges; the graph passed 39.0B. Read the live figure from https://nic.whisper.online/stats/data.json.`,
  );
});
