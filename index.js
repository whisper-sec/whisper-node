// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
// whisper-id - the Whisper security graph, a routable IPv6 identity, and safe egress for
// any Node agent. Dependency-free and two-tier (Postel): the graph's direct read verbs and
// the identity checks run KEYLESS over plain fetch() (graph.assess("8.8.8.8") needs no key
// at all); raw Cypher and the flows are sent the same way and the graph decides. Only the
// control plane requires WHISPER_API_KEY, and only register/egress/ip lean on the
// `whisper` CLI (https://whisper.online).
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const pexec = promisify(execFile);

const ADDR_RE = /2a04:2a01:[0-9a-fA-F:]{2,}/; // the public Whisper agent prefix (AS219419)
const HOSTPORT_RE = /127\.0\.0\.1:(\d{2,5})/;
const PROXY_VARS = ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"];
const UA = "whisper-id-node"; // client identifier for the keyless + control HTTP calls

/** Error thrown when a `whisper` invocation fails, or the CLI is not installed. */
export class WhisperError extends Error {
  constructor(message) {
    super(message);
    this.name = "WhisperError";
  }
}

function bin() {
  return process.env.WHISPER_BIN || "whisper";
}

async function run(args, { timeout = 120000, check = true } = {}) {
  try {
    const { stdout, stderr } = await pexec(bin(), args, { timeout, encoding: "utf8" });
    return { stdout: stdout || "", stderr: stderr || "", code: 0 };
  } catch (err) {
    if (err && err.code === "ENOENT") {
      throw new WhisperError(
        "the `whisper` CLI was not found on PATH. Install it with " +
          "`curl -fsSL https://get.whisper.online | sh` (see https://whisper.online)."
      );
    }
    const out = { stdout: err.stdout || "", stderr: err.stderr || "", code: typeof err.code === "number" ? err.code : 1 };
    if (check) {
      const detail = (out.stderr || out.stdout || err.message || `exit ${out.code}`).toString().trim();
      throw new WhisperError(`\`whisper ${args.join(" ")}\` failed: ${detail.slice(0, 300)}`);
    }
    return out;
  }
}

async function runJson(args, opts) {
  const { stdout } = await run(["--json", ...args], opts);
  try {
    return JSON.parse(stdout.trim());
  } catch {
    throw new WhisperError(`could not parse JSON from \`whisper ${args.join(" ")}\`: ${stdout.trim().slice(0, 200)}`);
  }
}

export function firstAddr(obj) {
  const m = ADDR_RE.exec(JSON.stringify(obj));
  return m ? m[0] : null;
}

function getKey(obj, ...keys) {
  if (obj && typeof obj === "object") {
    for (const k of keys) if (obj[k]) return obj[k];
    for (const v of Object.values(obj)) {
      if (v && typeof v === "object") {
        const got = getKey(v, ...keys);
        if (got) return got;
      }
    }
  }
  return null;
}

/** Create a named agent identity - a routable Whisper IPv6 /128. */
export async function register(name, { newKey = false, timeout = 120000 } = {}) {
  if (!name || !name.trim()) throw new WhisperError("register() needs a non-empty agent name");
  const args = ["create", "--name", name];
  if (newKey) args.push("--register");
  const env = await runJson(args, { timeout });
  const address = firstAddr(env);
  if (!address) throw new WhisperError(`no /128 returned by \`whisper create\`: ${JSON.stringify(env).slice(0, 200)}`);
  return { address, id: getKey(env, "id", "agent_id", "agentId"), name };
}

function makeEgress(port, address) {
  const proxyUrl = `http://127.0.0.1:${port}`;
  const socksUrl = `socks5h://127.0.0.1:${port}`;
  return { port, address: address || null, proxyUrl, socksUrl, proxies: { http: proxyUrl, https: proxyUrl }, close() {} };
}

/**
 * Bring egress up bound to your /128 (idempotent detached proxy). By default sets the standard
 * proxy env vars; call the returned `.close()` to restore them. Prefer `withEgress` for scoping.
 */
export async function egress({ agent, tier = "socks5", setEnv = true, timeout = 90000 } = {}) {
  const args = ["connect", "--ensure", "--tier", tier];
  if (agent) args.push("--agent", agent);
  const { stdout, stderr } = await run(args, { timeout });
  const m = HOSTPORT_RE.exec(`${stdout}\n${stderr}`);
  if (!m) throw new WhisperError(`could not determine the local proxy port from \`whisper connect\`: ${`${stdout}${stderr}`.trim().slice(0, 200)}`);
  const e = makeEgress(Number(m[1]), agent);
  const saved = {};
  if (setEnv) {
    for (const k of PROXY_VARS) saved[k] = process.env[k];
    process.env.HTTP_PROXY = process.env.http_proxy = e.proxyUrl;
    process.env.HTTPS_PROXY = process.env.https_proxy = e.proxyUrl;
    process.env.ALL_PROXY = process.env.all_proxy = e.socksUrl;
  }
  e.close = () => {
    for (const k of PROXY_VARS) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
  };
  return e;
}

/** Run `fn(egress)` with egress up, restoring the environment afterwards. */
export async function withEgress(optsOrFn, maybeFn) {
  const fn = typeof optsOrFn === "function" ? optsOrFn : maybeFn;
  const opts = typeof optsOrFn === "function" ? {} : optsOrFn || {};
  const e = await egress(opts);
  try {
    return await fn(e);
  } finally {
    e.close();
  }
}

// Keyless public endpoint base (the same surface the CLI uses, server-side). No key, no `whisper`
// CLI - these work in any runtime that can fetch() (serverless, edge, browser). Override via env.
function rdapBase() {
  return (process.env.WHISPER_RDAP_URL || "https://rdap.whisper.online").replace(/\/+$/, "");
}

async function httpGetJson(url, { timeout = 60000 } = {}) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeout);
  let res;
  try {
    res = await fetch(url, { headers: { Accept: "application/rdap+json, application/json, */*", "User-Agent": UA }, signal: ctrl.signal });
  } catch (err) {
    throw new WhisperError(`could not reach ${url}: ${err && err.message ? err.message : err}`);
  } finally {
    clearTimeout(t);
  }
  let body = null;
  try {
    body = await res.json();
  } catch {
    body = null;
  }
  return { status: res.status, body };
}

/**
 * Return true iff `address` is a real Whisper agent. **Keyless and CLI-free** - one HTTPS GET to
 * the public /verify-identity endpoint (server-side DANE+DNSSEC+reverse-DNS+JWS chain). Works in
 * any runtime. 200 ⇒ agent, 404 ⇒ not. Throws only if the endpoint is unreachable.
 */
export async function verify(address, { timeout = 60000 } = {}) {
  return (await verifyDetails(address, { timeout })) !== null;
}

/** Full verify verdict for a real agent (is_whisper_agent, fqdn, operator, tenant, dane_ok, jws_ok, ...), else null. Keyless, CLI-free. */
export async function verifyDetails(address, { timeout = 60000 } = {}) {
  if (!address || !address.trim()) throw new WhisperError("verify() needs an address");
  const url = `${rdapBase()}/verify-identity?ip=${encodeURIComponent(address.trim())}`;
  const { status, body } = await httpGetJson(url, { timeout });
  if (status !== 200 || !body || !body.is_whisper_agent) return null;
  return body;
}

/** Public RDAP record for a Whisper /128 (handle, name, status, entities, ...), or null. Keyless, CLI-free. */
export async function rdap(address, { timeout = 60000 } = {}) {
  if (!address || !address.trim()) throw new WhisperError("rdap() needs an address");
  const url = `${rdapBase()}/ip/${encodeURI(address.trim())}`; // path segment - keep the literal colons
  const { status, body } = await httpGetJson(url, { timeout });
  return status === 200 ? body : null;
}

/** The caller's current egress IP as seen by Whisper (what this process leaves from). Keyless, CLI-free. */
export async function egressIp({ timeout = 60000 } = {}) {
  const { status, body } = await httpGetJson(`${rdapBase()}/egress-ip`, { timeout });
  if (status !== 200) throw new WhisperError(`egress-ip endpoint returned HTTP ${status}`);
  return (body && body.ip) || "";
}

/** Return the current egress IP, proving it is your Whisper /128. */
export async function ip({ timeout = 60000 } = {}) {
  const env = await runJson(["ip"], { timeout });
  return getKey(env, "ip", "agent") || firstAddr(env) || "";
}

// ── Control plane (pure HTTP - no CLI) ──────────────────────────────────────────────
// The governance half of the two-tier surface (Postel: keyless verify above works with no
// key; these unlock with the caller's key). One control verb - `whisper.agents({op,args})`
// - POSTed straight to the control endpoint. No `whisper` CLI, no child process, no key on
// argv: works in any runtime with fetch() (serverless, edge, a plain server). The key is
// read from opts.apiKey or $WHISPER_API_KEY and sent ONLY in the X-API-Key header.

function controlUrl() {
  return process.env.WHISPER_CONTROL_URL || "https://graph.whisper.online/api/query";
}

// Conservative-emit (RFC 761): render a value as a Cypher literal so no input - however
// hostile - can break out of the map. A ' is doubled and a \ is doubled (order matters:
// backslashes first). Mirrors the reference client's cypher builder byte-for-byte.
function escapeCypher(s) {
  return String(s).replace(/\\/g, "\\\\").replace(/'/g, "''");
}
function quoteCypher(s) {
  return "'" + escapeCypher(s) + "'";
}
function lit(v) {
  if (v === null || v === undefined) return "null";
  if (typeof v === "string") return quoteCypher(v);
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "number") return Number.isFinite(v) ? String(v) : "null";
  if (Array.isArray(v)) return "[" + v.map(lit).join(",") + "]";
  if (typeof v === "object") return cypherMap(v);
  return quoteCypher(String(v));
}
// A Cypher map literal with keys in SORTED order → the query is byte-stable. undefined
// values are dropped so callers can pass a sparse args object.
function cypherMap(m) {
  const keys = Object.keys(m).filter((k) => m[k] !== undefined).sort();
  if (keys.length === 0) return "{}";
  return "{" + keys.map((k) => k + ":" + lit(m[k])).join(",") + "}";
}
function buildAgentsQuery(op, args) {
  const inner = args && Object.keys(args).some((k) => args[k] !== undefined) ? cypherMap(args) : "{}";
  return "CALL whisper.agents({op:" + quoteCypher(op) + ", args:" + inner + "})";
}

// Liberal-accept (RFC 761): decode BOTH documented envelope shapes into one normalised
// { ok, status, result, error, retryAfter } - the flat {ok,status,result,error} dev shape
// AND the live procedure-row table whose single row carries the per-op envelope - plus a
// bare RFC-7807 problem object. Never throws on shape; a fault becomes error, not a crash.
function decodeEnvelope(body, httpStatus) {
  const out = { ok: false, status: httpStatus, result: null, error: null, retryAfter: null };
  if (!body || typeof body !== "object") {
    out.error = { status: httpStatus, detail: httpStatus >= 400 ? "control plane returned a non-JSON error reply" : "control plane returned an unexpected reply" };
    return out;
  }
  const applyRow = (row) => {
    out.ok = !!row.ok;
    out.result = row.result || null;
    out.error = row.error || null;
    if (row.status) out.status = row.status;
    if (row.retry_after != null) out.retryAfter = row.retry_after;
    if (!out.ok && !out.error) out.error = { status: out.status, detail: "control plane reported failure" };
    if (out.error && !out.error.status) out.error.status = out.status;
    return out;
  };
  // Shape B - an explicit ok flag at the top level.
  if (typeof body.ok === "boolean") return applyRow(body);
  // Shape A - the procedure-row table: rows[0] carries {op,ok,status,result,error,...}. The
  // row may be an object already, or a positional array aligned to top-level columns.
  if (Array.isArray(body.rows) && body.rows.length > 0) {
    let row0 = body.rows[0];
    if (Array.isArray(row0) && Array.isArray(body.columns)) {
      const obj = {};
      body.columns.forEach((c, i) => { obj[c] = row0[i]; });
      row0 = obj;
    }
    if (row0 && typeof row0 === "object" && !Array.isArray(row0)) {
      if (typeof row0.ok === "boolean") return applyRow(row0);
      if (row0.result) { out.ok = true; out.result = row0.result; return out; }
    }
  }
  // A bare RFC-7807 problem object (no ok, no rows).
  if (body.error || body.detail || body.title || body.type) {
    out.error = body.error || { status: body.status || httpStatus, detail: body.detail, title: body.title, type: body.type };
    if (!out.error.status) out.error.status = httpStatus;
    return out;
  }
  // A top-level result, or a shapeless-but-valid table → success (read ops fail OPEN).
  if (body.result) { out.ok = true; out.result = body.result; return out; }
  if (Array.isArray(body.columns) || Array.isArray(body.rows)) {
    out.ok = true; out.result = { columns: body.columns || [], rows: body.rows || [] }; return out;
  }
  if (httpStatus >= 400) { out.error = { status: httpStatus, detail: "control plane reported failure" }; return out; }
  out.ok = true; out.result = { columns: [], rows: [] };
  return out;
}

// Turn a {columns,rows} result into column-keyed records. Rows may be positional arrays
// (aligned to columns) or already-keyed objects - both are accepted.
function recordsFrom(result) {
  if (!result || !Array.isArray(result.rows)) return [];
  const cols = Array.isArray(result.columns) ? result.columns : [];
  return result.rows.map((row) => {
    if (!Array.isArray(row)) return row && typeof row === "object" ? row : { value: row };
    const m = {};
    cols.forEach((c, i) => { if (i < row.length) m[c] = row[i]; });
    return m;
  });
}

function resolveKey(opts) {
  const key = (opts && opts.apiKey) || process.env.WHISPER_API_KEY;
  return key && String(key).trim();
}

// The one place that talks to the control plane. Builds the injection-proof query, POSTs
// it with the key in X-API-Key, decodes either envelope shape, and throws WhisperError
// (carrying the server's helpful `detail`, plus .status/.retryAfter) on ok:false. The key
// is never logged, never placed on argv, never returned.
async function callControl(op, args, opts = {}) {
  const key = resolveKey(opts);
  if (!key) {
    throw new WhisperError(
      `\`${op}\` needs a Whisper API key - pass { apiKey } or set WHISPER_API_KEY. ` +
        "(verify/verifyDetails/rdap and the graph's direct read verbs are keyless and need no key.)"
    );
  }
  const url = controlUrl();
  const timeout = opts.timeout || 60000;
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeout);
  let res;
  try {
    res = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
        "X-API-Key": key,
        "User-Agent": UA,
      },
      body: JSON.stringify({ query: buildAgentsQuery(op, args || {}) }),
      signal: ctrl.signal,
    });
  } catch (err) {
    throw new WhisperError(`could not reach the Whisper control plane at ${url}: ${err && err.message ? err.message : err}`);
  } finally {
    clearTimeout(t);
  }
  let body = null;
  try {
    body = await res.json();
  } catch {
    body = null;
  }
  const env = decodeEnvelope(body, res.status);
  if (!env.ok) {
    const e = env.error || {};
    const werr = new WhisperError(e.detail || e.title || e.type || `control plane returned HTTP ${env.status}`);
    werr.status = env.status;
    if (env.retryAfter != null) werr.retryAfter = env.retryAfter;
    if (e.suggestions) werr.suggestions = e.suggestions;
    throw werr;
  }
  return recordsFrom(env.result);
}

/**
 * List your fleet (keyed control plane). `kind`: "agents" (default) | "identities" | "records".
 * Liberal input: `list("identities")` or `list({ kind, apiKey })`. → an array of items
 * (`{label, fqdn, address, agent, created, state}`), newest-first is up to the caller.
 */
export async function list(opts = {}) {
  const o = typeof opts === "string" ? { kind: opts } : opts || {};
  const recs = await callControl("list", { kind: o.kind || "agents" }, o);
  // op:list rows are {kind,item}; unwrap to the item map when present.
  return recs.map((r) => (r && typeof r.item === "object" && r.item !== null ? r.item : r));
}

/**
 * Read or set your per-tenant DNS resolver policy (op:policy). NO policy fields ⇒ READ.
 * To set: `policy({ default:"deny", block:["x.com"], allow:["y.com"] })`. → an array of
 * `{ key, value }` rows (the effective policy).
 */
export async function policy(opts = {}) {
  const o = opts || {};
  const args = {};
  if (o.default != null && o.default !== "") args.default = o.default;
  if (Array.isArray(o.allow) && o.allow.length) args.allow = o.allow;
  if (Array.isArray(o.block) && o.block.length) args.block = o.block;
  return callControl("policy", args, o);
}

/**
 * Query recent activity from warm storage (op:logs) - the poll counterpart of the live
 * monitor. All filters optional: `{ agent, kind:"dns"|"conn"|"alloc", from, to, limit }`
 * (from/to accept epoch-ms, RFC-3339, or relative like "-1h"). → an array of event records.
 */
export async function logs(opts = {}) {
  const o = opts || {};
  const args = {};
  if (o.agent) args.agent = o.agent;
  if (o.kind) args.kind = o.kind;
  if (o.from != null && o.from !== "") args.from = o.from;
  if (o.to != null && o.to !== "") args.to = o.to;
  if (o.limit != null && Number(o.limit) > 0) args.limit = Number(o.limit);
  return callControl("logs", args, o);
}

/**
 * Fully revoke an agent - IRREVERSIBLE (op:revoke; needs admin:dns). Liberal input:
 * `revoke("agent-id")`, `revoke("2a04:2a01:...")`, or `revoke({ agent, apiKey })`.
 * → `{ status, ... }`.
 */
export async function revoke(target, maybeOpts) {
  const o = typeof target === "string" ? maybeOpts || {} : target || {};
  const sel = typeof target === "string" ? target : o.agent;
  if (!sel || !String(sel).trim()) throw new WhisperError("revoke() needs an agent id or /128 address");
  const recs = await callControl("revoke", { agent: String(sel).trim() }, o);
  const rec = recs.length ? recs[0] : {};
  return { status: rec.status || rec.state || "submitted", ...rec };
}

/**
 * Allocate your own /128 identity (op:identity): `identity({ label, contact_email })`.
 * Release form: `identity({ release:true, address:"2a04:2a01:..." })`.
 * → `{ agent, address, fqdn, ptr, state }`.
 */
export async function identity(opts = {}) {
  const o = opts || {};
  const args = {};
  if (o.release) {
    if (!o.address || !String(o.address).trim()) throw new WhisperError("identity({ release:true }) needs the address to release");
    args.release = true;
    args.address = String(o.address).trim();
  } else {
    if (!o.label || !String(o.label).trim()) throw new WhisperError("identity() needs a label (the agent's name)");
    args.label = String(o.label).trim();
    if (o.contact_email) args.contact_email = o.contact_email;
  }
  const recs = await callControl("identity", args, o);
  return recs.length ? recs[0] : null;
}

/**
 * One agent's detail + live counters (op:agent). Liberal input: `agent("2a04:2a01:...")`,
 * `agent("agent-id")`, or `agent({ agent })` / `agent({ address })`. A value with a colon
 * is treated as a /128 address. → the detail record, or null if not in your account.
 */
export async function agent(sel = {}, maybeOpts) {
  const o = typeof sel === "string" ? maybeOpts || {} : sel || {};
  const args = {};
  if (typeof sel === "string") {
    if (sel.includes(":")) args.address = sel.trim();
    else args.agent = sel.trim();
  } else if (o.address) {
    args.address = String(o.address).trim();
  } else if (o.agent) {
    if (String(o.agent).includes(":")) args.address = String(o.agent).trim();
    else args.agent = String(o.agent).trim();
  }
  if (!args.agent && !args.address) throw new WhisperError("agent() needs an agent id or /128 address");
  const recs = await callControl("agent", args, o);
  return recs.length ? recs[0] : null;
}

// ── Graph (the Whisper Security graph: Cypher intelligence, two-tier) ────────────────
// The intelligence pillar, Postel two-tier with both halves honest: the 13 DIRECT READ
// verbs (identify, assess, variants, walk, explain, pslTldplusone, pslAffiliation,
// origins, history, historyWhois, asset, lookupTorRelay, dbSchema) run KEYLESS - no key
// at all, a rate-limited taste (~100/window) with real answers; a key (opts.apiKey or
// WHISPER_API_KEY) lifts the limit. Raw Cypher (graph.query), the 15 multi-step flows,
// and the submit write channel are proxied up the same way. Everything POSTs to the SAME endpoint the
// control plane uses (https://graph.whisper.online/api/query), reusing resolveKey() so
// there is one auth path, not two: a present key rides ONLY in the X-API-Key header, an
// absent one sends NO auth header at all. It does NOT go through the whisper.agents()
// control wrapper: the graph contract is different (body {query,parameters}; reply
// {columns,rows,statistics} where rows are already column-keyed objects), so it has its
// own choke point, callGraph().
//
// Source of truth for the 29 methods is the Whisper query catalog (catalog.json +
// sdk-methods.json): the GRAPH_METHODS table below is GENERATED from it by
// scripts/gen-graph.mjs (`npm run gen`), so this SDK cannot drift from the catalog. The
// 14 `direct` entries run their catalog Cypher against /api/query; the 15 `flow` entries
// EXECUTE on the workflow runner (POST gallery/run, Server-Sent Events) via callFlow().
// Every method carries its canonical docs URL as `.docs`; graph.recipes() lists the
// whole catalog (keyless, no network). graph.query() is the raw escape hatch.

function graphUrl() {
  // Defaults to the control endpoint, which already IS the graph endpoint. Override for tests
  // or a private deployment. WHISPER_GRAPH_URL wins, then the shared control URL.
  return process.env.WHISPER_GRAPH_URL || controlUrl();
}

// Normalise the /api/query reply into { columns, rows, statistics }. Per the contract rows
// are OBJECTS keyed by column name; we also accept a positional-array row (aligned to
// columns) so a liberal server shape still decodes. Never throws on shape.
function normalizeGraph(body) {
  if (!body || typeof body !== "object") return { columns: [], rows: [], statistics: null };
  const columns = Array.isArray(body.columns) ? body.columns : [];
  const rawRows = Array.isArray(body.rows) ? body.rows : [];
  const rows = rawRows.map((row) => {
    if (Array.isArray(row)) {
      const m = {};
      columns.forEach((c, i) => { if (i < row.length) m[c] = row[i]; });
      return m;
    }
    return row && typeof row === "object" ? row : { value: row };
  });
  return { columns, rows, statistics: body.statistics || null };
}

// The one place that talks to the graph. POSTs {query,parameters}, and on an HTTP>=400 or
// an RFC-7807 problem body throws a WhisperError carrying the server's helpful detail
// (plus .status/.retryAfter). Two-tier auth (Postel: liberal in what we accept): a keyless
// method (`keyless: true`) NEVER throws for a missing key - with a key it runs unlimited,
// without one the X-API-Key header is omitted entirely and the server serves the
// rate-limited keyless taste. No method is refused here; the graph decides what to answer.
// The key is only ever sent in X-API-Key: never logged, never on argv, never returned.
async function callGraph(cypher, params, opts = {}) {
  // Proxy up with whatever key there is, or none: the graph owns the keyless policy and
  // decides what to answer. The SDK adds no gate the server did not ask for.
  const key = resolveKey(opts) || "";
  const url = graphUrl();
  const timeout = opts.timeout || 60000;
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeout);
  const headers = {
    "Content-Type": "application/json",
    Accept: "application/json",
    "User-Agent": UA,
  };
  if (key) headers["X-API-Key"] = key; // present => keyed (unlimited); absent => keyless taste
  let res;
  try {
    res = await fetch(url, {
      method: "POST",
      headers,
      body: JSON.stringify({ query: cypher, parameters: params || {} }),
      signal: ctrl.signal,
    });
  } catch (err) {
    throw new WhisperError(`could not reach the Whisper graph at ${url}: ${err && err.message ? err.message : err}`);
  } finally {
    clearTimeout(t);
  }
  let body = null;
  try {
    body = await res.json();
  } catch {
    body = null;
  }
  // A fault is either an HTTP error status or a problem body (has error/detail/title but no
  // result table). A valid table always carries columns/rows, so those are never a fault.
  const hasTable = body && typeof body === "object" && (Array.isArray(body.columns) || Array.isArray(body.rows));
  const problem = body && typeof body === "object" && (body.error || (!hasTable && (body.detail || body.title || body.type)));
  if (res.status >= 400 || problem) {
    const e = (body && (body.error || body)) || {};
    const werr = new WhisperError(e.detail || e.title || e.message || e.type || `graph query returned HTTP ${res.status}`);
    werr.status = e.status || res.status;
    if (e.retry_after != null) werr.retryAfter = e.retry_after;
    throw werr;
  }
  return normalizeGraph(body);
}

// BEGIN GENERATED: graph catalog (scripts/gen-graph.mjs) - do not edit by hand
// The Whisper query catalog, one row per entry (14 direct + 15 flow), in catalog order.
// A direct row carries its catalog Cypher (input bound as a $-parameter); a flow row
// carries its gallery/run slug plus the input/param names the workflow runner accepts;
// the map-call row (submit) enumerates its fields. `keyless` marks the 13 direct read
// verbs that run with no key at all (two-tier, straight from the catalog's requiresKey);
// `summary` feeds recipes() discovery; `docs` is the canonical docs URL.
const GRAPH_DOCS_BASE = "https://www.whisper.security";
const GRAPH_FLOW_RUN_URL = "https://console.whisper.security/api/gallery/run";
const GRAPH_METHODS = [
  { name: "anycastDnsRootSovereignty", mode: "flow", keyless: false, slug: "anycast-dns-root-sovereignty", primary: "country", inputs: ["country"], params: ["instanceType"], summary: "Assess how resilient a country's core DNS is if it were cut off from the world.", docs: GRAPH_DOCS_BASE + "/docs/recipes/compliance" },
  { name: "attackPath", mode: "flow", keyless: false, slug: "attack-path", primary: "value", inputs: ["value", "other"], params: ["level"], summary: "Find the choke points an attacker would target - and how any two things connect.", docs: GRAPH_DOCS_BASE + "/docs/recipes/attack-path" },
  { name: "attackSurface", mode: "flow", keyless: false, slug: "attack-surface", primary: "domain", inputs: ["domain"], params: ["level"], summary: "Map everything about a domain that's exposed to the outside world, scored for risk.", docs: GRAPH_DOCS_BASE + "/docs/recipes/pentest-recon" },
  { name: "bgpHijackExposure", mode: "flow", keyless: false, slug: "bgp-hijack-exposure", primary: "value", inputs: ["value"], params: [], summary: "Grade a network's routing security and trace conflicts to the domains they'd expose.", docs: GRAPH_DOCS_BASE + "/docs/recipes/bgp-routing" },
  { name: "blastRadius", mode: "flow", keyless: false, slug: "blast-radius", primary: "indicator", inputs: ["indicator"], params: ["depth"], summary: "Pick one asset and see what would break if it failed - and what it depends on in turn.", docs: GRAPH_DOCS_BASE + "/docs/recipes/soc" },
  { name: "buildTakedownEvidencePackage", mode: "flow", keyless: false, slug: "build-takedown-evidence-package", primary: "domain", inputs: ["domain"], params: [], summary: "Assemble a ready-to-submit dossier for taking down a scam or phishing domain.", docs: GRAPH_DOCS_BASE + "/docs/recipes/threat-intel" },
  { name: "discoverAiAgentInfrastructure", mode: "flow", keyless: false, slug: "discover-ai-agent-infrastructure", primary: "value", inputs: ["value"], params: [], summary: "Map an organisation's externally visible AI and agent endpoints from the outside.", docs: GRAPH_DOCS_BASE + "/docs/recipes/pentest-recon" },
  { name: "indicator", mode: "flow", keyless: false, slug: "indicator", primary: "indicator", inputs: ["indicator"], params: [], summary: "Investigate one suspicious domain, IP, or network in depth and get a clear picture of the threat and everything connected to it.", docs: GRAPH_DOCS_BASE + "/docs/recipes/soc" },
  { name: "indicatorEnrichment", mode: "flow", keyless: false, slug: "indicator-enrichment", primary: "value", inputs: ["value"], params: [], summary: "Turn one domain or IP into a full context card - owner, hosting, mail, location, reputation at a glance.", docs: GRAPH_DOCS_BASE + "/docs/recipes/dns-email" },
  { name: "infrastructureMapping", mode: "flow", keyless: false, slug: "infrastructure-mapping", primary: "value", inputs: ["value"], params: ["level"], summary: "Trace one indicator to its true owner and full estate, even behind privacy screens and CDNs.", docs: GRAPH_DOCS_BASE + "/docs/recipes/compliance" },
  { name: "mapSupplyChainConcentration", mode: "flow", keyless: false, slug: "map-supply-chain-concentration", primary: "domain", inputs: ["domain"], params: [], summary: "Grade an organisation for over-reliance on single providers, regions, or facilities.", docs: GRAPH_DOCS_BASE + "/docs/recipes/compliance" },
  { name: "nameserverHijackDnsConsistency", mode: "flow", keyless: false, slug: "nameserver-hijack-dns-consistency", primary: "value", inputs: ["value"], params: [], summary: "Check a domain's name servers for the misconfigurations that enable DNS hijacking.", docs: GRAPH_DOCS_BASE + "/docs/recipes/dns-email" },
  { name: "routeHealth", mode: "flow", keyless: false, slug: "route-health", primary: "target", inputs: ["target"], params: [], summary: "Profile a network or address block into a full routing and reachability health card.", docs: GRAPH_DOCS_BASE + "/docs/recipes/bgp-routing" },
  { name: "subdomainTakeover", mode: "flow", keyless: false, slug: "subdomain-takeover", primary: "value", inputs: ["value"], params: [], summary: "Find subdomains that point at abandoned services an attacker could claim.", docs: GRAPH_DOCS_BASE + "/docs/recipes/pentest-recon" },
  { name: "typosquat", mode: "flow", keyless: false, slug: "typosquat", primary: "domain", inputs: ["domain"], params: [], summary: "Find registered look-alikes of your brand and check which ones are dangerous.", docs: GRAPH_DOCS_BASE + "/docs/recipes/brand-protection" },
  { name: "identify", mode: "direct", keyless: true, input: "v", cypher: "CALL whisper.identify([$v]) YIELD host, vendor_id, canonical_name, category, roles, host_class, band", summary: "Name the vendor and operator role behind a host or IP in one call.", docs: GRAPH_DOCS_BASE + "/docs/whisper-graph/procedures/identify" },
  { name: "assess", mode: "direct", keyless: true, input: "v", cypher: "CALL whisper.assess([$v]) YIELD host, label, band, sub_labels, coverage, evidence", summary: "Get a labelled threat posture for a host or IP - malicious, benign, or unknown.", docs: GRAPH_DOCS_BASE + "/docs/whisper-graph/procedures" },
  { name: "variants", mode: "direct", keyless: true, input: "v", cypher: "CALL whisper.variants($v) YIELD variant, method, exists, confidence", summary: "Generate look-alike domain variants of a brand and see which are registered.", docs: GRAPH_DOCS_BASE + "/docs/whisper-graph/procedures/variants" },
  { name: "walk", mode: "direct", keyless: true, input: "v", cypher: "CALL whisper.walk($v) YIELD coverage, host, nearest_known_vendors, no_atlas_match, siblings", summary: "Walk the graph to the nearest known vendors behind a host, with the channel and confidence.", docs: GRAPH_DOCS_BASE + "/docs/whisper-graph/procedures" },
  { name: "explain", mode: "direct", keyless: true, input: "v", cypher: "CALL whisper.explain($v) YIELD indicator, score, level, explanation, sources", summary: "Score an indicator against the threat feeds and explain exactly why.", docs: GRAPH_DOCS_BASE + "/docs/whisper-graph/procedures/explain" },
  { name: "pslTldplusone", mode: "direct", keyless: true, input: "v", cypher: "CALL whisper.psl.tldPlusOne($v) YIELD apex", summary: "Reduce any hostname to its registrable apex (eTLD+1) via the Public Suffix List.", docs: GRAPH_DOCS_BASE + "/docs/whisper-graph/procedures/helpers" },
  { name: "pslAffiliation", mode: "direct", keyless: true, input: "v", cypher: "CALL whisper.psl.affiliation($v) YIELD found, suffix, submitterOrg, submitterLogin, evidenceKind, confidence", summary: "Check whether a domain is a PSL private-section suffix and who submitted it.", docs: GRAPH_DOCS_BASE + "/docs/whisper-graph/procedures/helpers" },
  { name: "origins", mode: "direct", keyless: true, input: "v", cypher: "CALL whisper.origins($v) YIELD ip, confidence, methods, asn, asnName, kind", summary: "Find the real origin IPs behind a CDN-fronted domain, ranked by confidence.", docs: GRAPH_DOCS_BASE + "/docs/whisper-graph/procedures/origins" },
  { name: "history", mode: "direct", keyless: true, input: "v", cypher: "CALL whisper.history($v)", summary: "Get the full historical WHOIS timeline for a domain.", docs: GRAPH_DOCS_BASE + "/docs/whisper-graph/procedures/history" },
  { name: "historyWhois", mode: "direct", keyless: true, input: "v", cypher: "CALL whisper.history.whois($v) YIELD queryTime, createDate, updateDate, expiryDate, registrar, registrant, country, nameServers", summary: "Get the WHOIS-only historical timeline for a domain.", docs: GRAPH_DOCS_BASE + "/docs/whisper-graph/procedures/history" },
  { name: "asset", mode: "direct", keyless: true, input: "v", cypher: "CALL whisper.asSet($v) YIELD asSetName, memberAsn, sourceRir", summary: "List the member ASNs of an AS-SET macro.", docs: GRAPH_DOCS_BASE + "/docs/whisper-graph/procedures" },
  { name: "lookupTorRelay", mode: "direct", keyless: true, input: "v", cypher: "CALL whisper.lookupTorRelay($v) YIELD indicator, found, fingerprint, exitAddressCount, source, ingestedAt", summary: "Check whether an IP is a known Tor exit relay.", docs: GRAPH_DOCS_BASE + "/docs/whisper-graph/procedures/helpers" },
  { name: "dbSchema", mode: "direct", keyless: true, input: null, cypher: "CALL db.schema()", summary: "List every node and relationship type in the graph with counts and examples.", docs: GRAPH_DOCS_BASE + "/docs/whisper-graph/schema" },
  { name: "submit", mode: "direct", keyless: false, proc: "whisper.submit", fields: [["kind", "kind"], ["identifierKind", "identifier_kind"], ["value", "value"], ["observationId", "observation_id"], ["confidence", "confidence"], ["firstSeen", "first_seen"], ["provenance", "provenance"], ["query", "query"], ["results", "results"], ["comment", "comment"], ["severity", "severity"], ["v", "v"]], requires: ["kind"], summary: "Contribute an indicator observation or feedback back into the graph (requires an API key).", docs: GRAPH_DOCS_BASE + "/docs/cypher-api" },
];
// END GENERATED: graph catalog

// Coerce a liberal first arg into the string value bound as $v. Accepts a bare value or a
// { value } / { v } wrapper; empty is rejected with a clear error, never an opaque failure.
function graphValue(name, value) {
  let v = value;
  if (v && typeof v === "object" && !Array.isArray(v)) {
    if (v.value !== undefined) v = v.value;
    else if (v.v !== undefined) v = v.v;
  }
  if (v === null || v === undefined || String(v).trim() === "") {
    throw new WhisperError(`graph.${name}() needs a value (a host, IP, domain, or ASN)`);
  }
  return String(v).trim();
}

/**
 * Run raw Cypher against the Whisper Security graph. The escape hatch under every
 * typed method: `graph.query("MATCH (n) RETURN n LIMIT 1", {}, { apiKey })`. Returns the
 * full `{ columns, rows, statistics }` (rows are objects keyed by column name).
 * @see https://www.whisper.security/docs/cypher-api
 */
async function graphQuery(cypher, params, opts = {}) {
  if (!cypher || !String(cypher).trim()) throw new WhisperError("graph.query() needs a Cypher string");
  return callGraph(String(cypher), params || {}, opts);
}

/**
 * Discover the whole catalog: every graph method with `{ method, keyless, mode, summary,
 * params, docsUrl }` - baked from the Whisper query catalog at generation time, so it
 * needs no key and no network. `keyless: true` marks the direct read verbs that run with
 * no key at all; `params` are the method's input names (a flow's inputs, a direct verb's
 * $-parameter, the submit fields). Call any method by name, or check its docsUrl.
 * @see https://www.whisper.security/docs/recipes
 */
function graphRecipes() {
  return GRAPH_METHODS.map((m) => ({
    method: m.name,
    keyless: !!m.keyless,
    mode: m.mode,
    summary: m.summary,
    params: m.mode === "flow" ? m.inputs.slice() : m.fields ? m.fields.map(([, param]) => param) : m.input ? [m.input] : [],
    docsUrl: m.docs,
  }));
}

// ── Flow runner (gallery/run, Server-Sent Events) ───────────────────────────────────
// A flow entry is a multi-step read workflow orchestrated by the Whisper workflow runner:
// POST {slug, value, paramValues} to the gallery/run endpoint (X-API-Key when set) and consume
// the SSE stream. Each `step` event carries a step's bound Cypher + rows; the terminal
// `complete` event carries the aggregate context. callFlow() collects the whole stream and
// resolves to { slug, steps, complete, events } - one call, the full flow.

function flowRunUrl() {
  return process.env.WHISPER_FLOW_URL || GRAPH_FLOW_RUN_URL;
}

// Liberal-accept (RFC 761): coerce the caller's input into the runner's {inputs, params}.
// A bare value binds to the flow's primary input; a plain object routes each key by name
// (a known knob name goes to params, everything else to inputs); an explicit
// { inputs, params } wrapper passes through untouched.
function flowBody(m, input) {
  const inputs = {};
  const params = {};
  if (input === null || input === undefined) return { inputs, params };
  if (typeof input !== "object" || Array.isArray(input)) {
    const v = String(input).trim();
    if (v === "") throw new WhisperError(`graph.${m.name}() needs a value for its \`${m.primary}\` input (a host, IP, domain, ASN, or prefix)`);
    inputs[m.primary] = v;
    return { inputs, params };
  }
  if ((input.inputs && typeof input.inputs === "object") || (input.params && typeof input.params === "object")) {
    return { inputs: { ...(input.inputs || {}) }, params: { ...(input.params || {}) } };
  }
  for (const [k, v] of Object.entries(input)) {
    if (v === undefined) continue;
    if (m.params.includes(k)) params[k] = v;
    else inputs[k] = v;
  }
  return { inputs, params };
}

// Map the routed { inputs, params } onto the runner's wire contract {slug, value, paramValues}:
// `value` is the ONE primary entity (a host / IP / ASN), or `values` for a bulk list; the FIRST
// input becomes the anchor `value`, and every other input plus every tuning knob rides in
// `paramValues`. We send ONLY the keys the runner reads - an `inputs`/`params` map is silently
// ignored, so the flow would fall back to its default anchor. A nullish input is skipped so the
// flow's own default applies (Postel: sensible defaults, liberal in what we accept).
function flowWireBody(m, input) {
  const { inputs, params } = flowBody(m, input);
  const paramValues = {};
  let value;
  let values;
  let first = true;
  for (const [name, val] of Object.entries(inputs)) {
    if (val === undefined || val === null) continue;
    if (first) {
      if (Array.isArray(val)) values = val.map((x) => String(x));
      else value = String(val);
      first = false;
    } else {
      paramValues[name] = val;
    }
  }
  for (const [k, v] of Object.entries(params)) paramValues[k] = v;
  const body = { slug: m.slug };
  if (value !== undefined) body.value = value;
  if (values !== undefined) body.values = values;
  if (Object.keys(paramValues).length > 0) body.paramValues = paramValues;
  return body;
}

// Parse one SSE record ("event: x\ndata: {...}") into { event, data }; data is JSON-decoded
// when possible, else kept as the raw string. Never throws on shape.
function parseSseRecord(record) {
  let event = "message";
  const dataLines = [];
  for (const line of record.split("\n")) {
    if (line.startsWith("event:")) event = line.slice(6).trim();
    else if (line.startsWith("data:")) dataLines.push(line.slice(5).replace(/^ /, ""));
  }
  let data = dataLines.join("\n");
  try {
    data = JSON.parse(data);
  } catch {
    // not JSON - keep the raw string
  }
  return { event, data };
}

// The one place that talks to the workflow runner. Sends the key when there is one (shared
// resolveKey) and goes without when there is not, POSTs {slug, value, paramValues},
// consumes the SSE stream, and resolves to the collected
// { slug, steps, complete, events }. Flows are multi-step, so the default timeout is 5
// minutes (override with opts.timeout). On an HTTP error, an `error` event, or a stream
// that ends with no result at all, throws a WhisperError with the server's clear detail.
async function callFlow(m, input, opts = {}) {
  // Flows proxy up like every other graph verb; the runner decides on the key.
  const key = resolveKey(opts) || "";
  const body = flowWireBody(m, input);
  const url = flowRunUrl();
  const timeout = opts.timeout || 300000;
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeout);
  try {
    let res;
    try {
      const headers = {
        "Content-Type": "application/json",
        Accept: "text/event-stream",
        "User-Agent": UA,
      };
      // Present => keyed. ABSENT => keyless: an empty credential is not the same as no
      // credential, and a server handed "" refuses instead of applying keyless policy.
      if (key) headers["X-API-Key"] = key;
      res = await fetch(url, {
        method: "POST",
        headers,
        body: JSON.stringify(body),
        signal: ctrl.signal,
      });
    } catch (err) {
      throw new WhisperError(`could not reach the Whisper workflow runner at ${url}: ${err && err.message ? err.message : err}`);
    }
    if (res.status >= 400) {
      let body = null;
      try {
        body = await res.json();
      } catch {
        body = null;
      }
      const e = body && typeof body === "object" ? body : {};
      const werr = new WhisperError(
        e.message || e.detail || (typeof e.error === "string" ? e.error : null) || `the workflow runner returned HTTP ${res.status}`
      );
      werr.status = res.status;
      throw werr;
    }
    // Liberal accept: a plain-JSON reply (no stream) is decoded as the complete result.
    const ct = res.headers && typeof res.headers.get === "function" ? res.headers.get("content-type") || "" : "";
    if (ct.includes("json")) {
      let body = null;
      try {
        body = await res.json();
      } catch {
        body = null;
      }
      return { slug: m.slug, steps: [], complete: body && typeof body === "object" ? body : null, events: [] };
    }
    // The SSE stream: split records on blank lines (CRLF-safe), decode each.
    const events = [];
    const decoder = new TextDecoder("utf-8");
    let buf = "";
    const drain = () => {
      buf = buf.replace(/\r\n/g, "\n");
      let i;
      while ((i = buf.indexOf("\n\n")) !== -1) {
        const rec = buf.slice(0, i);
        buf = buf.slice(i + 2);
        if (rec.trim() !== "") events.push(parseSseRecord(rec));
      }
    };
    for await (const chunk of res.body) {
      buf += decoder.decode(chunk, { stream: true });
      drain();
    }
    buf += decoder.decode();
    drain();
    if (buf.trim() !== "") events.push(parseSseRecord(buf));
    const steps = events.filter((ev) => ev.event === "step").map((ev) => ev.data);
    const completeEv = events.findLast((ev) => ev.event === "complete");
    const complete = completeEv && completeEv.data && typeof completeEv.data === "object" ? completeEv.data : null;
    const errEv = events.find((ev) => ev.event === "error");
    if (errEv && !complete) {
      const d = errEv.data && typeof errEv.data === "object" ? errEv.data : { detail: String(errEv.data || "") };
      const werr = new WhisperError(d.message || d.detail || (typeof d.error === "string" ? d.error : null) || `graph.${m.name} failed on the workflow runner`);
      werr.events = events;
      throw werr;
    }
    if (!complete && steps.length === 0) {
      const werr = new WhisperError(`graph.${m.name}: the flow stream ended without a step or complete event`);
      werr.events = events;
      throw werr;
    }
    return { slug: m.slug, steps, complete, events };
  } catch (err) {
    if (err instanceof WhisperError) throw err;
    if ((err && err.name === "AbortError") || ctrl.signal.aborted) {
      throw new WhisperError(`graph.${m.name} timed out after ${timeout}ms (flows are multi-step; raise { timeout } if you need longer)`);
    }
    throw new WhisperError(`graph.${m.name} failed while streaming from the workflow runner: ${err && err.message ? err.message : err}`);
  } finally {
    clearTimeout(t);
  }
}

// The map-call write (whisper.submit): each payload field becomes one entry of a Cypher
// map with its value bound as its own $-parameter (injection-safe), keys in SORTED order
// so the query is byte-stable. Field names are accepted in both catalog spellings
// (camelCase id or snake_case paramName) and normalised to the wire form; any extra key
// must be a plain identifier, and the server validates the full set per kind.
function makeMapCall(m) {
  const canon = new Map();
  for (const [id, param] of m.fields) {
    canon.set(id, param);
    canon.set(param, param);
  }
  return async (payload, opts = {}) => {
    const p = payload && typeof payload === "object" && !Array.isArray(payload) ? payload : {};
    const bound = {};
    for (const [k, v] of Object.entries(p)) {
      if (v === undefined) continue;
      const name = canon.get(k) || k;
      if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) {
        throw new WhisperError(`graph.${m.name}() field ${JSON.stringify(k)} is not a valid field name (letters, digits, _)`);
      }
      bound[name] = v;
    }
    for (const req of m.requires) {
      if (bound[req] === null || bound[req] === undefined || String(bound[req]).trim() === "") {
        throw new WhisperError(`graph.${m.name}() needs a { ${req} } of 'indicator' or 'feedback' (plus its fields)`);
      }
    }
    const keys = Object.keys(bound).sort();
    const cypher = `CALL ${m.proc}({` + keys.map((k) => `${k}:$${k}`).join(", ") + "})";
    return callGraph(cypher, bound, opts);
  };
}

// Build the namespace from the generated catalog table: query + recipes + one method per
// entry. Direct methods run their catalog Cypher (the 13 keyless reads never require a
// key); the map-call write builds its parameter map; flow methods execute on the workflow
// runner. Every method carries its canonical docs URL as `.docs` (docsBase + docPath).
const graph = { query: graphQuery, recipes: graphRecipes };
graph.query.docs = GRAPH_DOCS_BASE + "/docs/cypher-api";
graph.recipes.docs = GRAPH_DOCS_BASE + "/docs/recipes";

for (const m of GRAPH_METHODS) {
  if (m.mode === "flow") {
    graph[m.name] = async (input, opts = {}) => callFlow(m, input, opts);
  } else if (m.fields) {
    graph[m.name] = makeMapCall(m);
  } else if (m.input) {
    graph[m.name] = async (value, opts = {}) => callGraph(m.cypher, { [m.input]: graphValue(m.name, value) }, opts);
  } else {
    graph[m.name] = async (opts = {}) => callGraph(m.cypher, {}, opts);
  }
  graph[m.name].docs = m.docs;
}

export { graph };
