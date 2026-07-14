// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
// whisper-id - a routable IPv6 identity and safe egress for any Node agent.
// A thin, dependency-free wrapper over the `whisper` CLI (https://whisper.online): the CLI
// holds the auth, control plane, and egress tunnel; this gives you register/egress/verify/ip.
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
          "`curl get.whisper.online | sh` (see https://whisper.online)."
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
  return process.env.WHISPER_CONTROL_URL || "https://graph.whisper.security/api/query";
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
        "(verify/verifyDetails/rdap are keyless and need no key.)"
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

// ── Graph (keyed Cypher over the Whisper Security graph) ─────────────────────────────
// The intelligence half of the keyed surface. Postel two-tier holds cleanly: the keyless
// identity calls above (verify/verifyDetails/rdap) run with NO key and touch NO Cypher;
// this whole `graph` namespace is KEYED (Kaveh's absolute rule: if it is Cypher, it needs
// a key). It POSTs raw Cypher to the SAME endpoint the control plane uses
// (https://graph.whisper.security/api/query, X-API-Key), reusing resolveKey() so there is
// one auth path, not two. It does NOT go through the whisper.agents() control wrapper: the
// graph contract is different (body {query,parameters}; reply {columns,rows,statistics}
// where rows are already column-keyed objects), so it has its own choke point, callGraph().
//
// Source of truth for the 29 methods is the Whisper query catalog (catalog.json +
// sdk-methods.json); the tables below are copied from it (keyed by exec.mode). A test
// asserts the count so the two cannot silently drift. 14 `direct` entries run their catalog
// Cypher against /api/query; 15 `flow` entries run via the workflow runner (run_workflow),
// which is NOT a single /api/query Cypher, so they are shipped as clearly-noted stubs and
// are not wired to an engine here. graph.query() is the raw escape hatch.

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

// The one place that talks to the graph. Requires a key (via the shared resolveKey), POSTs
// {query,parameters}, and on an HTTP>=400 or an RFC-7807 problem body throws a WhisperError
// carrying the server's helpful detail (plus .status/.retryAfter). The key is only ever sent
// in X-API-Key: never logged, never on argv, never returned.
async function callGraph(cypher, params, opts = {}, methodName = "query") {
  const key = resolveKey(opts);
  if (!key) {
    throw new WhisperError(
      `\`graph.${methodName}\` needs a Whisper API key: pass { apiKey } or set WHISPER_API_KEY. ` +
        "(verify/verifyDetails/rdap are keyless and need no key; graph queries are Cypher, so they do.)"
    );
  }
  const url = graphUrl();
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

// The 14 `direct` catalog entries: id (camelCased) -> its catalog Cypher. Every one binds a
// single input as $v (paramName `v` in the catalog), except dbSchema (no input) and submit
// (a write map, handled below). Copied verbatim from whisper-catalog/catalog.json.
const GRAPH_DIRECT = {
  identify: "CALL whisper.identify([$v]) YIELD host, vendor_id, canonical_name, category, roles, host_class, band",
  assess: "CALL whisper.assess([$v]) YIELD host, label, band, sub_labels, coverage, evidence",
  variants: "CALL whisper.variants($v) YIELD variant, method, exists, confidence",
  walk: "CALL whisper.walk($v) YIELD coverage, host, nearest_known_vendors, no_atlas_match, siblings",
  explain: "CALL whisper.explain($v) YIELD indicator, score, level, explanation, sources",
  pslTldplusone: "CALL whisper.psl.tldPlusOne($v) YIELD apex",
  pslAffiliation: "CALL whisper.psl.affiliation($v) YIELD found, suffix, submitterOrg, submitterLogin, evidenceKind, confidence",
  origins: "CALL whisper.origins($v) YIELD ip, confidence, methods, asn, asnName, kind",
  history: "CALL whisper.history($v)",
  historyWhois: "CALL whisper.history.whois($v) YIELD queryTime, createDate, updateDate, expiryDate, registrar, registrant, country, nameServers",
  asset: "CALL whisper.asSet($v) YIELD asSetName, memberAsn, sourceRir",
  lookupTorRelay: "CALL whisper.lookupTorRelay($v) YIELD indicator, found, fingerprint, exitAddressCount, source, ingestedAt",
};

// The 15 `flow` catalog entries: id (camelCased) -> its runVia slug. These are multi-step
// read workflows run by the console/agent workflow runner, NOT a single /api/query Cypher,
// so they are not wired to an engine in this SDK. Copied verbatim from the catalog.
const GRAPH_FLOW = {
  anycastDnsRootSovereignty: "run_workflow (anycast-dns-root-sovereignty)",
  attackPath: "run_workflow (attack-path)",
  attackSurface: "run_workflow (attack-surface)",
  bgpHijackExposure: "run_workflow (bgp-hijack-exposure)",
  blastRadius: "run_workflow (blast-radius)",
  buildTakedownEvidencePackage: "run_workflow (build-takedown-evidence-package)",
  discoverAiAgentInfrastructure: "run_workflow (discover-ai-agent-infrastructure)",
  indicator: "run_workflow (indicator)",
  indicatorEnrichment: "run_workflow (indicator-enrichment)",
  infrastructureMapping: "run_workflow (infrastructure-mapping)",
  mapSupplyChainConcentration: "run_workflow (map-supply-chain-concentration)",
  nameserverHijackDnsConsistency: "run_workflow (nameserver-hijack-dns-consistency)",
  routeHealth: "run_workflow (route-health)",
  subdomainTakeover: "run_workflow (subdomain-takeover)",
  typosquat: "run_workflow (typosquat)",
};

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
 * Run raw Cypher against the Whisper Security graph (keyed). The escape hatch under every
 * typed method: `graph.query("MATCH (n) RETURN n LIMIT 1", {}, { apiKey })`. Returns the
 * full `{ columns, rows, statistics }` (rows are objects keyed by column name).
 */
async function graphQuery(cypher, params, opts = {}) {
  if (!cypher || !String(cypher).trim()) throw new WhisperError("graph.query() needs a Cypher string");
  return callGraph(String(cypher), params || {}, opts, "query");
}

// Build the namespace: query + a typed method per catalog entry. Direct methods run their
// Cypher; flow methods throw a clear, honest "runs via the workflow runner, not wired here"
// error (never a silent no-op) and carry .runVia for programmatic inspection.
const graph = { query: graphQuery };

for (const [name, cypher] of Object.entries(GRAPH_DIRECT)) {
  graph[name] = async (value, opts = {}) => callGraph(cypher, { v: graphValue(name, value) }, opts, name);
}

/** List every node and relationship type in the graph with counts and examples (keyed). No input. */
graph.dbSchema = async (opts = {}) => callGraph("CALL db.schema()", {}, opts, "dbSchema");

/**
 * Contribute an indicator observation or feedback back into the graph (keyed WRITE). Pass
 * `{ kind: "indicator" | "feedback", ...fields }`. The payload is bound as a single Cypher
 * parameter (injection-safe). The server enforces its own write scopes and rejects anonymous
 * callers, so a scope/quota fault surfaces as the server's WhisperError detail.
 */
graph.submit = async (payload, opts = {}) => {
  const p = payload && typeof payload === "object" && !Array.isArray(payload) ? payload : {};
  if (!p.kind || String(p.kind).trim() === "") {
    throw new WhisperError("graph.submit() needs a { kind } of 'indicator' or 'feedback' (plus its fields)");
  }
  return callGraph("CALL whisper.submit($submission)", { submission: p }, opts, "submit");
};

for (const [name, runVia] of Object.entries(GRAPH_FLOW)) {
  graph[name] = () => {
    const err = new WhisperError(
      `graph.${name}() is a multi-step read workflow: it runs via the Whisper workflow runner ` +
        `(${runVia}), not a single /api/query Cypher, and is not wired into this SDK yet. Use ` +
        "graph.query() for a raw Cypher call, or run the workflow via the console/agent runner."
    );
    err.runVia = runVia;
    return Promise.reject(err);
  };
}

export { graph };
