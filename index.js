// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
// whisper-id — a routable IPv6 identity and safe egress for any Node agent.
// A thin, dependency-free wrapper over the `whisper` CLI (https://whisper.online): the CLI
// holds the auth, control plane, and egress tunnel; this gives you register/egress/verify/ip.
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const pexec = promisify(execFile);

const ADDR_RE = /2a04:2a01:[0-9a-fA-F:]{2,}/; // the public Whisper agent prefix (AS219419)
const HOSTPORT_RE = /127\.0\.0\.1:(\d{2,5})/;
const PROXY_VARS = ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"];

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

/** Create a named agent identity — a routable Whisper IPv6 /128. */
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
// CLI — these work in any runtime that can fetch() (serverless, edge, browser). Override via env.
function rdapBase() {
  return (process.env.WHISPER_RDAP_URL || "https://rdap.whisper.online").replace(/\/+$/, "");
}

async function httpGetJson(url, { timeout = 60000 } = {}) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeout);
  let res;
  try {
    res = await fetch(url, { headers: { Accept: "application/rdap+json, application/json, */*", "User-Agent": "whisper-id-node/0.2.0" }, signal: ctrl.signal });
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
 * Return true iff `address` is a real Whisper agent. **Keyless and CLI-free** — one HTTPS GET to
 * the public /verify-identity endpoint (server-side DANE+DNSSEC+reverse-DNS+JWS chain). Works in
 * any runtime. 200 ⇒ agent, 404 ⇒ not. Throws only if the endpoint is unreachable.
 */
export async function verify(address, { timeout = 60000 } = {}) {
  return (await verifyDetails(address, { timeout })) !== null;
}

/** Full verify verdict for a real agent (is_whisper_agent, fqdn, operator, tenant, dane_ok, jws_ok, …), else null. Keyless, CLI-free. */
export async function verifyDetails(address, { timeout = 60000 } = {}) {
  if (!address || !address.trim()) throw new WhisperError("verify() needs an address");
  const url = `${rdapBase()}/verify-identity?ip=${encodeURIComponent(address.trim())}`;
  const { status, body } = await httpGetJson(url, { timeout });
  if (status !== 200 || !body || !body.is_whisper_agent) return null;
  return body;
}

/** Public RDAP record for a Whisper /128 (handle, name, status, entities, …), or null. Keyless, CLI-free. */
export async function rdap(address, { timeout = 60000 } = {}) {
  if (!address || !address.trim()) throw new WhisperError("rdap() needs an address");
  const url = `${rdapBase()}/ip/${encodeURI(address.trim())}`; // path segment — keep the literal colons
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
