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

/** Return true iff `address` is a real Whisper agent (DANE+DNSSEC+reverse-DNS+JWS). Keyless. */
export async function verify(address, { timeout = 60000 } = {}) {
  if (!address || !address.trim()) throw new WhisperError("verify() needs an address");
  const { code } = await run(["verify", address], { timeout, check: false });
  return code === 0;
}

/** Return the current egress IP, proving it is your Whisper /128. */
export async function ip({ timeout = 60000 } = {}) {
  const env = await runJson(["ip"], { timeout });
  return getKey(env, "ip", "agent") || firstAddr(env) || "";
}
