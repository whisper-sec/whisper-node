// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
export declare class WhisperError extends Error {}

export interface Agent {
  /** The routable IPv6 /128 — both the identity and the auth. */
  address: string;
  id: string | null;
  name: string;
}

export interface Egress {
  port: number;
  address: string | null;
  proxyUrl: string;
  socksUrl: string;
  proxies: { http: string; https: string };
  /** Restore the proxy environment variables to their prior values. */
  close(): void;
}

export interface RegisterOptions { newKey?: boolean; timeout?: number; }
export interface EgressOptions { agent?: string; tier?: string; setEnv?: boolean; timeout?: number; }

export function register(name: string, opts?: RegisterOptions): Promise<Agent>;
export function egress(opts?: EgressOptions): Promise<Egress>;
export function withEgress<T>(fn: (e: Egress) => Promise<T> | T): Promise<T>;
export function withEgress<T>(opts: EgressOptions, fn: (e: Egress) => Promise<T> | T): Promise<T>;
/** Full server-side verify verdict (keyless). */
export interface VerifyVerdict {
  is_whisper_agent: boolean;
  fqdn?: string;
  operator?: string;
  tenant?: string;
  dane_ok?: boolean;
  jws_ok?: boolean;
  verified_at?: number;
  evidence?: unknown;
  [k: string]: unknown;
}

/** Keyless, CLI-free: is `address` a real Whisper agent? (server-side DANE+DNSSEC+reverse-DNS+JWS) */
export function verify(address: string, opts?: { timeout?: number }): Promise<boolean>;
/** Keyless, CLI-free: the full verify verdict, or null if not an agent. */
export function verifyDetails(address: string, opts?: { timeout?: number }): Promise<VerifyVerdict | null>;
/** Keyless, CLI-free: the public RDAP record for a /128, or null. */
export function rdap(address: string, opts?: { timeout?: number }): Promise<Record<string, unknown> | null>;
/** Keyless, CLI-free: the caller's current egress IP (what this process leaves from). */
export function egressIp(opts?: { timeout?: number }): Promise<string>;
/** Your current egress IP via the CLI (proves your /128). */
export function ip(opts?: { timeout?: number }): Promise<string>;
export function firstAddr(obj: unknown): string | null;

// ── Control plane (pure HTTP, keyed — no CLI) ───────────────────────────────────────
// The governance half of the two-tier surface: pure `fetch` to the control endpoint, so
// it runs anywhere (serverless, edge, a plain server). The key is read from `opts.apiKey`
// or `WHISPER_API_KEY` and sent only in the `X-API-Key` header. On failure these throw a
// `WhisperError` carrying the server's `detail` (and `.status` / `.retryAfter`).

/** Common options for every keyed control call. */
export interface ControlOptions {
  /** The Whisper owner key (`whisper_live_…`). Falls back to `process.env.WHISPER_API_KEY`. */
  apiKey?: string;
  /** Per-call timeout in ms (default 60000). */
  timeout?: number;
}

/** One agent as returned by `list` / `agent` (fields present depend on the op). */
export interface AgentItem {
  label?: string;
  fqdn?: string;
  address?: string;
  agent?: string;
  created?: string | number;
  state?: string;
  [k: string]: unknown;
}

/** A `{ key, value }` row of the per-tenant DNS policy. */
export interface PolicyEntry {
  key: string;
  value: unknown;
  [k: string]: unknown;
}

/** One activity event from `logs` (columns depend on `kind`). */
export interface LogEvent {
  ts?: string | number;
  kind?: string;
  qname?: string;
  qtype?: string;
  rcode?: string;
  decision?: string;
  source?: string;
  answer?: string;
  agent?: string;
  peer?: string;
  [k: string]: unknown;
}

export interface ListOptions extends ControlOptions {
  /** What to list: "agents" (default) | "identities" | "records". */
  kind?: "agents" | "identities" | "records" | string;
}
export interface PolicyOptions extends ControlOptions {
  /** Default action when nothing matches: "allow" | "deny". Omit all fields to READ. */
  default?: "allow" | "deny" | string;
  /** Names to allow. */
  allow?: string[];
  /** Names to block. */
  block?: string[];
}
export interface LogsOptions extends ControlOptions {
  agent?: string;
  kind?: "dns" | "conn" | "alloc" | string;
  from?: string | number;
  to?: string | number;
  limit?: number;
}
export interface RevokeOptions extends ControlOptions {
  agent?: string;
}
export interface IdentityOptions extends ControlOptions {
  /** The agent's human name (required to allocate). */
  label?: string;
  /** Opt-in public contact email (surfaced in RDAP). */
  contact_email?: string;
  /** Release form: set true and pass `address` to release an existing /128. */
  release?: boolean;
  /** The /128 to release (with `release:true`). */
  address?: string;
}
export interface AgentSelectOptions extends ControlOptions {
  agent?: string;
  address?: string;
}

/** List your fleet (keyed). → items (`{label, fqdn, address, agent, created, state}`). */
export function list(kind: string, opts?: ControlOptions): Promise<AgentItem[]>;
export function list(opts?: ListOptions): Promise<AgentItem[]>;
/** Read (no policy fields) or set your per-tenant DNS resolver policy. → `{key,value}` rows. */
export function policy(opts?: PolicyOptions): Promise<PolicyEntry[]>;
/** Query recent DNS/conn/alloc activity from warm storage. → event records. */
export function logs(opts?: LogsOptions): Promise<LogEvent[]>;
/** Fully revoke an agent — IRREVERSIBLE (admin:dns). → `{ status, … }`. */
export function revoke(agent: string, opts?: ControlOptions): Promise<{ status: string; [k: string]: unknown }>;
export function revoke(opts: RevokeOptions): Promise<{ status: string; [k: string]: unknown }>;
/** Allocate your own /128 (or release with `{release:true,address}`). → `{agent,address,fqdn,ptr,state}`. */
export function identity(opts?: IdentityOptions): Promise<AgentItem | null>;
/** One agent's detail + live counters. Accepts an id, a /128, or `{agent}`/`{address}`. */
export function agent(sel: string, opts?: ControlOptions): Promise<AgentItem | null>;
export function agent(opts?: AgentSelectOptions): Promise<AgentItem | null>;
