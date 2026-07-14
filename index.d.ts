// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
export declare class WhisperError extends Error {}

export interface Agent {
  /** The routable IPv6 /128 - both the identity and the auth. */
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

// ── Control plane (pure HTTP, keyed - no CLI) ───────────────────────────────────────
// The governance half of the two-tier surface: pure `fetch` to the control endpoint, so
// it runs anywhere (serverless, edge, a plain server). The key is read from `opts.apiKey`
// or `WHISPER_API_KEY` and sent only in the `X-API-Key` header. On failure these throw a
// `WhisperError` carrying the server's `detail` (and `.status` / `.retryAfter`).

/** Common options for every keyed control call. */
export interface ControlOptions {
  /** The Whisper owner key (`whisper_live_...`). Falls back to `process.env.WHISPER_API_KEY`. */
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
/** Fully revoke an agent - IRREVERSIBLE (admin:dns). → `{ status, ... }`. */
export function revoke(agent: string, opts?: ControlOptions): Promise<{ status: string; [k: string]: unknown }>;
export function revoke(opts: RevokeOptions): Promise<{ status: string; [k: string]: unknown }>;
/** Allocate your own /128 (or release with `{release:true,address}`). → `{agent,address,fqdn,ptr,state}`. */
export function identity(opts?: IdentityOptions): Promise<AgentItem | null>;
/** One agent's detail + live counters. Accepts an id, a /128, or `{agent}`/`{address}`. */
export function agent(sel: string, opts?: ControlOptions): Promise<AgentItem | null>;
export function agent(opts?: AgentSelectOptions): Promise<AgentItem | null>;

// ── Graph (keyed Cypher over the Whisper Security graph) ─────────────────────────────
// The intelligence half of the keyed surface. Postel two-tier: the keyless identity calls
// above (verify/verifyDetails/rdap) run with no key and no Cypher; this whole `graph`
// namespace is KEYED (Kaveh's rule: if it is Cypher, it needs a key). It POSTs raw Cypher to
// the same endpoint the control plane uses, with the key only in `X-API-Key`. `direct`
// methods run their Cypher and resolve to a `GraphResult`; the 15 `flow` methods are
// workflow-runner reads not wired here, so calling one rejects with a clear `WhisperError`.

/** Per-call options for the keyed graph namespace (same shape as the control plane). */
export interface GraphOptions extends ControlOptions {}

/** Result of a keyed graph query. `rows` are objects keyed by column name. */
export interface GraphResult {
  columns: string[];
  rows: Record<string, unknown>[];
  statistics?: { rowCount?: number; executionTimeMs?: number; [k: string]: unknown } | null;
}

/** A `graph.submit` payload: an indicator observation or a piece of feedback. */
export interface GraphSubmission {
  kind: "indicator" | "feedback" | string;
  [k: string]: unknown;
}

/**
 * The keyed graph namespace: typed Cypher methods over the Whisper Security graph, plus a
 * raw `query` escape hatch. Every method needs a key (`{ apiKey }` or `WHISPER_API_KEY`).
 */
export interface GraphNamespace {
  /** Raw Cypher escape hatch. Returns the full `{columns,rows,statistics}`. */
  query(cypher: string, params?: Record<string, unknown>, opts?: GraphOptions): Promise<GraphResult>;

  /** Name the vendor and operator role behind a host or IP in one call. */
  identify(value: string, opts?: GraphOptions): Promise<GraphResult>;
  /** Labelled threat posture for a host or IP: malicious, benign, or unknown. */
  assess(value: string, opts?: GraphOptions): Promise<GraphResult>;
  /** Generate look-alike domain variants of a brand and see which are registered. */
  variants(value: string, opts?: GraphOptions): Promise<GraphResult>;
  /** Walk the graph to the nearest known vendors behind a host, with channel and confidence. */
  walk(value: string, opts?: GraphOptions): Promise<GraphResult>;
  /** Score an indicator against the threat feeds and explain exactly why. */
  explain(value: string, opts?: GraphOptions): Promise<GraphResult>;
  /** Reduce any hostname to its registrable apex (eTLD+1) via the Public Suffix List. */
  pslTldplusone(value: string, opts?: GraphOptions): Promise<GraphResult>;
  /** Check whether a domain is a PSL private-section suffix and who submitted it. */
  pslAffiliation(value: string, opts?: GraphOptions): Promise<GraphResult>;
  /** Find the real origin IPs behind a CDN-fronted domain, ranked by confidence. */
  origins(value: string, opts?: GraphOptions): Promise<GraphResult>;
  /** Full historical WHOIS timeline for a domain. */
  history(value: string, opts?: GraphOptions): Promise<GraphResult>;
  /** WHOIS-only historical timeline for a domain. */
  historyWhois(value: string, opts?: GraphOptions): Promise<GraphResult>;
  /** List the member ASNs of an AS-SET macro. */
  asset(value: string, opts?: GraphOptions): Promise<GraphResult>;
  /** Check whether an IP is a known Tor exit relay. */
  lookupTorRelay(value: string, opts?: GraphOptions): Promise<GraphResult>;
  /** List every node and relationship type in the graph with counts and examples. No input. */
  dbSchema(opts?: GraphOptions): Promise<GraphResult>;
  /** Contribute an indicator observation or feedback back into the graph (keyed WRITE). */
  submit(payload: GraphSubmission, opts?: GraphOptions): Promise<GraphResult>;

  // The 15 `flow` workflow-runner methods. Not wired into this SDK: each rejects with a clear
  // WhisperError (carrying `.runVia`). Run them via the console/agent workflow runner.
  /** Workflow (run_workflow): assess a country's DNS-root sovereignty. Not wired here. */
  anycastDnsRootSovereignty(opts?: GraphOptions): Promise<never>;
  /** Workflow (run_workflow): find the choke points an attacker would target. Not wired here. */
  attackPath(opts?: GraphOptions): Promise<never>;
  /** Workflow (run_workflow): map a domain's externally exposed attack surface. Not wired here. */
  attackSurface(opts?: GraphOptions): Promise<never>;
  /** Workflow (run_workflow): grade a network's routing security. Not wired here. */
  bgpHijackExposure(opts?: GraphOptions): Promise<never>;
  /** Workflow (run_workflow): what breaks if one asset fails, and its dependencies. Not wired here. */
  blastRadius(opts?: GraphOptions): Promise<never>;
  /** Workflow (run_workflow): assemble a takedown evidence dossier. Not wired here. */
  buildTakedownEvidencePackage(opts?: GraphOptions): Promise<never>;
  /** Workflow (run_workflow): map an org's externally visible AI/agent endpoints. Not wired here. */
  discoverAiAgentInfrastructure(opts?: GraphOptions): Promise<never>;
  /** Workflow (run_workflow): investigate one indicator in depth. Not wired here. */
  indicator(opts?: GraphOptions): Promise<never>;
  /** Workflow (run_workflow): turn one domain/IP into a full context card. Not wired here. */
  indicatorEnrichment(opts?: GraphOptions): Promise<never>;
  /** Workflow (run_workflow): trace an indicator to its true owner and estate. Not wired here. */
  infrastructureMapping(opts?: GraphOptions): Promise<never>;
  /** Workflow (run_workflow): grade an org for supply-chain concentration. Not wired here. */
  mapSupplyChainConcentration(opts?: GraphOptions): Promise<never>;
  /** Workflow (run_workflow): check name servers for DNS-hijack misconfigurations. Not wired here. */
  nameserverHijackDnsConsistency(opts?: GraphOptions): Promise<never>;
  /** Workflow (run_workflow): profile a network/block into a routing health card. Not wired here. */
  routeHealth(opts?: GraphOptions): Promise<never>;
  /** Workflow (run_workflow): find subdomains that point at claimable services. Not wired here. */
  subdomainTakeover(opts?: GraphOptions): Promise<never>;
  /** Workflow (run_workflow): find registered look-alikes of your brand. Not wired here. */
  typosquat(opts?: GraphOptions): Promise<never>;
}

/** The keyed graph namespace. `import { graph } from "whisper-id"`. */
export const graph: GraphNamespace;
