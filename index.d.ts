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

// ── Graph (keyed: Cypher + flows over the Whisper Security graph) ────────────────────
// The intelligence half of the keyed surface. Postel two-tier: the keyless identity calls
// above (verify/verifyDetails/rdap) run with no key and no Cypher; this whole `graph`
// namespace is KEYED (Kaveh's rule: if it is Cypher, it needs a key). The 14 `direct`
// methods POST their catalog Cypher to /api/query; the 15 `flow` methods execute on the
// workflow runner (POST gallery/run, Server-Sent Events) and resolve to the collected
// stream. The key rides only in `X-API-Key`. The method surface below is GENERATED from
// the Whisper query catalog by scripts/gen-graph.mjs; every method's docs live at the
// `@see` URL and are also on the function itself as `.docs`.

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
  identifier_kind?: string;
  identifierKind?: string;
  value?: string;
  observation_id?: string;
  observationId?: string;
  confidence?: number;
  first_seen?: string;
  firstSeen?: string;
  provenance?: string;
  query?: string;
  results?: unknown;
  comment?: string;
  severity?: string;
  v?: number;
  [k: string]: unknown;
}

/**
 * Input for a flow method: a bare value for the flow's primary input, a plain object of
 * named inputs (a known knob name routes to params), or an explicit `{ inputs, params }`.
 */
export type GraphFlowInput =
  | string
  | number
  | Record<string, unknown>
  | { inputs?: Record<string, unknown>; params?: Record<string, unknown> };

/** One Server-Sent Event from a flow run; `data` is JSON-decoded when possible. */
export interface GraphFlowEvent {
  event: string;
  data: unknown;
}

/**
 * Result of a flow run: every `step` event's payload (each carries the step's bound
 * Cypher, columns, and rows), the terminal `complete` payload (the aggregate context;
 * `null` if the stream ended early), and the full raw event list.
 */
export interface GraphFlowResult {
  slug: string;
  steps: Record<string, unknown>[];
  complete: Record<string, unknown> | null;
  events: GraphFlowEvent[];
}

/**
 * The keyed graph namespace: one typed method per catalog entry (14 direct Cypher reads +
 * 15 workflow-runner flows), plus a raw `query` escape hatch. Every method needs a key
 * (`{ apiKey }` or `WHISPER_API_KEY`) and carries its canonical docs URL as `.docs`.
 */
export interface GraphNamespace {
  /**
   * Raw Cypher escape hatch: run arbitrary Cypher with `params` bound server-side as
   * $-parameters. Returns the full `{columns,rows,statistics}`.
   * @see https://www.whisper.security/docs/cypher-api
   */
  query(cypher: string, params?: Record<string, unknown>, opts?: GraphOptions): Promise<GraphResult>;

  // BEGIN GENERATED: graph catalog (scripts/gen-graph.mjs) - do not edit by hand
  /**
   * Assess how resilient a country's core DNS is if it were cut off from the world.
   *
   * Could a country still resolve names if it were isolated? Counts how many of the 13 root
   * letters have in-country DNS_ROOT_INSTANCE anycast nodes, the Global-vs-Local split, the BGP
   * origin ASNs hosting them, and a resilience grade.
   *
   * KEYED flow: streams Server-Sent Events from the workflow runner (slug "anycast-dns-root-sovereignty")
   * and resolves to the collected { slug, steps, complete, events }.
   * Inputs: country. Params: instanceType.
   * @see https://www.whisper.security/docs/recipes/compliance
   */
  anycastDnsRootSovereignty(input?: GraphFlowInput, opts?: GraphOptions): Promise<GraphFlowResult>;

  /**
   * Find the choke points an attacker would target - and how any two things connect.
   *
   * From a starting foothold, finds shared dependencies whose compromise reaches furthest; for
   * any two indicators, traces how they are actually connected.
   *
   * KEYED flow: streams Server-Sent Events from the workflow runner (slug "attack-path")
   * and resolves to the collected { slug, steps, complete, events }.
   * Inputs: value, other. Params: level.
   * @see https://www.whisper.security/docs/recipes/attack-path
   */
  attackPath(input?: GraphFlowInput, opts?: GraphOptions): Promise<GraphFlowResult>;

  /**
   * Map everything about a domain that's exposed to the outside world, scored for risk.
   *
   * Maps the full external footprint - subdomains, name/mail servers, registrant, third-party
   * services, connected web - and scores the exposure.
   *
   * KEYED flow: streams Server-Sent Events from the workflow runner (slug "attack-surface")
   * and resolves to the collected { slug, steps, complete, events }.
   * Inputs: domain. Params: level.
   * @see https://www.whisper.security/docs/recipes/pentest-recon
   */
  attackSurface(input?: GraphFlowInput, opts?: GraphOptions): Promise<GraphFlowResult>;

  /**
   * Grade a network's routing security and trace conflicts to the domains they'd expose.
   *
   * Grades a network on the conflicts/gaps that make route hijacking possible, then traces any
   * conflict to the specific domains and organisations exposed on the affected blocks.
   *
   * KEYED flow: streams Server-Sent Events from the workflow runner (slug "bgp-hijack-exposure")
   * and resolves to the collected { slug, steps, complete, events }.
   * Inputs: value.
   * @see https://www.whisper.security/docs/recipes/bgp-routing
   */
  bgpHijackExposure(input?: GraphFlowInput, opts?: GraphOptions): Promise<GraphFlowResult>;

  /**
   * Pick one asset and see what would break if it failed - and what it depends on in turn.
   *
   * Maps dependencies in both directions: everything that breaks if the asset fails (SPOFs) and
   * everything it relies on (its own DNS/mail/hosting/network supply chain).
   *
   * KEYED flow: streams Server-Sent Events from the workflow runner (slug "blast-radius")
   * and resolves to the collected { slug, steps, complete, events }.
   * Inputs: indicator. Params: depth.
   * @see https://www.whisper.security/docs/recipes/soc
   */
  blastRadius(input?: GraphFlowInput, opts?: GraphOptions): Promise<GraphFlowResult>;

  /**
   * Assemble a ready-to-submit dossier for taking down a scam or phishing domain.
   *
   * One-pass takedown package: reputation verdict, owner (WHOIS), abuse-list listings, and
   * surrounding infrastructure, laid out ready to hand to a registrar/host.
   *
   * KEYED flow: streams Server-Sent Events from the workflow runner (slug "build-takedown-evidence-package")
   * and resolves to the collected { slug, steps, complete, events }.
   * Inputs: domain.
   * @see https://www.whisper.security/docs/recipes/threat-intel
   */
  buildTakedownEvidencePackage(input?: GraphFlowInput, opts?: GraphOptions): Promise<GraphFlowResult>;

  /**
   * Map an organisation's externally visible AI and agent endpoints from the outside.
   *
   * Maps externally visible AI/agent hosts (API, model, agent) from the outside via heuristic
   * hostname patterns (api./mcp./ai./vector./llm./agent./chat./copilot.). Best-effort leads.
   *
   * KEYED flow: streams Server-Sent Events from the workflow runner (slug "discover-ai-agent-infrastructure")
   * and resolves to the collected { slug, steps, complete, events }.
   * Inputs: value.
   * @see https://www.whisper.security/docs/recipes/pentest-recon
   */
  discoverAiAgentInfrastructure(input?: GraphFlowInput, opts?: GraphOptions): Promise<GraphFlowResult>;

  /**
   * Investigate one suspicious domain, IP, or network in depth and get a clear picture of the threat and everything connected to it.
   *
   * Deep-dive: works outward across the whole footprint (related domains, real origins behind
   * CDN, neighbouring infra), threat-checks each node, never inherits maliciousness from shared
   * infra; labelled posture, no score.
   *
   * KEYED flow: streams Server-Sent Events from the workflow runner (slug "indicator")
   * and resolves to the collected { slug, steps, complete, events }.
   * Inputs: indicator.
   * @see https://www.whisper.security/docs/recipes/soc
   */
  indicator(input?: GraphFlowInput, opts?: GraphOptions): Promise<GraphFlowResult>;

  /**
   * Turn one domain or IP into a full context card - owner, hosting, mail, location, reputation at a glance.
   *
   * Fills the picture for one indicator: registrant (WHOIS), hosting + country, mail/name
   * servers, network behind it, reputation read.
   *
   * KEYED flow: streams Server-Sent Events from the workflow runner (slug "indicator-enrichment")
   * and resolves to the collected { slug, steps, complete, events }.
   * Inputs: value.
   * @see https://www.whisper.security/docs/recipes/dns-email
   */
  indicatorEnrichment(input?: GraphFlowInput, opts?: GraphOptions): Promise<GraphFlowResult>;

  /**
   * Trace one indicator to its true owner and full estate, even behind privacy screens and CDNs.
   *
   * Works out the true operator (even behind privacy WHOIS), de-cloaks CDN-fronted sites to real
   * servers, pivots to the rest of that owner's estate across every layer.
   *
   * KEYED flow: streams Server-Sent Events from the workflow runner (slug "infrastructure-mapping")
   * and resolves to the collected { slug, steps, complete, events }.
   * Inputs: value. Params: level.
   * @see https://www.whisper.security/docs/recipes/compliance
   */
  infrastructureMapping(input?: GraphFlowInput, opts?: GraphOptions): Promise<GraphFlowResult>;

  /**
   * Grade an organisation for over-reliance on single providers, regions, or facilities.
   *
   * Grades how concentrated infra is - too much riding on one provider/region/data-centre/cable
   * landing - surfacing SPOFs for resilience and DORA/NIS2 fourth-party risk.
   *
   * KEYED flow: streams Server-Sent Events from the workflow runner (slug "map-supply-chain-concentration")
   * and resolves to the collected { slug, steps, complete, events }.
   * Inputs: domain.
   * @see https://www.whisper.security/docs/recipes/compliance
   */
  mapSupplyChainConcentration(input?: GraphFlowInput, opts?: GraphOptions): Promise<GraphFlowResult>;

  /**
   * Check a domain's name servers for the misconfigurations that enable DNS hijacking.
   *
   * Audits delegation, flags stale/mismatched/lame nameservers, sizes each provider's share,
   * surfaces registry facts - catches delegation weakness before exploit.
   *
   * KEYED flow: streams Server-Sent Events from the workflow runner (slug "nameserver-hijack-dns-consistency")
   * and resolves to the collected { slug, steps, complete, events }.
   * Inputs: value.
   * @see https://www.whisper.security/docs/recipes/dns-email
   */
  nameserverHijackDnsConsistency(input?: GraphFlowInput, opts?: GraphOptions): Promise<GraphFlowResult>;

  /**
   * Profile a network or address block into a full routing and reachability health card.
   *
   * Health card for a network/block: what it announces, peers/transit, single-upstream lean,
   * RPKI protection - the one-look reach & resilience report.
   *
   * KEYED flow: streams Server-Sent Events from the workflow runner (slug "route-health")
   * and resolves to the collected { slug, steps, complete, events }.
   * Inputs: target.
   * @see https://www.whisper.security/docs/recipes/bgp-routing
   */
  routeHealth(input?: GraphFlowInput, opts?: GraphOptions): Promise<GraphFlowResult>;

  /**
   * Find subdomains that point at abandoned services an attacker could claim.
   *
   * Walks subdomains and flags ones aiming at deprovisioned targets (dangling CNAME whose target
   * no longer resolves) so you can reclaim/remove before someone else does. CNAME layer is
   * prod-ahead.
   *
   * KEYED flow: streams Server-Sent Events from the workflow runner (slug "subdomain-takeover")
   * and resolves to the collected { slug, steps, complete, events }.
   * Inputs: value.
   * @see https://www.whisper.security/docs/recipes/pentest-recon
   */
  subdomainTakeover(input?: GraphFlowInput, opts?: GraphOptions): Promise<GraphFlowResult>;

  /**
   * Find registered look-alikes of your brand and check which ones are dangerous.
   *
   * Finds registered impersonations across misspellings/risky TLDs, separates your own defensive
   * domains from strangers', flags fresh/privacy/abuse-listed ones into a prioritised list.
   *
   * KEYED flow: streams Server-Sent Events from the workflow runner (slug "typosquat")
   * and resolves to the collected { slug, steps, complete, events }.
   * Inputs: domain.
   * @see https://www.whisper.security/docs/recipes/brand-protection
   */
  typosquat(input?: GraphFlowInput, opts?: GraphOptions): Promise<GraphFlowResult>;

  /**
   * Name the vendor and operator role behind a host or IP in one call.
   *
   * Resolves a host/IP to its canonical vendor, category and operator roles (DNS_OPERATOR / CDN
   * / ORIGIN_AS / MAIL_RECEIVER) with a confidence band.
   *
   * KEYED. Cypher: CALL whisper.identify([$v]) YIELD host, vendor_id, canonical_name, category, roles, host_class, band
   * Returns columns: host, vendor_id, canonical_name, category, roles, host_class, band.
   * @see https://www.whisper.security/docs/whisper-graph/procedures/identify
   */
  identify(value: string, opts?: GraphOptions): Promise<GraphResult>;

  /**
   * Get a labelled threat posture for a host or IP - malicious, benign, or unknown.
   *
   * Returns a posture label + severity band + sub-labels + coverage + evidence for an indicator;
   * benign-allowlisted vs malicious-evidenced, never a bare score.
   *
   * KEYED. Cypher: CALL whisper.assess([$v]) YIELD host, label, band, sub_labels, coverage, evidence
   * Returns columns: host, label, band, sub_labels, coverage, evidence.
   * @see https://www.whisper.security/docs/whisper-graph/procedures
   */
  assess(value: string, opts?: GraphOptions): Promise<GraphResult>;

  /**
   * Generate look-alike domain variants of a brand and see which are registered.
   *
   * Enumerates permutations (omission, bitsquatting, ...) of a domain, flags which exist, with a
   * per-variant confidence.
   *
   * KEYED. Cypher: CALL whisper.variants($v) YIELD variant, method, exists, confidence
   * Returns columns: variant, method, exists, confidence.
   * @see https://www.whisper.security/docs/whisper-graph/procedures/variants
   */
  variants(value: string, opts?: GraphOptions): Promise<GraphResult>;

  /**
   * Walk the graph to the nearest known vendors behind a host, with the channel and confidence.
   *
   * Structural attribution: returns nearest_known_vendors with the channel (DELEGATED_TO /
   * ORIGIN_AS) and confidence, plus siblings and coverage - explains WHY a host maps to a
   * vendor.
   *
   * KEYED. Cypher: CALL whisper.walk($v) YIELD coverage, host, nearest_known_vendors, no_atlas_match, siblings
   * Returns columns: coverage, host, nearest_known_vendors, no_atlas_match, siblings.
   * @see https://www.whisper.security/docs/whisper-graph/procedures
   */
  walk(value: string, opts?: GraphOptions): Promise<GraphResult>;

  /**
   * Score an indicator against the threat feeds and explain exactly why.
   *
   * Threat-intel scorer: score + level + human explanation + the feeds it is listed in (feedId,
   * weight, firstSeen/lastSeen). Two live forms: bare CALL explain($v) (full columns) and CALL
   * whisper.explain($v) (restricted YIELD).
   *
   * KEYED. Cypher: CALL whisper.explain($v) YIELD indicator, score, level, explanation, sources
   * Returns columns: indicator, score, level, explanation, sources.
   * @see https://www.whisper.security/docs/whisper-graph/procedures/explain
   */
  explain(value: string, opts?: GraphOptions): Promise<GraphResult>;

  /**
   * Reduce any hostname to its registrable apex (eTLD+1) via the Public Suffix List.
   *
   * PSL-correct eTLD+1: www.foo.co.uk -> foo.co.uk. The right way to group hosts by the thing
   * someone actually registered.
   *
   * KEYED. Cypher: CALL whisper.psl.tldPlusOne($v) YIELD apex
   * Returns columns: apex.
   * @see https://www.whisper.security/docs/whisper-graph/procedures/helpers
   */
  pslTldplusone(value: string, opts?: GraphOptions): Promise<GraphResult>;

  /**
   * Check whether a domain is a PSL private-section suffix and who submitted it.
   *
   * For a PSL private-section suffix, returns the submitting org/login and evidence kind +
   * confidence; found=false for ordinary registrable domains.
   *
   * KEYED. Cypher: CALL whisper.psl.affiliation($v) YIELD found, suffix, submitterOrg, submitterLogin, evidenceKind, confidence
   * Returns columns: found, suffix, submitterOrg, submitterLogin, evidenceKind, confidence.
   * @see https://www.whisper.security/docs/whisper-graph/procedures/helpers
   */
  pslAffiliation(value: string, opts?: GraphOptions): Promise<GraphResult>;

  /**
   * Find the real origin IPs behind a CDN-fronted domain, ranked by confidence.
   *
   * Candidate origin IPs behind a CDN with confidence, the methods that found them (e.g.
   * links_to), and the hosting ASN/name - de-cloaks to the real server.
   *
   * KEYED. Cypher: CALL whisper.origins($v) YIELD ip, confidence, methods, asn, asnName, kind
   * Returns columns: ip, confidence, methods, asn, asnName, kind.
   * @see https://www.whisper.security/docs/whisper-graph/procedures/origins
   */
  origins(value: string, opts?: GraphOptions): Promise<GraphResult>;

  /**
   * Get the full historical WHOIS timeline for a domain.
   *
   * Every observed WHOIS snapshot over time: create/update/expiry, registrar, registrant,
   * country, nameservers - the ownership/registration story.
   *
   * KEYED. Cypher: CALL whisper.history($v)
   * Returns columns: indicator, type, queryTime, createDate, updateDate, expiryDate, registrar, registrant, country, nameServers, cached.
   * @see https://www.whisper.security/docs/whisper-graph/procedures/history
   */
  history(value: string, opts?: GraphOptions): Promise<GraphResult>;

  /**
   * Get the WHOIS-only historical timeline for a domain.
   *
   * The registration-record projection of the history timeline: create/update/expiry, registrar,
   * registrant, country, nameservers per snapshot.
   *
   * KEYED. Cypher: CALL whisper.history.whois($v) YIELD queryTime, createDate, updateDate, expiryDate, registrar, registrant, country, nameServers
   * Returns columns: queryTime, createDate, updateDate, expiryDate, registrar, registrant, country, nameServers.
   * @see https://www.whisper.security/docs/whisper-graph/procedures/history
   */
  historyWhois(value: string, opts?: GraphOptions): Promise<GraphResult>;

  /**
   * List the member ASNs of an AS-SET macro.
   *
   * Expands an AS-SET name (e.g. AS-CLOUDFLARE) to its member ASNs and source RIR. Arg is a
   * STRING as-set name, not an integer ASN. (Membership is sparsely populated in the current
   * graph.)
   *
   * KEYED. Cypher: CALL whisper.asSet($v) YIELD asSetName, memberAsn, sourceRir
   * Returns columns: asSetName, memberAsn, sourceRir.
   * @see https://www.whisper.security/docs/whisper-graph/procedures
   */
  asset(value: string, opts?: GraphOptions): Promise<GraphResult>;

  /**
   * Check whether an IP is a known Tor exit relay.
   *
   * Live Tor exit-node check: found + fingerprint + exit-address count + source + ingest time
   * for an IPv4.
   *
   * KEYED. Cypher: CALL whisper.lookupTorRelay($v) YIELD indicator, found, fingerprint, exitAddressCount, source, ingestedAt
   * Returns columns: indicator, found, fingerprint, exitAddressCount, source, ingestedAt.
   * @see https://www.whisper.security/docs/whisper-graph/procedures/helpers
   */
  lookupTorRelay(value: string, opts?: GraphOptions): Promise<GraphResult>;

  /**
   * List every node and relationship type in the graph with counts and examples.
   *
   * The self-describing schema: node/relationship types with counts, descriptions, examples,
   * source/target labels and query best-practices - the map of what the graph holds.
   *
   * KEYED. Cypher: CALL db.schema()
   * Returns columns: type, name, count, description, example, sourceLabels, targetLabels, fastPatterns, slowPatterns, bestPractices.
   * @see https://www.whisper.security/docs/whisper-graph/schema
   */
  dbSchema(opts?: GraphOptions): Promise<GraphResult>;

  /**
   * Contribute an indicator observation or feedback back into the graph (requires an API key).
   *
   * The write channel: submit an indicator/feedback with an attributable API key (anonymous
   * submits are refused to preserve K-anonymity). Keyed-only by design.
   *
   * KEYED write: CALL whisper.submit({...}) with the payload fields bound as $-parameters.
   * Fields: kind, identifier_kind, value, observation_id, confidence, first_seen, provenance, query, results, comment, severity, v (kind required).
   * Returns columns: observation_id, kind, accepted, idempotent, promotion_state, k_bucket, advisory, v.
   * @see https://www.whisper.security/docs/cypher-api
   */
  submit(payload: GraphSubmission, opts?: GraphOptions): Promise<GraphResult>;
  // END GENERATED: graph catalog
}

/** The keyed graph namespace. `import { graph } from "whisper-id"`. */
export const graph: GraphNamespace;
