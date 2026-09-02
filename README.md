# whisper-id

Three things for any Node agent, in one dependency-free package: query the **Whisper security graph** (billions of nodes joining the physical, network, naming, ownership and threat layers; live totals at nic.whisper.online/stats, Cypher), give the agent a routable **IPv6 identity** with safe **egress**, and drive the full **control plane**.

```sh
npm i whisper-id
```

## The security graph (keyless, zero setup)

The Whisper graph knows who operates a host, its threat posture, its look-alikes, the real origins behind a CDN, WHOIS history, and 20+ named investigations. The **direct read verbs run with no key at all** (rate-limited taste, ~100/window). One import, real answers:

```js
import { graph } from "whisper-id";                // no key needed for the read verbs

await graph.assess("8.8.8.8");                     // -> { rows: [{ host: "8.8.8.8", label: "benign-allowlisted", band: "INFO", ... }] }
await graph.identify("api.openai.com");            // who operates this host -> vendor + operator roles
await graph.origins("cloudflare.com");             // the real origin IPs behind a CDN
await graph.explain("paypal.com");                 // threat-feed score + why
```

Set `WHISPER_API_KEY` (or pass `{ apiKey }`) to lift the rate limit and unlock **raw Cypher** and the **multi-step flows**:

```js
// raw Cypher, your own query, parameters bound as $-params (never string-built):
await graph.query("MATCH (h:HOSTNAME {name:$n})-[:RESOLVES_TO]->(ip) RETURN ip.name AS ip LIMIT 5", { n: "github.com" });

// a named catalog recipe (a multi-step investigation, streamed over SSE):
await graph.typosquat("paypal.com");               // look-alike sweep -> registered variants + verdict
await graph.attackSurface({ domain: "github.com" });  // full external footprint, scored

// discover the whole catalog (29 queries + flows) with no key, no network:
for (const r of graph.recipes()) {
  console.log(r.method, r.keyless ? "keyless" : "keyed", r.docsUrl);
}
```

Every verb maps to a catalog entry with its own docs page under [whisper.security/docs](https://www.whisper.security/docs) (e.g. [`assess`](https://www.whisper.security/docs/whisper-graph/procedures), [`identify`](https://www.whisper.security/docs/whisper-graph/procedures/identify)); `recipes()` carries the exact `docsUrl` for each, and the same URL sits on every method as `graph.identify.docs` and on its `@see` tag in your editor. The 13 direct reads are keyless; the 15 multi-step flows and the `submit` write channel are keyed. Full query reference: [whisper-catalog](https://github.com/whisper-sec/whisper-catalog).

## Identity + egress

```js
import { identity, withEgress } from "whisper-id"; // with a key (WHISPER_API_KEY)

const me = await identity({ label: "my-bot" });    // allocate a routable Whisper /128
await withEgress(async (e) => {
  // proxy env (HTTP_PROXY/HTTPS_PROXY/ALL_PROXY) now points at your local Whisper proxy
  // -> curl, axios, got, and other env-aware clients leave from your /128.
  console.log("egress on", e.proxyUrl);
});
```

And anyone, with no key, can verify an address is a real Whisper agent:

```js
import { verify, rdap } from "whisper-id";
if (await verify(addr)) console.log((await rdap(addr)).name);   // keyless, pure HTTPS
```

## API

### The graph (two-tier)

`import { graph } from "whisper-id"`: one typed method per catalog entry, plus `graph.query`
(raw Cypher) and `graph.recipes()` (catalog discovery). Direct reads resolve to
`{ columns, rows, statistics }` where `rows` are objects keyed by column name.

| Call | Keyless | Does |
|------|:-------:|------|
| `graph.assess(value)` | yes | Labelled threat posture for a host or IP (malicious / benign / unknown) |
| `graph.identify(value)` | yes | Name the vendor and operator role behind a host or IP |
| `graph.variants(value)` | yes | Look-alike domain variants of a brand, and which are registered |
| `graph.walk(value)` | yes | Walk to the nearest known vendors behind a host, with channel + confidence |
| `graph.explain(value)` | yes | Score an indicator against the threat feeds and explain why |
| `graph.origins(value)` | yes | Real origin IPs behind a CDN-fronted domain, ranked by confidence |
| `graph.history(value)` / `graph.historyWhois(value)` | yes | Historical WHOIS timeline for a domain |
| `graph.pslTldplusone(value)` / `graph.pslAffiliation(value)` | yes | Registrable apex (eTLD+1) / PSL private-section affiliation |
| `graph.asset(value)` | yes | Member ASNs of an AS-SET macro |
| `graph.lookupTorRelay(value)` | yes | Is an IP a known Tor exit relay |
| `graph.dbSchema()` | yes | Every node + relationship type in the graph, with counts and examples |
| `graph.query(cypher, params)` | key | Raw Cypher escape hatch. -> the full `{ columns, rows, statistics }` |
| `graph.submit({ kind, ...fields })` | key | Contribute an indicator observation or feedback (the write channel) |
| `graph.recipes()` | yes (offline) | The whole catalog: `{ method, keyless, mode, summary, params, docsUrl }` per verb |

Fifteen multi-step **workflow** methods (`attackPath`, `attackSurface`, `blastRadius`, `typosquat`,
`indicator`, `routeHealth`, and 9 more) execute keyed on the Whisper workflow runner and stream
Server-Sent Events; one call collects the whole run into `{ slug, steps, complete, events }`:

```js
const run = await graph.typosquat("paypal.com");   // bare value -> the flow's primary input
console.log(run.steps.length, "steps");            // each step: its bound Cypher, columns, rows
console.log(run.complete.totalLatencyMs, "ms");    // the terminal aggregate context

await graph.attackSurface({ domain: "github.com", level: "deep" });  // named inputs + knobs
```

Every `graph` method is generated from the Whisper query catalog (never hand-copied, so it
cannot drift). A key, when present, rides only in the `X-API-Key` header; a keyless call sends
no auth header at all.

### Keyless: no key, no CLI (pure HTTPS)

Run anywhere `fetch` runs (Cloudflare Workers, Vercel, Deno, Lambda, the browser).

| Call | Does |
|------|------|
| `verify(address)` | Is `address` a real Whisper agent? (server-side DANE + DNSSEC + reverse-DNS + JWS) → `boolean` |
| `verifyDetails(address)` | The full verdict (`is_whisper_agent`, `fqdn`, `operator`, `dane_ok`, `jws_ok`, and more) or `null` |
| `rdap(address)` | The public RDAP record for a `/128`, or `null` |
| `egressIp()` | The IP this process leaves from (a `/128` when routed, else the platform's) → `string` |

### Control plane: with a key (pure HTTP, no CLI)

Pure `fetch` to the control endpoint, with no `whisper` CLI and no child process. The key comes from
`opts.apiKey` or `WHISPER_API_KEY` and is sent only in the `X-API-Key` header (never on argv,
never logged). Each also takes `{ apiKey, timeout }`. On failure they throw a `WhisperError`
carrying the server's `detail` (plus `.status` / `.retryAfter`).

| Call | Does |
|------|------|
| `list({ kind })` | List your fleet. `kind`: `"agents"` (default) \| `"identities"` \| `"records"`. → items `{ label, fqdn, address, agent, created, state }` |
| `identity({ label, contact_email })` | Allocate your own `/128`. Release with `{ release: true, address }`. → `{ agent, address, fqdn, ptr, state }` |
| `agent(idOrAddress)` | One agent's detail + live counters. → the record, or `null` |
| `policy({ default, allow, block })` | Read (no fields) or set your per-tenant DNS policy. → `{ key, value }` rows |
| `logs({ agent, kind, from, to, limit })` | Recent DNS/conn/alloc activity from warm storage. → event records |
| `revoke(idOrAddress)` | Fully revoke an agent, **irreversible** (needs `admin:dns`). → `{ status }` |

```js
import { list, policy, logs } from "whisper-id"; // WHISPER_API_KEY in the env

await policy({ default: "deny", allow: ["api.openai.com", "*.githubusercontent.com"] });
for (const a of await list()) console.log(a.address, a.label);
const recent = await logs({ kind: "dns", limit: 100 });
```

### Egress + CLI-backed

| Call | Does |
|------|------|
| `register(name, { newKey })` | Create a named agent via the CLI: a routable `/128`. `newKey: true` mints a new agent **and** its own API key. → `Agent { address, id, name }` |
| `egress({ agent, tier, setEnv })` | Bring up egress bound to your `/128`. → `Egress { port, proxyUrl, socksUrl, proxies, close() }`. `tier: "wireguard"` for a routed `/128`. Sets proxy env unless `setEnv:false`; call `close()` to restore. |
| `withEgress([opts], fn)` | Run `fn(egress)` with egress up, restoring the environment afterwards. |
| `ip()` | Your current egress IP via the CLI, proving it's your `/128`. → `string` |

`register`, `egress`, `withEgress`, and `ip` need the `whisper` CLI on the host (egress brings up
the local proxy). Everything else, the graph included, is pure HTTP and needs no CLI.

### Using it with `fetch`

Node's global `fetch` (undici) does **not** read proxy env vars, so pass a dispatcher:

```js
import { egress } from "whisper-id";
import { ProxyAgent } from "undici";          // npm i undici

const e = await egress();
const res = await fetch("https://api64.ipify.org", { dispatcher: new ProxyAgent(e.proxyUrl) });
console.log(await res.text());                 // ← your /128
```

`axios` / `got` can take `e.proxyUrl` directly; CLI tools and env-aware libraries work
transparently inside `withEgress`.

## Requirements

Zero dependencies. The **graph read verbs**, the **keyless** checks, and the **control plane** are
pure HTTP (Node ≥ 18's global `fetch`), with no CLI and nothing to install. Set `WHISPER_API_KEY`
(or pass `{ apiKey }`) for the control plane and the keyed graph (raw Cypher + flows + `submit`);
the graph read verbs, `verify`, and `rdap` need no key.

Only **egress** and the CLI-backed calls (`register`, `egress`, `withEgress`, `ip`) need the
`whisper` CLI on your `PATH`:

```sh
curl -fsSL https://get.whisper.online | sh
```

(`$WHISPER_BIN` overrides the CLI path; `$WHISPER_CONTROL_URL` / `$WHISPER_GRAPH_URL` /
`$WHISPER_FLOW_URL` / `$WHISPER_RDAP_URL` override the endpoints.)

## Links

- Site: https://whisper.online
- Docs: https://www.whisper.security/docs
- Query catalog: https://github.com/whisper-sec/whisper-catalog
- CLI: https://github.com/whisper-sec/whisper-cli

MIT licensed.
