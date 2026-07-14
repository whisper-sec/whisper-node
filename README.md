# whisper-id

A real, routable **IPv6 identity** and **safe egress** for any Node agent.

**Two-tier, by design** (Postel's Law): **with no key** the keyless half works everywhere.
`verify`, `verifyDetails`, and `rdap` let anyone prove an address is a Whisper agent. **With
your key** (`opts.apiKey` or `WHISPER_API_KEY`) the whole control plane unlocks (list, policy,
logs, revoke, identity, agent), plus the keyed **`graph`** namespace (Cypher intelligence over
the Whisper Security graph) and **egress** that sources your traffic from your `/128`.

```sh
npm i whisper-id
```

```js
import { verify } from "whisper-id";
await verify("2a04:2a01:...");                     // keyless: true if it's a real Whisper agent
```

```js
import { identity, withEgress } from "whisper-id"; // with a key (WHISPER_API_KEY)
const me = await identity({ label: "my-bot" });    // allocate a routable Whisper /128
await withEgress(async (e) => {
  // proxy env (HTTP_PROXY/HTTPS_PROXY/ALL_PROXY) now points at your local Whisper proxy
  // → curl, axios, got, and other env-aware clients leave from your /128.
  console.log("egress on", e.proxyUrl);
});
```

## API

### Keyless: no key, no CLI (pure HTTPS)

Run anywhere `fetch` runs (Cloudflare Workers, Vercel, Deno, Lambda, the browser).

| Call | Does |
|------|------|
| `verify(address)` | Is `address` a real Whisper agent? (server-side DANE + DNSSEC + reverse-DNS + JWS) → `boolean` |
| `verifyDetails(address)` | The full verdict (`is_whisper_agent`, `fqdn`, `operator`, `dane_ok`, `jws_ok`, and more) or `null` |
| `rdap(address)` | The public RDAP record for a `/128`, or `null` |
| `egressIp()` | The IP this process leaves from (a `/128` when routed, else the platform's) → `string` |

```js
import { verify, rdap } from "whisper-id";
if (await verify(addr)) console.log((await rdap(addr)).name);
```

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

### Graph (keyed Cypher, pure HTTP)

The intelligence half of the keyed surface. `import { graph } from "whisper-id"` and you get one
typed method per catalog entry over the Whisper Security graph, plus a raw `graph.query` escape
hatch. Same auth as the control plane: the key comes from `opts.apiKey` or `WHISPER_API_KEY` and
is sent only in `X-API-Key`. If it is Cypher, it needs a key: this whole namespace is keyed (the
keyless `verify` / `verifyDetails` / `rdap` above touch no Cypher and stay key-free). Every method
resolves to `{ columns, rows, statistics }` where `rows` are objects keyed by column name.

```js
import { graph } from "whisper-id";                // WHISPER_API_KEY in the env, or pass { apiKey }

const r = await graph.identify("api.openai.com", { apiKey: "whisper-..." });
console.log(r.rows[0].vendor_id, r.rows[0].canonical_name);   // → openai OpenAI

await graph.assess("185.220.101.33");              // threat posture: malicious / benign / unknown
await graph.variants("paypal.com");                // registered look-alike domains
await graph.origins("cloudflare.com");             // real origin IPs behind a CDN
await graph.query("MATCH (n) RETURN n LIMIT $lim", { lim: 5 });  // raw Cypher escape hatch
```

| Call | Does |
|------|------|
| `graph.identify(value)` | Name the vendor and operator role behind a host or IP |
| `graph.assess(value)` | Labelled threat posture for a host or IP (malicious / benign / unknown) |
| `graph.variants(value)` | Look-alike domain variants of a brand, and which are registered |
| `graph.walk(value)` | Walk to the nearest known vendors behind a host, with channel + confidence |
| `graph.explain(value)` | Score an indicator against the threat feeds and explain why |
| `graph.pslTldplusone(value)` | Reduce any hostname to its registrable apex (eTLD+1) |
| `graph.pslAffiliation(value)` | Is a domain a PSL private-section suffix, and who submitted it |
| `graph.origins(value)` | Real origin IPs behind a CDN-fronted domain, ranked by confidence |
| `graph.history(value)` | Full historical WHOIS timeline for a domain |
| `graph.historyWhois(value)` | WHOIS-only historical timeline for a domain |
| `graph.asset(value)` | Member ASNs of an AS-SET macro |
| `graph.lookupTorRelay(value)` | Is an IP a known Tor exit relay |
| `graph.dbSchema()` | Every node + relationship type in the graph, with counts and examples |
| `graph.submit({ kind, ...fields })` | Contribute an indicator observation or feedback (keyed write) |
| `graph.query(cypher, params)` | Raw Cypher escape hatch. → the full `{ columns, rows, statistics }` |

Fifteen multi-step **workflow** methods (`attackPath`, `attackSurface`, `blastRadius`, `typosquat`,
`indicator`, `routeHealth`, and 9 more) execute on the Whisper workflow runner and stream
Server-Sent Events; one call collects the whole run into `{ slug, steps, complete, events }`:

```js
const run = await graph.typosquat("paypal.com");   // bare value → the flow's primary input
console.log(run.steps.length, "steps");            // each step: its bound Cypher, columns, rows
console.log(run.complete.totalLatencyMs, "ms");    // the terminal aggregate context

await graph.attackSurface({ domain: "github.com", level: "deep" });  // named inputs + knobs
```

Every `graph` method is generated from the Whisper query catalog (never hand-copied, so it
cannot drift) and links its canonical docs: `graph.identify.docs` →
`https://www.whisper.security/docs/whisper-graph/procedures/identify`, and the same URL is on
each method's `@see` tag in your editor.

### Egress + CLI-backed

| Call | Does |
|------|------|
| `register(name, { newKey })` | Create a named agent via the CLI: a routable `/128`. `newKey: true` mints a new agent **and** its own API key. → `Agent { address, id, name }` |
| `egress({ agent, tier, setEnv })` | Bring up egress bound to your `/128`. → `Egress { port, proxyUrl, socksUrl, proxies, close() }`. `tier: "wireguard"` for a routed `/128`. Sets proxy env unless `setEnv:false`; call `close()` to restore. |
| `withEgress([opts], fn)` | Run `fn(egress)` with egress up, restoring the environment afterwards. |
| `ip()` | Your current egress IP via the CLI, proving it's your `/128`. → `string` |

`register`, `egress`, `withEgress`, and `ip` need the `whisper` CLI on the host (egress brings up
the local proxy). Everything under **Keyless** and **Control plane** is pure HTTP and needs no CLI.

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

Zero dependencies. The **keyless** checks and the **control plane** are pure HTTP (Node ≥ 18's
global `fetch`), with no CLI and nothing to install. For the control plane, set `WHISPER_API_KEY` (or
pass `{ apiKey }`).

Only **egress** and the CLI-backed calls (`register`, `egress`, `withEgress`, `ip`) need the
`whisper` CLI on your `PATH`:

```sh
curl get.whisper.online | sh
```

(`$WHISPER_BIN` overrides the CLI path; `$WHISPER_CONTROL_URL` / `$WHISPER_GRAPH_URL` /
`$WHISPER_RDAP_URL` override the endpoints.)

## Links

- Site: https://whisper.online
- CLI: https://github.com/whisper-sec/whisper-cli

MIT licensed.
