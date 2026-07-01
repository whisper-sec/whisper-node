# whisper-id

A real, routable **IPv6 identity** and **safe egress** for any Node agent.

**Two-tier, by design** (Postel's Law): **with no key** the keyless half works everywhere —
`verify`, `verifyDetails`, `rdap` — so anyone can prove an address is a Whisper agent. **With
your key** (`opts.apiKey` or `WHISPER_API_KEY`) the whole control plane unlocks — list, policy,
logs, revoke, identity, agent — plus **egress** that sources your traffic from your `/128`.

```sh
npm i whisper-id
```

```js
import { verify } from "whisper-id";
await verify("2a04:2a01:…");                       // keyless: true if it's a real Whisper agent
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

### Keyless — no key, no CLI (pure HTTPS)

Run anywhere `fetch` runs (Cloudflare Workers, Vercel, Deno, Lambda, the browser).

| Call | Does |
|------|------|
| `verify(address)` | Is `address` a real Whisper agent? (server-side DANE + DNSSEC + reverse-DNS + JWS) → `boolean` |
| `verifyDetails(address)` | The full verdict (`is_whisper_agent`, `fqdn`, `operator`, `dane_ok`, `jws_ok`, …) or `null` |
| `rdap(address)` | The public RDAP record for a `/128`, or `null` |
| `egressIp()` | The IP this process leaves from (a `/128` when routed, else the platform's) → `string` |

```js
import { verify, rdap } from "whisper-id";
if (await verify(addr)) console.log((await rdap(addr)).name);
```

### Control plane — with a key (pure HTTP, no CLI)

Pure `fetch` to the control endpoint — no `whisper` CLI, no child process. The key comes from
`opts.apiKey` or `WHISPER_API_KEY` and is sent only in the `X-API-Key` header (never on argv,
never logged). Each also takes `{ apiKey, timeout }`. On failure they throw a `WhisperError`
carrying the server's `detail` (plus `.status` / `.retryAfter`).

| Call | Does |
|------|------|
| `list({ kind })` | List your fleet — `kind`: `"agents"` (default) \| `"identities"` \| `"records"`. → items `{ label, fqdn, address, agent, created, state }` |
| `identity({ label, contact_email })` | Allocate your own `/128`. Release with `{ release: true, address }`. → `{ agent, address, fqdn, ptr, state }` |
| `agent(idOrAddress)` | One agent's detail + live counters. → the record, or `null` |
| `policy({ default, allow, block })` | Read (no fields) or set your per-tenant DNS policy. → `{ key, value }` rows |
| `logs({ agent, kind, from, to, limit })` | Recent DNS/conn/alloc activity from warm storage. → event records |
| `revoke(idOrAddress)` | Fully revoke an agent — **irreversible** (needs `admin:dns`). → `{ status }` |

```js
import { list, policy, logs } from "whisper-id"; // WHISPER_API_KEY in the env

await policy({ default: "deny", allow: ["api.openai.com", "*.githubusercontent.com"] });
for (const a of await list()) console.log(a.address, a.label);
const recent = await logs({ kind: "dns", limit: 100 });
```

### Egress + CLI-backed

| Call | Does |
|------|------|
| `register(name, { newKey })` | Create a named agent via the CLI — a routable `/128`. `newKey: true` mints a new agent **and** its own API key. → `Agent { address, id, name }` |
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
global `fetch`) — no CLI, nothing to install. For the control plane, set `WHISPER_API_KEY` (or
pass `{ apiKey }`).

Only **egress** and the CLI-backed calls (`register`, `egress`, `withEgress`, `ip`) need the
`whisper` CLI on your `PATH`:

```sh
curl get.whisper.online | sh
```

(`$WHISPER_BIN` overrides the CLI path; `$WHISPER_CONTROL_URL` / `$WHISPER_RDAP_URL` override the
endpoints.)

## Links

- Site — https://whisper.online
- CLI — https://github.com/whisper-sec/whisper-cli

MIT licensed.
