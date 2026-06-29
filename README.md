# whisper-id

A real, routable **IPv6 identity** and **safe egress** for any Node agent — in two calls.

```sh
npm i whisper-id
```

```js
import { register, withEgress } from "whisper-id";

const agent = await register("my-bot");          // a routable Whisper /128 identity
await withEgress(async (e) => {
  // proxy env (HTTP_PROXY/HTTPS_PROXY/ALL_PROXY) now points at your local Whisper proxy
  // → curl, axios, got, and other env-aware clients leave from your /128.
  console.log("egress on", e.proxyUrl);
});
```

## API

| Call | Does |
|------|------|
| `register(name, { newKey })` | Create a named agent — a routable `/128`. `newKey: true` mints a new agent **and** its own API key. → `Agent { address, id, name }` |
| `egress({ agent, tier, setEnv })` | Bring up egress bound to your `/128`. → `Egress { port, proxyUrl, socksUrl, proxies, close() }`. `tier: "wireguard"` for a routed `/128`. Sets proxy env unless `setEnv:false`; call `close()` to restore. |
| `withEgress([opts], fn)` | Run `fn(egress)` with egress up, restoring the environment afterwards. |
| `verify(address)` | Keyless — is `address` a real Whisper agent? (DANE + DNSSEC + reverse-DNS + JWS) → `boolean` |
| `ip()` | Your current egress IP, proving it's your `/128`. → `string` |

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

The `whisper` CLI on your `PATH` (this package is a thin, dependency-free wrapper over it):

```sh
curl get.whisper.online | sh
```

For authenticated calls (`register`, `egress`, `ip`), set `WHISPER_API_KEY` or run
`whisper login`. `verify` is keyless. (`$WHISPER_BIN` overrides the CLI path.)

## Links

- Site — https://whisper.online
- CLI — https://github.com/whisper-sec/whisper-cli

MIT licensed.
