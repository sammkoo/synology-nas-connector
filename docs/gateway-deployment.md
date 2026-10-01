# Running the gateway service

The gateway now has a native CLI, a portable bundle and a dedicated Docker target. It serves OAuth discovery/protocol, first-party browser consent, pairing and the protected MCP resource, and accepts outbound NAS channels. This is an operator deployment preview. Build 0005 adds DSM agent/pairing controls; a running gateway is not proof of a completed ChatGPT connection. Real DSM authentication and approved public hosting still need validation.

Use a tested Node.js 22.18+ or Node.js 24 runtime. The gateway alone uses `node:sqlite`; the NAS bundle does not import it. OpenSSL is needed for development TLS tests, not for the shipped gateway process. Run one gateway process per private state directory on a local filesystem with SQLite locking. Network filesystem state and multiple replicas are unsupported.

## First installation

Build the repository, then explicitly initialize a new private installation:

```sh
npm ci
npm run check
node dist/gateway.cjs --init --config .gateway/config.json \
  --issuer https://gateway.example/ \
  --callback https://client.example/exact-callback
```

Both URLs above are placeholders. Choose the actual gateway domain and copy the exact OAuth callback from the client's connection management page. Do not invent an OpenAI callback/client ID or use a wildcard allowlist. Additional approved callbacks use repeated `--callback` options, up to 20. Issuer values are canonical HTTPS origins ending in `/`; the resource is that origin plus `mcp`.

Initialization creates a process-owned private directory, config, 32-byte `state/auth.key`, installation metadata and SQLite database. Files are mode `0600`, directories `0700`. It refuses to overwrite an existing configuration or state directory. Partial initialization also requires operator inspection; retrying never replaces a pre-existing key. Startup does not initialize missing state or repair permissions automatically.

Default configuration:

```json
{
  "issuer": "https://gateway.example/",
  "redirectUris": ["https://client.example/exact-callback"],
  "dataDirectory": "state",
  "transport": {
    "mode": "https",
    "host": "127.0.0.1",
    "port": 8788,
    "certificateFile": "tls/cert.pem",
    "privateKeyFile": "tls/key.pem"
  },
  "limits": {
    "maxConnections": 128,
    "databaseMaxBytes": 268435456
  }
}
```

File paths resolve against the config file directory. Unknown fields, duplicate callbacks and invalid transport settings fail validation. Keep config/state writable only by the gateway operator/service identity. Its private TLS key must also be process-owned and mode `0600`; a certificate chain is public and may be readable by other users. Symlink file replacements are rejected. Install the actual certificate chain and matching key in the configured paths; initialization never creates or trusts a production self-signed certificate.

```sh
node dist/gateway.cjs --config .gateway/config.json
node dist/gateway.cjs --healthcheck --config .gateway/config.json
```

`NAS_GATEWAY_CONFIG` can supply the config path instead of `--config`. There are no command-line bearer tokens, passwords or master-key values. Startup output contains only fixed status/error codes. The health probe connects only to the configured listener address, supplies the configured Host and verifies its TLS certificate against the issuer hostname and OS trust store. An explicitly managed CA may use Node's `NODE_EXTRA_CA_CERTS`; certificate verification remains enabled.

The listener defaults to loopback. An operator may set an explicit literal IP for direct HTTPS binding. The issuer remains the public origin even when the internal port/address differs. Public DNS, certificate issuance/renewal, HTTPS routing and a hosting account still need an approved operator deployment. This project does not provision a domain or silently expose a home NAS.

## Existing TLS reverse proxy

For a gateway process on the same host as an operator-managed TLS edge, replace only `transport`:

```json
"transport": {
  "mode": "proxy",
  "host": "127.0.0.1",
  "port": 8788,
  "trustedProxyAddresses": ["127.0.0.1"]
}
```

Proxy mode permits only loopback binding and explicitly trusted loopback peers. The edge must route the exact configured Host, overwrite `X-Forwarded-Proto` with `https` and overwrite `X-Forwarded-For` with one valid client IP. Appended chains, missing provenance and direct plaintext requests fail. On a TLS listener, untrusted forwarded headers are ignored; client address is the direct peer. Do not trust arbitrary networks or expose a proxy-mode listener on a public/container bridge address.

The edge must support HTTP/1.1 WebSocket upgrades for `/agent/relay`, preserve the `nas-relay.v1` subprotocol and use bounded connection/header/body budgets. HTTP bodies need at most 16 KiB. Allow at least the agent's 20-second heartbeat and the MCP response deadline of 40 seconds; a 45-second idle upstream budget is compatible with those bounds. Turn off URL/header/body access logging: OAuth authorization parameters and pairing credentials can appear in requests. Never enable a shared response cache, content analytics or request mirroring on these routes. See [relay privacy and limits](relay.md).

## Docker

Initialize `.gateway` natively as above, install the real TLS files, then set `transport.host` to `0.0.0.0` **inside the HTTPS container configuration**. Keep the configured port 8788 for the supplied Compose file. The host publication remains `127.0.0.1:8788`; an operator-managed HTTPS edge or explicitly approved public deployment supplies external routing.

```sh
GATEWAY_UID=$(id -u) GATEWAY_GID=$(id -g) \
  docker compose -f compose.gateway.yaml up --build -d
```

The configured UID/GID must own `.gateway/config.json`, private key and state files. Compose mounts config/TLS read-only and only the state directory writable; it drops capabilities, uses a read-only image, disallows privilege escalation and caps process count, memory and CPU. Shutdown has a ten-second container grace period. The dedicated image target is also available as:

```sh
docker build --target gateway -t nas-connector-gateway .
```

The ordinary Docker build still defaults to the local NAS connector. Both bundles have their dependency license notices in `dist/`; the gateway uses `GATEWAY_THIRD_PARTY_NOTICES.txt`. Optional native WebSocket accelerators are not bundled or required. The existing CI Docker smoke script additionally builds and starts the gateway target, exercises real verified TLS and OAuth discovery/catalog, rejects anonymous data access, checks read-only config and verifies a container restart with persistent state.

## Lifetime, backups and recovery

The SQLite connection holds an exclusive lock for its entire lifetime. A second gateway using that state fails startup; the OS releases the lock after process termination, so no stale lock-file deletion is required. SIGTERM/SIGINT stop accepting connections, disconnect relay channels, drain HTTP work for at most five seconds and close the database. NAS agents reconnect and existing unexpired grants remain device-bound.

Back up **the complete private state directory**, configuration and required TLS material consistently while the service is stopped. Protect backups as credentials. The installation metadata binds the key to the issuer, and the database contains a separate HMAC binding to that installation. Missing/replaced keys, a missing database, or a database from a different key/issuer fail startup. Restore a matching backup; `--init` is not a recovery or key-rotation command. If no consistent backup exists, establishing a new gateway installation requires fresh NAS pairing and client consent. Do not reuse an old issuer/state selectively and claim existing grants were preserved.

Issuer migration, zero-downtime key rotation, distributed state and automatic backup/restore orchestration are not implemented. Certificate replacement at the same configured paths requires a graceful restart; key modes/ownership must remain valid. OAuth dynamic registrations stay valid for a connection lifetime, while access and refresh/grant lifetimes remain short/bounded as documented in [gateway authorization](gateway-auth.md). Expired records are pruned every minute. Operators still need a policy for retiring unused persistent client registrations before their bounded capacity is exhausted.

SQLite main database growth defaults to 256 MiB and can be configured between 16 MiB and 1 GiB. Exceeding it rejects writes without committing a partial record; existing reads/grants remain subject to the normal checks. Journals/backups require additional disk budget. Do not reduce the configured limit below an existing database's allocated pages. Pruning reuses database pages and does not promise to shrink the file. Monitor disk space, resource use, fixed startup codes and HTTP errors without capturing request secrets or NAS content. `/health` confirms a running attached listener; it does not certify every NAS is online or all future storage writes can succeed.

The process caps total connections (including incomplete TLS handshakes), enforces TLS 1.2+, ten-second TLS/header deadlines, a fifteen-second request-input deadline, bounded keep-alive/idle sockets and a sixteen-KiB header limit. These are in addition to [application/MCP/relay bounds](relay.md). Container limits are initial operator defaults, not a capacity or load certification; production hosting still needs its own monitoring, renewal, recovery and resource validation.

## Verification and remaining gates

`tests/gateway-deployment.test.ts` checks private/immutable initialization, strict config, lost or replaced keys, unsafe modes/symlinks, missing/mismatched database backup, exclusive runtime locking, actual HTTPS MCP reads through a signed NAS channel across restart, revocation, loopback proxy provenance, pending-TLS connection limits and database budget failure without loss of committed state. `scripts/smoke-gateway.mjs` executes the shipped bundle as separate processes and verifies TLS health with an explicit test CA, rejection without trust, wire-level OAuth catalog/challenges, client registration persistence, concurrent-instance refusal, clean shutdown and key-loss refusal.

Those are local/CI deployment tests. DSM agent controls, supported-device install/upgrade/ACL testing, approved public hosting, real ChatGPT linking/revocation and product acceptance remain required. Sign in with ChatGPT is not supplied by this first-party gateway session.

Runtime references checked 2026-10-01: [Node.js HTTPS](https://nodejs.org/api/https.html), [Node.js 22 TLS](https://nodejs.org/docs/latest-v22.x/api/tls.html), [Node.js connection limits](https://nodejs.org/docs/latest-v22.x/api/net.html#servermaxconnections), [SQLite exclusive locking](https://www.sqlite.org/pragma.html#pragma_locking_mode).
