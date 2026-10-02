# Outbound NAS relay implementation

`packages/relay` and `packages/gateway` implement an outbound WSS connection and the gateway `/mcp` resource. They are exercised through real loopback TLS and the official MCP SDK client. Build 0005 connects the DSM administrator bridge to a persistent NAS connection controller; explicit pairing enables the agent. The [gateway service](gateway-deployment.md) supplies a native CLI and Docker target. No public deployment, release or real ChatGPT connection is implied.

## Ownership and data path

1. An administrator selects folders on the NAS. The same `NasFiles` policy used locally supplies the outbound agent; physical paths stay on the NAS.
2. The NAS retains a private Ed25519 identity. The existing pairing protocol associates its public key with an immutable first-party owner after the browser/NAS comparison and administrator confirmation described in [gateway authorization](gateway-auth.md).
3. The agent opens `wss://<configured-gateway>/agent/relay` with subprotocol `nas-relay.v1`. TLS certificate verification is always enabled. Redirects and WebSocket compression are disabled.
4. The gateway accepts only a paired, active key. It sends a fresh nonce and connection UUID; the NAS signs the exact issuer, nonce, connection, public key and canonical folder manifest. A captured signature cannot authenticate another socket. Duplicate active connections for one device are rejected.
5. OAuth consent issues a grant for one verified owner/device and explicit folder IDs. For an MCP call, the gateway selects the channel by that verified device, checks scope and folder grants, and sends one of the five read operations or a separately scoped mutation. The NAS applies its own current filesystem policy too.
6. The gateway validates result shape, root and requested file path, and revalidates OAuth immediately before and after the read. Device or grant revocation during a read prevents the response from reaching the client. A stale channel proxy cannot silently switch to a reconnected device.

There is no arbitrary file command, shell execution, write tool, content index or upstream inference call. Operations and strict Zod schemas live in `packages/core/src/operations.ts` and are shared with local MCP. Document text is marked `untrusted-document-content`.

Folder policy updates travel on the authenticated channel. Removing a folder narrows existing grants; re-adding it requires fresh consent. A source/provider replacement during an in-flight read discards the old result. The agent checks manifest changes every second and reconnects with bounded exponential backoff and jitter. Local source changes must replace the provider object, as the management service does, rather than mutate a provider behind an in-flight operation.

## Library wiring

An operator-provided HTTPS listener can use the runtime as follows; the issuer/resource, exact callback allowlist, durable store and private HMAC key must already be configured on `GatewayOAuthProvider`:

```ts
import { createServer } from 'node:https';
import { createGatewayRuntime } from '../packages/gateway/src/index.js';

const { app, relay } = createGatewayRuntime(oauth);
const listener = createServer({ key: tlsKey, cert: tlsCertificate }, app);
relay.attach(listener);
listener.listen(port, listenAddress);
```

The NAS side, after confirmed ownership pairing, uses the same private key:

```ts
import { loadOrCreateRelayIdentity, NasRelayAgent } from '../packages/relay/src/index.js';

const identity = await loadOrCreateRelayIdentity(privateIdentityDirectory);
const agent = new NasRelayAgent({
  issuer: 'https://gateway.example/',
  privateKey: identity.privateKey,
  source: () => currentNasFiles,
});
agent.start();
// Graceful shutdown: await agent.stop();
```

These examples show library composition; use the [gateway CLI and Docker instructions](gateway-deployment.md) for the complete server command. The agent's `connect()` performs one connection attempt; `start()` manages reconnection. State observers expose only `stopped`, `connecting`, `online` and `offline`. The private directory must be process-owned and mode `0700`, and `identity.key` mode `0600`; symlink/unsafe ownership/permission replacements fail closed. Never rotate the key silently after a read error or lose it during a package upgrade.

The normal agent uses the OS trust store. The optional `trust.ca` and DNS lookup are for explicitly managed trust environments and isolated tests; there is no insecure certificate-validation switch. The NAS connection controller wires those components together and supplies a public-only DNS lookup for all HTTP and WSS connections. Ordinary users still need an approved gateway and device validation.

## Bounds and failure behavior

| Boundary | Implemented bound |
| --- | --- |
| Gateway HTTP and WS upgrade traffic | shared 600/minute globally, 120/minute per IP; exact Host and TLS/trusted proxy provenance |
| Agent handshake | 10 seconds, 16 pending handshakes, at most 256 authenticated device channels |
| WS frames | 4 MiB NAS responses; 16 KiB gateway commands and unauthenticated handshake messages; 64 fragments, 32 buffered chunks; compression disabled |
| Authenticated NAS messages | 600/minute per channel; heartbeat every 20 seconds |
| Gateway reads | 32 pending globally, four per device; default 15-second deadline |
| Agent filesystem work | four actual operations by default, retained until OS I/O finishes even after cancellation or reconnect |
| HTTP MCP | 32 active requests, 16 KiB input, 40-second response deadline; stateless JSON transport |
| Manifest | at most 20 unique aliases, bounded labels; no physical paths |
| Result | at most 200 entries, text bounded by core and frame size; errors contain codes, no OS paths or file bodies |

JSON escaping can make a permitted core text response exceed the frame cap; that response becomes `RESULT_TOO_LARGE`. The default core text limit is 256 KiB. Cancellation discards eventual results but cannot guarantee that a kernel or network filesystem read stops immediately. Retaining agent slots prevents repeated cancellations from launching unlimited underlying I/O. Stopping the agent aborts work and closes its socket; process shutdown policy must still account for potentially blocked filesystem operations.

HTTP and WS share one exact-IP proxy policy. A trusted proxy must overwrite forwarded protocol and client IP, enforce connection/time budgets and bind its upstream privately. Browser Origin, cookies and bearer Authorization are rejected on WS upgrades. Browser sessions are not NAS channel credentials. The public health response reports attachment, never device IDs, users or an inventory of online NAS devices.

## Privacy and remaining deployment work

TLS terminates at the gateway. It can see filenames, metadata and returned document text in memory; this is **not end-to-end encryption**. It stores owner/device keys, aliases/labels and grants, but the implementation does not persist, cache or log file contents. A real operator must configure body-free logs, crash reporting, retention, backups and monitoring accordingly. The NAS pairing private credential and identity key are never sent as MCP bearer credentials.

The operational gateway CLI/container now provides private initialization, state/key binding, exclusive storage, listener/socket limits and graceful shutdown. Remaining gates include real DSM session/package validation, production HTTPS hosting and resource validation, reconnect/upgrade tests on real NAS hardware, and current ChatGPT client linking/revocation. Single-process SQLite and in-memory channels are supported; horizontal replication is not implemented.

## Evidence

`tests/relay.test.ts` uses disposable test keys and a test certificate with certificate validation enabled. It exercises all five tools through actual HTTPS/WSS and the official MCP client, raw-wire OAuth tool metadata, anonymous discovery without data access, two owners/devices with identical aliases, grant/device/source revocation during reads, cancellation capacity, malicious result roots/paths, private identity permissions, unpaired keys, wrong CA, browser upgrade credentials, handshake replay, reconnection after restart, manifest removal/re-addition, deadlines and malformed-upgrade capacity recovery. It does not use household NAS documents or disable TLS verification.

Verified references (2026-10-01): [OpenAI MCP authentication](https://developers.openai.com/plugins/build/auth), [ws API](https://github.com/websockets/ws/blob/master/doc/ws.md), [ws upgrade authentication example](https://github.com/websockets/ws#client-authentication).

## v0.2 mutations

Signed manifests optionally include creation and Drive-link capabilities; legacy read-only manifests keep their original signature encoding. Write calls include a matching capability grant. Before a mutation commits, the NAS sends a commit request and awaits current gateway authorization. It checks its local provider again after approval. Only a matching pending mutation may request approval, and approval is one-time. Read replies still undergo post-operation authorization and policy checks. A lost/invalid mutation reply reports `WRITE_RESULT_UNKNOWN` instead of claiming the write failed. See [mutation setup and limits](create-and-drive-links.md).
