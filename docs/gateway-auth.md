# Gateway authorization and device pairing implementation

`packages/gateway` implements durable OAuth protocol and device-pairing services. It is not a deployed gateway or a completed ChatGPT account connection. Browser login/consent routes, the outbound relay agent, approved HTTPS hosting, DSM integration and a real ChatGPT client test remain required. No gateway endpoints are enabled by the NAS CLI.

## OAuth protocol

The SDK-backed router provides authorization-server discovery, path-specific protected-resource metadata, public-client DCR, authorization-code exchange with S256 PKCE, refresh and revocation. It advertises only the `none` client-authentication method it supports. CIMD/private-key JWT clients are not advertised.

Callbacks are an exact HTTPS deployment allowlist; copy the actual callback from the ChatGPT management page. There is no wildcard callback or invented OpenAI client ID. Issuer identification is advertised because success, denial and SDK-generated error redirects include the configured exact `iss` value. State and the resource identifier are bound throughout authorization and token exchange.

Tokens are random opaque credentials, checked against gateway state on every request. They are bound to issuer, resource, OAuth client, stable first-party subject, paired device and selected folder IDs. They are unrelated to OpenAI ID/inference tokens. Database keys use an HMAC digest under a separate private gateway key. Raw authorization codes, access credentials, refresh credentials and device/browser pairing secrets are not stored in the database.

Codes expire after one minute and are atomically consumed with PKCE verification. Access credentials default to five minutes. Refresh credentials rotate on every exchange; replay of a used refresh credential revokes its grant, including sibling access/refresh credentials. Revocation checks occur on every request. Failed requests from a different client or resource cannot revoke a legitimate grant.

Folder removal immediately narrows existing grants. Per-folder policy versions prevent re-adding a folder from restoring an old grant's access. A fresh consent is required for the newly enabled folder. Device revocation invalidates active access and refresh credentials.

`authenticator()` returns the verified device ID as well as subject/scopes/roots. A file server must bind to that device explicitly; the HTTP server rejects device-scoped identities when no expected device is configured or when it differs. A multi-device gateway must select its relay channel from the verified token's device ID and recheck the grant after an in-flight response. Never attach one global file provider to all accounts.

## NAS ownership proof and browser sign-in

Pairing uses an Ed25519 key generated and retained on the NAS. Begin returns a private device polling credential and a separate browser user code; their roles cannot be exchanged. The browser claims the user code under a server-generated first-party session identifier. The NAS and browser display the same six-digit comparison. An authenticated DSM administrator must compare both screens and confirm before the agent signs.

The signed message binds the gateway issuer, NAS public key, label, folder IDs, fresh challenge, browser binding and comparison value. The NAS agent must compare the returned metadata to its local initiated request before signing. The gateway cannot finish browser sign-in until the NAS signature is valid. Browser completion and NAS approval are one-time operations. A stolen user code alone is insufficient; claiming it first can deny service until the owner starts a fresh pairing, so the comparison step must never be skipped.

The NAS key maps to an immutable first-party subject. Re-pairing cannot transfer it to a different signed-in account. Recovery using the same private key signs in to the same account; device revocation requires a fresh NAS/admin confirmation before connecting again. Browser routing must take its session/subject from secure server state, apply exact Origin and CSRF protection, rotate the session after successful pairing, and store cookies as `HttpOnly; Secure; SameSite=Lax; Path=/` with a `__Host-` name.

This supplies a NAS ownership-based first-party sign-in path. It does not claim to be Sign in with ChatGPT. OpenAI's website identity route currently requires selected-partner eligibility and provisioned OAuth client settings. A future optional identity adapter must verify discovery, state, nonce, PKCE, signatures, issuer, audience, expiration and stable subject without treating matching email as ownership proof.

## Storage and operation

Gateway state uses Node's `node:sqlite`, with synchronous atomic `BEGIN IMMEDIATE` transactions, full synchronization, foreign keys, a busy timeout, private process-owned directory/database, symlink rejection and disabled extension loading. The NAS server/core do not import SQLite. Use a gateway runtime of Node.js 22.18 or later, or tested Node.js 24. SQLite remains marked experimental in Node.js 22; assess that runtime dependency before production promotion.

Keep the 32-byte HMAC key in a separate private secret store and use the same key after restart. Key replacement invalidates credential lookups; it is not a seamless rotation protocol. Back up the private database and key consistently, protect backups as credentials and document recovery. A single durable database is supported; a horizontally distributed database/session design is a separate deployment requirement.

The library bounds dynamic clients, pending authorizations and pairing requests. Public gateway routing must additionally enforce Host, TLS/proxy provenance, body sizes, bounded rate/concurrency limits, secure sessions and no credential/content logging. The SDK router includes protocol endpoint rate limits and additional 16 KiB parsing bounds. Prune expired records periodically.

## Evidence

The test suite exercises HTTP metadata/DCR/PKCE/refresh/revocation, account/device/root isolation, code consumption, token-family reuse detection, expiration, restart persistence, private storage, issuer/audience mismatch, signature tampering, pairing expiry, wrong-browser completion, immutable NAS ownership and safe reconnection after revocation. Fixture-supplied owners validate the protocol; they do not prove production browser authentication or real ChatGPT integration.

Verified references (2026-09-30): [OpenAI MCP authentication](https://developers.openai.com/plugins/build/auth), [MCP authorization specification](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization), [OpenAI website identity](https://developers.openai.com/siwc/website), [Node SQLite API](https://nodejs.org/api/sqlite.html).
