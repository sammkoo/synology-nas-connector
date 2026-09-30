# OpenAI integration evidence

Verified against fetched official documentation on **2026-09-30**. Capabilities and rollout may change; follow these sources before enabling a production integration. This connector is an MCP server and does not call the OpenAI inference API.

## MCP access to NAS data

[OpenAI plugin authentication](https://developers.openai.com/plugins/build/auth) describes the MCP authorization contract: the connector is a protected resource, an authorization server issues user grants, and ChatGPT/Codex are MCP clients. Authenticated MCP integration uses OAuth authorization-code + PKCE S256, protected-resource metadata, authorization-server discovery, audience/resource binding and scope checks on every request. Supported client identification options include CIMD, dynamic registration and predefined clients. Use the exact callback shown by the connection management page rather than inventing a callback URL.

v0.1 implements only a local bearer-token verifier and an `Authenticator` contract for a later OAuth adapter. It does not advertise OAuth, emit fake OpenAI URLs or mark the NAS as linked. Static-token testing with a local MCP client is not production ChatGPT linking. Production deployment must implement and test the entire discovery/consent/token/revocation flow and current tool `securitySchemes`/authentication challenge requirements from the official guide.

## Sign in with ChatGPT

[Official registration and sign-in documentation](https://developers.openai.com/siwc/token-sharing-open-source/sign-in) now documents the open-source flow, including initial dynamic registration, a persistent host ID, PKCE/state/nonce, issued client-ID handling and ID-token validation. It specifies an HTTP loopback callback on **127.0.0.1**. In a DSM browser session on a laptop, that callback reaches the laptop, not the NAS. Therefore simply placing the local flow behind a DSM button is not a validated implementation. Evaluate the [website identity route](https://developers.openai.com/siwc/website) or a local companion using official guidance before implementation; the website documentation does not establish automatic NAS pairing.

[OpenAI's open-source integration article](https://developers.openai.com/cookbook/articles/sign-in-with-chatgpt) separates identity from optional eligible ChatGPT plan usage. Neither grants access to ChatGPT conversation history. NAS file-access grants are separate from identity and inference permissions. An OpenAI API access token is not a NAS access token, and sign-in does not solve network reachability.

We intentionally ship no partial login implementation: no callback listener, token exchange, OpenAI credential storage, fabricated identity claims, client registration or API calls. The UI describes this as planned. This avoids presenting a login URL as a complete integration.

## Network path and distribution

The current [MCP server build guide](https://developers.openai.com/plugins/build/mcp-server) and [Secure MCP Tunnel guide](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels) are references for the next phase. Direct remote access requires an approved reachable deployment; an outbound relay or supported private tunnel needs a separate trust and operational design. OAuth identity does not open NAT or pair a device automatically. No universal availability, directory approval or automatic Package Center distribution is assumed.

Document ownership, access-grant scope, retention, TLS termination and revocation before adding any relay. Do not label a TLS-terminating relay as end-to-end encrypted.
