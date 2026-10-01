# Security policy and threat model

v0.1 is a read-only developer preview for trusted local/self-hosted clients. Report vulnerabilities privately to the repository maintainer using GitHub private vulnerability reporting once enabled. Do not post tokens or private filenames in public issues. No maintainer address or hosted security service is assumed yet.

## Defaults

- Empty root allowlist; explicit root aliases; no physical paths in successful results or tool errors.
- No write/delete/rename/upload/shell/DSM-login tools. The core only opens files with read flags.
- Loopback HTTP, authentication for all MCP requests and status, exact Host/Origin allowlists, no wildcard CORS or trusted forwarded headers.
- Owner-only token file, at least 32 base64url characters, constant-time digest comparison; random 256-bit generated secrets. Secrets are excluded from Git, Docker build context and SPK.
- Symlinks and special files refused; traversal, absolute paths, backslashes and ambiguous path components rejected. Linux/DSM opens every component with `O_NOFOLLOW` through pinned `/proc/self/fd` directory descriptors.
- Dotfiles, `@` directories, recycle/snapshot directories, selected credential names and credential/database extensions refused. Deny rules apply to reads and listings; administrators can add denied names but cannot remove built-in denies.
- Strict UTF-8 and binary/control-character rejection. Supported extensions only; maximum 256 KiB input by default, at most 500 returned lines. Output can still contain a long line within the byte limit.
- Bounded scans, maximum depth, cooperative time/cancellation checks, request body limit, global request budget and HTTP concurrency ceiling. No request payload, filenames, content or token logging. Liveness endpoint has no folder data.
- DSM package-user privileges; Docker drops capabilities and uses OS-enforced read-only mounts.

## Boundaries and residual risks

Read-only access still discloses content to the connected MCP client. The local bearer token grants all configured roots to its holder until rotation and restart; it is not a per-user OAuth permission model. Stdio inherits the spawning OS process's trust. Protect the configuration and token from other local users.

The portable non-Linux development fallback checks path components, real paths and final descriptor inode identity. Node's portable path APIs cannot provide an atomic `openat` walk; concurrent ancestor renames by an adversarial local writer may race these checks. Use Linux/DSM descriptor access with trusted root ancestors and restrict local writers. Even descriptor-pinned directories can be renamed after they are opened. The service operates on objects it opened under the permitted tree; it is not a continuous namespace revocation mechanism. Restart after changes to root grants. Files deliberately hard-linked into a selected root count as content in that root. Share ACLs/read-only container mounts remain the OS boundary.

Scan time limits are checked between filesystem operations; a stalled NAS filesystem call is not interrupted by a JavaScript deadline. Large/deep scans return `truncated`, and inaccessible child directories are counted. Directory ordering can change between requests. Use narrower roots/subdirectories where needed.

Filename/extension deny rules are defense in depth, not proof that a document contains no secrets. Keep backups, databases, credential directories and package `var` outside shared roots. A plain text document may contain malicious instructions; MCP responses explicitly classify file contents as untrusted data and the server instructions tell clients not to execute them. Client-side instruction handling is still required.

The DSM dashboard uses the authenticated CGI bridge, exact administrator-group validation and a separate private HMAC/CSRF channel. The standalone local dashboard uses bearer auth. Both use CSP and `textContent`. NAS gateway pairing and disconnection require that administrator channel; no DSM cookie, MCP token, private NAS identity or pairing polling credential is sent to the gateway or exposed to browser JavaScript. The gateway sees requested file data in transit; there is no E2E encryption. The OpenAI identity flow remains unimplemented.

The separate gateway implements MCP OAuth, per-principal grants, revocation, TLS termination/proxy checks and request limits. Before production use, validate deployed TLS/callbacks, operator privacy/logging policy, real ChatGPT integration and DSM authentication/ACLs; undergo security review and real DSM testing. Do not represent the local-token preview as a public ChatGPT plugin.

## NAS connection state

Gateway addresses must be canonical HTTPS origins. The shipped NAS controller rejects private, loopback, reserved and transition addresses, validates every DNS answer, and supplies those validated answers directly to HTTP/WSS sockets. Redirects are disabled and certificates are verified. No UI trust bypass is provided. Optional custom DNS/CA settings exist only as library arguments for managed environments and test fixtures.

Pairing remains tied to its initiating DSM administrator and unchanged folder-provider object. Approval signs the exact gateway, NAS identity, label, root IDs, browser binding, challenge and comparison; a fresh poll must match the displayed proof. A replaced/missing saved key prevents automatic restoration. Private state writes are atomic and synced; disconnection stops transport before writing disabled state and sends a timestamped, nonce-bound NAS signature to revoke gateway grants. Offline revocation stays pending and is retried on service restart or by the administrator. If storage cannot be replaced or removed, the API explicitly reports `DISCONNECT_NOT_PERSISTED`; the stopped process cannot guarantee that old enabled state will stay disabled after a restart.
