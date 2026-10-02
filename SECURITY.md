# Security policy and threat model

v0.2 is read-only by default and adds separately gated creation/Drive-link tools to the developer preview for trusted local/self-hosted clients. Report vulnerabilities privately to the repository maintainer using GitHub private vulnerability reporting once enabled. Do not post tokens or private filenames in public issues. No maintainer address or hosted security service is assumed yet.

## Defaults

- Empty root allowlist; explicit root aliases; no physical paths in successful results or tool errors.
- Creation and Drive-link capabilities default off. `create_file` is additive, Linux-only, bounded and exclusive; it never overwrites, deletes, renames, creates folders or executes commands. `create_drive_link` preserves existing permissions. There are no generic upload, shell, DSM administration or permission-edit tools.
- Loopback HTTP, authentication for all MCP requests and status, exact Host/Origin allowlists, no wildcard CORS or trusted forwarded headers.
- Owner-only token file, at least 32 base64url characters, constant-time digest comparison; random 256-bit generated secrets. Secrets are excluded from Git, Docker build context and SPK.
- Symlinks and special files refused; traversal, absolute paths, backslashes and ambiguous path components rejected. Linux/DSM opens every component with `O_NOFOLLOW` through pinned `/proc/self/fd` directory descriptors.
- Dotfiles, `@` directories, recycle/snapshot directories, selected credential names and credential/database extensions refused. Deny rules apply to reads, listings, creation and sharing; administrators can add denied names but cannot remove built-in denies.
- Strict UTF-8 and binary/control-character rejection. Supported extensions only; maximum 256 KiB input by default, at most 500 returned lines. Output can still contain a long line within the byte limit.
- Bounded scans, maximum depth, cooperative time/cancellation checks, request body limit, global request budget and HTTP concurrency ceiling. No request payload, filenames, content or token logging. Liveness endpoint has no folder data.
- DSM package-user privileges; Docker drops capabilities and default mounts remain read-only. The optional development override makes only a dedicated test mount writable. DSM ACLs are never changed by the application.

## Boundaries and residual risks

Read-only access still discloses content to the connected MCP client. The local bearer token grants the current configured capabilities of all roots to its holder until rotation and restart; it is not a per-user OAuth permission model. Stdio inherits the spawning OS process's trust. Protect the configuration and token from other local users.

The portable non-Linux development fallback checks path components, real paths and final descriptor inode identity. Node's portable path APIs cannot provide an atomic `openat` walk; concurrent ancestor renames by an adversarial local writer may race these checks. Use Linux/DSM descriptor access with trusted root ancestors and restrict local writers. Even descriptor-pinned directories can be renamed after they are opened. The service operates on objects it opened under the permitted tree; it is not a continuous namespace revocation mechanism. Restart after changes to root grants. Files deliberately hard-linked into a selected root count as content in that root. Share ACLs/read-only container mounts remain the OS boundary.

Scan time limits are checked between filesystem operations; a stalled NAS filesystem call is not interrupted by a JavaScript deadline. Large/deep scans return `truncated`, and inaccessible child directories are counted. Directory ordering can change between requests. Use narrower roots/subdirectories where needed.

Filename/extension deny rules are defense in depth, not proof that a document contains no secrets. Keep backups, databases, credential directories and package `var` outside shared roots. A plain text document may contain malicious instructions; MCP responses explicitly classify file contents as untrusted data and the server instructions tell clients not to execute them. Client-side instruction handling is still required.

The DSM dashboard uses the authenticated CGI bridge, exact administrator-group validation and a separate private HMAC/CSRF channel. The standalone local dashboard uses bearer auth. Both use CSP and `textContent`. NAS gateway pairing and disconnection require that administrator channel; no DSM cookie, MCP token, private NAS identity or pairing polling credential is sent to the gateway or exposed to browser JavaScript. The gateway sees requested file data in transit; there is no E2E encryption. The OpenAI identity flow remains unimplemented.

The separate gateway implements MCP OAuth, per-principal grants, revocation, TLS termination/proxy checks and request limits. Before production use, validate deployed TLS/callbacks, operator privacy/logging policy, real ChatGPT integration and DSM authentication/ACLs; undergo security review and real DSM testing. Do not represent the local-token preview as a public ChatGPT plugin.

## NAS connection state

Gateway addresses must be canonical HTTPS origins. The shipped NAS controller rejects private, loopback, reserved and transition addresses, validates every DNS answer, and supplies those validated answers directly to HTTP/WSS sockets. Redirects are disabled and certificates are verified. No UI trust bypass is provided. Optional custom DNS/CA settings exist only as library arguments for managed environments and test fixtures.

Pairing remains tied to its initiating DSM administrator and unchanged folder-provider object. Approval signs the exact gateway, NAS identity, label, root IDs, browser binding, challenge and comparison; a fresh poll must match the displayed proof. A replaced/missing saved key prevents automatic restoration. Private state writes are atomic and synced; disconnection stops transport before writing disabled state and sends a timestamped, nonce-bound NAS signature to revoke gateway grants. Offline revocation stays pending and is retried on service restart or by the administrator. If storage cannot be replaced or removed, the API explicitly reports `DISCONNECT_NOT_PERSISTED`; the stopped process cannot guarantee that old enabled state will stay disabled after a restart.

## Mutation and Drive boundaries

Read/create/share scopes are distinct. Existing read-only grants never gain writes. NAS capability changes increment the folder policy generation; disabling/re-enabling cannot restore an old grant. All selected folders must support each requested mutation scope before consent is accepted. A write asks the gateway to revalidate the current token/folder grant before the NAS commits, followed by another NAS policy check. Revocation after the commit decision cannot undo an already authorized operation. Lost delivery returns `WRITE_RESULT_UNKNOWN`; the connector never automatically retries a mutation. See [the write contract](docs/create-and-drive-links.md).

The package's optional Read/Write OS permission can permit more than its exposed create-only tool. Restrict it to a dedicated share. Created files use mode 0600; test inherited Synology ACLs and Drive indexing before sharing. Trusted root ancestors and local writers remain required even with pinned descriptors.

Drive uses a dedicated non-administrator NAS account with least-privilege team-folder access. Its password is accepted only by authenticated administrator management, sent through the signed loopback bridge to the configured NAS's HTTPS login API, and never persisted or sent to the gateway/OpenAI. Owner-only, symlink-refusing session files stay in private package state. A changed Drive account first disables existing sharing capabilities, even if subsequent credential saving fails. REST redirects and TLS bypass are prohibited; API bodies and response bodies are bounded, and all errors are sanitized. The configured API origin is trusted administrator input, never an MCP argument.

Drive metadata must match both the exact virtual team-folder path and physical NAS file path before link creation by file ID. Links must use HTTPS, the configured trusted origin and the documented `/d/f/` form. Missing/incompatible metadata rejects the request. This is defense in depth, not an atomic filesystem/Drive transaction; trusted local writers and correct Drive folder mapping remain necessary.

A link does not receive new permissions from this implementation. Existing public or editable Drive permissions remain in effect. Folder revocation stops new connector operations but does not revoke existing Drive links or remove created files. Recipients and link access must be managed in Drive. Vendor SDK/documentation and API specifications are not redistributed with this source.
