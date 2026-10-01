# Synology NAS Connector for ChatGPT

Independent, MIT-licensed **v0.1 developer preview**. A read-only MCP server for selected NAS folders, a portable Node.js core, a DSM dashboard, and a reproducible DSM `.spk` builder. Local operation requires no OpenAI API key or DSM password. Optional gateway pairing enables outbound HTTPS/WSS for ChatGPT access; the gateway sees requested data in transit. No telemetry or inference calls are made.

**Implemented:** folder listing, filename search, metadata, bounded UTF-8 document reads; MCP stdio and stateless Streamable HTTP; bearer-token development authentication; DSM package lifecycle. Build 0005 includes an authenticated management bridge, graphical share selection, live policy revocation, administrator-confirmed gateway pairing, connection status and signed disconnection, pending real DSM CGI validation.

**Remaining product gates:** Real DSM installation/authentication, approved public gateway hosting, real ChatGPT linking, Sign in with ChatGPT and public distribution. The NAS UI provides gateway pairing controls; it does not claim an implemented OpenAI identity flow. A `.spk` build is not proof of installation compatibility; real DSM testing remains a release gate.

Development now includes [durable gateway OAuth, NAS ownership pairing and browser consent](docs/gateway-auth.md), plus an [outbound WSS relay and protected MCP resource](docs/relay.md). These components and the NAS connection controller are tested together through real local TLS. The gateway browser has first-party sessions, a folder consent screen and disconnection controls. A [native/Docker gateway service](docs/gateway-deployment.md) now supplies private initialization, listener limits and restart-safe state. Public HTTPS hosting, device validation and real ChatGPT linking remain required.

## DSM setup and downloads

Download the `.spk` and matching checksum from the [build 0005 preview](https://github.com/sammkoo/synology-nas-connector/releases/tag/v0.1.0-preview.5), then follow the [graphical installation guide](docs/installation.md). DSM setup uses your existing administrator session, folder selection and comparison-code pairing; no raw JSON or copied bearer token is needed. You need a separately deployed trusted HTTPS gateway for remote ChatGPT access. This preview still requires real-device and real-account validation.

## Quick start

Use Node.js 22 (Node.js 24 is also covered by CI), Python 3 for packaging and OpenSSL for disposable TLS test certificates. Docker installs OpenSSL only in its build/test stage.

```sh
npm ci
npm run init
```

Edit `.local/config.json`; new configurations have **no roots**. Add only specific folders:

```json
"roots": [{"id": "documents", "label": "Documents", "path": "/absolute/path/to/selected/folder"}]
```

Keep the token file private, owned by the service user, with mode `0600`. The generated configuration binds to `127.0.0.1` and permits only the two local dashboard origins.

```sh
npm run check
npm run build
node dist/server.cjs --config .local/config.json
```

Open `http://127.0.0.1:8787`. Enter the locally generated token from `.local/token` to see service status and allowed folder aliases. Copy it locally; never commit it. The dashboard stores no credentials. Root access is configured by editing the private config and restarting, rather than granting file permissions from a browser.

## Local MCP clients

Use an absolute server and config path in a client that supports stdio:

```json
{
  "mcpServers": {
    "synology-nas": {
      "command": "node",
      "args": ["/absolute/path/to/dist/server.cjs", "--stdio", "--config", "/absolute/path/to/.local/config.json"]
    }
  }
}
```

Stdio trusts the local spawning process and OS identity; it does not require a bearer token. It uses the same root policy and core as HTTP and DSM. This configuration example is for clients that accept this format; it is not a claimed ChatGPT desktop configuration.

HTTP clients use `POST /mcp` with `Authorization: Bearer <local-token>` and MCP transport headers. There is no legacy SSE transport. Static tokens are for local/self-hosted development, not a completed public ChatGPT authentication flow.

| Tool | Inputs | Result |
| --- | --- | --- |
| `list_roots` | none | allowed root IDs and labels |
| `list_directory` | `rootId`, relative `path`, `limit`, `offset` | entries, `nextOffset`, partial-coverage indicators |
| `search_files` | `rootId`, filename `query`, `limit` | matching files, partial-coverage indicators |
| `get_metadata` | `rootId`, relative `path` | type, bytes, modification time |
| `read_text` | `rootId`, relative `path`, `startLine`, `maxLines` | text, line range, trust marker |

Text support: `.txt`, `.md`, `.csv`, `.tsv`, `.json`, `.xml`, `.yaml`, `.yml`, `.log`, `.rst`, strictly UTF-8. PDF, DOCX, spreadsheets, OCR and archives are outside v0.1. Search matches filenames only and does not index file contents. Default directory scans stop at 5,000 examined entries; tool output is capped at 200 entries. Use `nextOffset` for another directory page. `scanTruncated` means the scan budget stopped discovery; further pages cannot recover unscanned entries. Pagination is not a snapshot if the directory changes. There is no persistent search index.

## Docker

After generating `.local`, set `http.host` to `0.0.0.0` **inside the container config**, and use `/data/documents` as the root path. Keep `tokenFile` as `token`, allowed hosts as `127.0.0.1`/`localhost`, and the local dashboard origins. Compose publishes only on the host loopback interface and mounts both config and documents read-only.

```sh
NAS_UID=$(id -u) NAS_GID=$(id -g) docker compose up --build
```

The selected UID/GID must own `.local/token` and be able to traverse the mounted directories. Linux Docker uses descriptor-relative file access. The image runs without root, capabilities or a writable root filesystem. No Docker daemon is required for native local development.

## Gateway service

The separate gateway has its own private state/key and supports direct HTTPS or a loopback TLS proxy. Its CLI and Docker target are tested independently of DSM. Follow [gateway deployment](docs/gateway-deployment.md) to initialize with a real issuer/callback allowlist, install TLS files and start `dist/gateway.cjs`. The DSM UI can now pair with that gateway and show the protected MCP URL after its connection is online. Validate on a test NAS before connecting real documents.

## DSM package

```sh
npm run build
npm run spk
npm run test:spk
```

Output: `artifacts/SynologyNASConnector-0.1.0-0006-noarch.spk` and its SHA-256 checksum. See [DSM management preview](docs/dsm-management.md) for the setup flow and device-validation limits. Build 0006 adds complete CGI status headers and a process-output smoke test; real DSM HTTP compatibility remains unverified. It bundles the outbound relay and DSM pairing controls, with no gateway SQLite in the NAS bundle. A fresh installation has no outbound connection; only explicit administrator pairing enables it. A previously paired installation resumes its saved connection after restart or upgrade. Upgrade preserves the private identity and connection record. The [installation guide](docs/installation.md) provides graphical DSM setup and separate local diagnostics.

## Project layout

```text
packages/core/      filesystem policy, limits, config; no DSM or MCP dependency
packages/auth/      local-token authentication and future OAuth adapter contract
packages/management/ signed bridge, share catalog, private config and connection controller
packages/gateway/   OAuth, signed pairing, browser consent and deployment runtime
packages/relay/     persistent NAS identity, outbound WSS agent and bounded protocol
apps/server/        MCP tool definitions, HTTP transport, stdio CLI
apps/gateway/       gateway initialization, service and verified local health CLI
apps/dsm-ui/        static dashboard served locally and packaged for DSM
apps/dsm-bridge/    authenticated DSM CGI bridge; no DSM credentials forwarded
packaging/synology/ INFO, privilege policy, lifecycle scripts and DSM launcher
scripts/           portable bundle, SPK builder, package and Docker verification
tests/             policy, authentication and real MCP SDK client tests
docs/              architecture, installation, integration evidence, threat model
```

GitHub Actions tests on Linux with Node.js 22/24, builds and verifies `.spk`, uploads package artifacts, audits production dependencies, and builds/smoke-tests Docker. Source is published at [sammkoo/synology-nas-connector](https://github.com/sammkoo/synology-nas-connector). No release is published automatically; production promotion requires the [product acceptance evidence](docs/product-plan.md).

See [architecture](docs/architecture.md), [verified OpenAI integration points](docs/openai-integration.md), [security](SECURITY.md), [verification record](docs/verification.md), and [contributing](CONTRIBUTING.md).
