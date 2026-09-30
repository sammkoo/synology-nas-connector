# Verification record

Date: **2026-09-30**. Local host: macOS arm64. Target runtime additionally exercised using **Node.js v22.23.3** from the npm Node runtime package; host Node.js v23.7.0 was used during initial development. This is a developer-preview validation record, not a NAS compatibility certification.

| Check | Observed result |
| --- | --- |
| `npm ci --ignore-scripts --offline` / locked dependencies | exact dependencies restored from local cache; lockfile included |
| `npm run typecheck` | passed |
| `npm test` under Node.js 22 | **15 tests passed, 0 failed** |
| `npm run build` | portable CommonJS bundle and static UI built |
| `npm run test:bundle` | official MCP client initialized the bundled stdio process, listed five tools and read a sample document |
| HTTP integration | official SDK client initialized, listed tools and read text through authenticated Streamable HTTP |
| File policy | traversal, symlinks, hidden/sensitive names, invalid UTF-8, binary and oversized text rejected; scan limits and pagination exercised |
| Auth/HTTP policy | token permissions, root grants, scope/provider failure, Host, Origin, request sizes and global rate limit exercised |
| `npm audit --omit=dev --audit-level=high` | 0 vulnerabilities reported at verification time |
| `npm run spk` | `.spk` built successfully with Node.js v22 dependency and package-user privileges |
| `npm run test:spk` | structure, script syntax, file modes, payload, checksum, static DSM launcher and byte-for-byte rebuild passed |
| UI browser check | dashboard rendered; ephemeral local test credential showed running read-only service and no exposed roots |
| Python build/smoke scripts | syntax parsed successfully |

## Unverified here

- Docker build and container smoke: no Docker CLI/daemon is installed on this host. A Linux GitHub Actions job builds the image, makes a real authenticated MCP read and verifies the mounted share rejects writes. That workflow has not been run on GitHub from this local scaffold.
- Linux descriptor traversal: implemented for DSM/Linux and covered by the same suite when run in Linux CI; local macOS exercises the documented portable fallback. Do not infer Linux test execution from this local report.
- DSM manual installation, package-account ACL behavior, lifecycle, shortcut, reboot and upgrade: require real NAS hardware. Two Node.js v22 runtime paths are checked at startup. An attempted read-only inspection of the vendor's public runtime SPK found a non-tar vendor container, so its runtime layout was not established by that attempt. Validate the path on the target NAS before promoting the package.
- Sign in with ChatGPT, MCP OAuth, public ChatGPT linking, relay and directory approval: planned, not implemented or tested. Official integration documentation was fetched and the distinction between identity and NAS authorization is recorded in `openai-integration.md`.
- Node.js 24 and GitHub-hosted workflows: configured in CI but not executed in this local session.

Run the recorded commands again on changes. The real-device release checklist is in `installation.md`. Artifacts and private local configuration are ignored by Git; no secrets or NAS documents are needed to rerun tests.
