# Verification record

Latest local verification: **2026-10-01** (MCP authentication rechecked 2026-10-01; other integration references fetched 2026-09-30). Local host: macOS arm64. Target runtime additionally exercised using **Node.js v22.23.3** from the npm Node runtime package; host Node.js v23.7.0 was used during initial development. This is a developer-preview validation record, not a NAS compatibility certification.

| Check | Observed result |
| --- | --- |
| `npm ci --ignore-scripts --offline` / locked dependencies | exact dependencies restored from local cache; lockfile included |
| `npm run typecheck` | passed |
| `npm test` under Node.js 22 | **64 tests passed, 0 failed** after actual TLS relay, cancellation, reconnect, revocation and wire-level authentication additions |
| `npm run build` | portable CommonJS bundle and static UI built |
| `npm run test:bundle` | official MCP client initialized the bundled stdio process, listed five tools and read a sample document |
| HTTP integration | official SDK client initialized, listed tools and read text through authenticated Streamable HTTP |
| File policy | traversal, symlinks, hidden/sensitive names, invalid UTF-8, binary and oversized text rejected; scan limits and pagination exercised |
| Auth/HTTP policy | token permissions, root grants, scope/provider failure, Host, Origin, request sizes and global rate limit exercised |
| `npm audit --omit=dev --audit-level=high` | 0 vulnerabilities reported at verification time |
| `npm run spk` | `.spk` built successfully with Node.js v22 dependency and package-user privileges |
| `npm run test:spk` | structure, script syntax, file modes, payload, checksum, static DSM launcher and byte-for-byte rebuild passed |
| UI browser check | original token dashboard rendered; new DSM onboarding exercised with a disposable local fixture: save selection, list sample entry, revoke selection and verify disabled check controls. This fixture does not authenticate a real DSM session |
| Python build/smoke scripts | syntax parsed successfully |

## Remote and device evidence; remaining gates

- Baseline Linux CI: [run 36676696976](https://github.com/sammkoo/synology-nas-connector/actions/runs/36676696976) passed for commit `8aef10f` under Node.js 22 and 24, including Linux file-policy tests, Docker build/runtime MCP read with an OS read-only mount, and SPK validation. No Docker daemon is installed on the local Mac. Later commits require their own green run.
- Real DSM inspection: DS224+, DSM **7.4.1-90080**, 6144 MB RAM, Node.js package **22.22.3-1010**. Package Center reported connector **0.1.0-0001 Running** on Volume 1. The original launcher produced 404; navigating to the documented `/webman/3rdparty` path showed the setup page. These observations establish installation/service-state/UI behavior only, not successful NAS tool execution.
- DSM package-account ACL behavior, new CGI management session, reboot, upgrade and real MCP reads: still require device testing. Two Node.js v22 runtime paths are checked at startup; the working baseline service is evidence that at least one matched on DS224+, not certification of every platform.
- Sign in with ChatGPT, public ChatGPT linking and directory approval: not implemented or tested. The MCP OAuth protocol, browser consent and outbound relay libraries are implemented and locally tested; DSM agent/pairing controls, operational deployment and real account linking remain required. Official integration documentation was fetched and the distinction between identity and NAS authorization is recorded in `openai-integration.md`.
- New management build: HMAC tampering/replay/address checks, administrator/origin restrictions, CSRF, durable root selection, stale revisions, live-session revocation, in-flight read revocation and credential-preserving package migration are covered by the added test suite. Real DSM CGI execution and account linking remain unverified.
- Build `0002` Linux CI: [run 36679752569](https://github.com/sammkoo/synology-nas-connector/actions/runs/36679752569) passed for commit `3b93b5f`, including Node.js 22/24, Docker runtime and reproducible SPK validation. Build `0003` adds gateway protocol tests and corrected DSM checkbox/select styling; its local 41-test check, bundle smoke test and reproducible SPK check passed. Its DSM UI fixture saved a folder and listed `welcome.txt` in a browser.
- Gateway protocol build: [run 36782250092](https://github.com/sammkoo/synology-nas-connector/actions/runs/36782250092) passed for commit `6712b83` under Linux Node.js 22/24, including Docker runtime, dependency audit and SPK validation.
- Gateway browser implementation: native code entry, comparison and simulated-NAS signed sign-in reached the consent screen in an isolated local browser fixture; root checkboxes start unchecked. HTTP tests cover first-party sessions, Origin/CSRF, handle binding, private state, revocation, logout, restart and cancellation. Browser testing found and corrected a `no-referrer` policy that changed form Origin to null; the final fixture observed its real local Origin and retained rejection of null Origin. TLS/cookies are simulated only in that disposable browser preview shim; the separate relay suite uses real TLS and certificate verification. Real DSM pairing and deployed ChatGPT linking are still unverified. See `gateway-auth.md`.


- Gateway browser CI: [run 36784826666](https://github.com/sammkoo/synology-nas-connector/actions/runs/36784826666) passed for commit `b0df6ac`, including Linux Node.js 22/24, Docker runtime, audit and SPK validation.
- Build `0004` adds shared strict operations, cancellable reads and preserved wire-level OAuth tool metadata. Its 64-test check, bundle smoke test and reproducible SPK verification passed locally. `tests/relay.test.ts` covers actual HTTPS/WSS, all tools, two NAS with identical aliases, revocation during reads, malicious responses, bounded cancelled I/O, wrong trust, replay, reconnect and deadline behavior. See [relay evidence](relay.md). Remote CI for this change must be checked after publication.

Run the recorded commands again on changes. The real-device release checklist is in `installation.md`. Artifacts and private local configuration are ignored by Git; no secrets or NAS documents are needed to rerun tests.
