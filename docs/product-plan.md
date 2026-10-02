# Product objective and acceptance evidence

The objective is a fully functional, simple, intuitive and secure open-source Synology NAS Connector for ordinary users, published to the owner's GitHub. The user's benchmark is the Google Drive experience in ChatGPT: one connection for discovery, document reads and edits, creation, organization and sharing. See the [capability acceptance matrix](google-drive-parity.md). Existing installations stay read-only by default; new capabilities require explicit consent.

Repository: https://github.com/sammkoo/synology-nas-connector

## Required end state

| Requirement | Evidence required before completion |
| --- | --- |
| GitHub source and development history | current source pushed and remote HEAD verified |
| Simple DSM installation | released SPK installed on supported x86_64 and ARM devices |
| DSM authentication and setup | existing administrator session verified; no copied bearer tokens or raw config editing |
| Folder consent | graphical share selection; least-privilege ACL guidance/checks; configuration persists and revocation takes effect |
| ChatGPT connection | a complete real account-linking/consent flow, discoverable protected MCP resource, scoped credentials and revocation |
| Reachability for ordinary home NAS users | tested outbound device connection/pairing to HTTPS gateway without inbound port forwarding |
| Sign in with ChatGPT | documented supported identity route tested on NAS deployment; no inferred loopback compatibility |
| Read-only tools | traversal/race/permission tests and real documents through a production-equivalent MCP transport |
| Intuitive UI | onboarding, status, folder management, connection/revocation and actionable errors tested in browser |
| Safe deployment | hardened process/container, TLS, secrets lifecycle, bounded requests, isolation of NAS and management credentials |
| Build and distribution | passing Linux CI, Docker tests, reproducible SPK and release downloads/checksums |
| User documentation | installation and recovery flows accurately describe the shipped UI and supported environments |

No broad completion claim is justified by a green unit suite alone. Hosting and real NAS availability are needed for the final gates. When those are unavailable, continue implementing and verifying independent product components and record the remaining gates explicitly.

## Implementation sequence

1. Publish the existing code and run its tests on Linux.
2. Build an authenticated DSM management bridge, durable configuration service and share-selection onboarding. The MCP file-access service stays unprivileged.
3. Implement user/device pairing, outbound relay and complete MCP OAuth with resource-bound, revocable grants. Keep identity, NAS consent and data transit separate.
4. Deploy an approved HTTPS gateway, test real ChatGPT linking and NAS reconnection/revocation behavior.
5. Verify device installation and upgrades, fix product-level failures, ship release artifacts and complete the acceptance audit above.

## Current checkpoint (2026-10-02)

Read-only build 0009 is installed on the test NAS; the actual ChatGPT connection, reads and folder revocation have passed. The v0.2 [PR 1](https://github.com/sammkoo/synology-nas-connector/pull/1) adds optional text creation and Drive links preserving permissions. [Linux/Docker CI](https://github.com/sammkoo/synology-nas-connector/actions/runs/36980927769) passed 114 Linux tests and a reproducible build 0010. Live creation, Drive mapping and new ChatGPT mutation consent remain pending. No broader NAS permissions have been applied. Google Drive parity is still a development target.

## Historical checkpoint (2026-10-01)

Published management, gateway/browser and relay checkpoints passed Linux CI. The operational gateway CLI/Docker target passed [run 36792812906](https://github.com/sammkoo/synology-nas-connector/actions/runs/36792812906) for `c83c463`, including verified TLS, durable private state and container restart. Build 0005 now wires DSM administrator actions to a NAS connection controller: public-only HTTPS destinations, explicit transit consent, comparison confirmation, persistent private identity/device binding, connection status, offline disconnection and signed gateway revocation. Backend tests use real TLS, not household documents. The NAS bundle excludes gateway SQLite. Build 0005 passed [Linux CI 36796866749](https://github.com/sammkoo/synology-nas-connector/actions/runs/36796866749) for `e6860f1`, including 85 tests on Node.js 22/24, reproducible SPK and both Docker runtime paths. The graphical installation guide now matches the shipped DSM setup; preview release downloads provide the tested SPK, checksum and source.

Remaining acceptance work: verify real DSM CGI/authentication and ACLs, install/upgrade/reboot the current SPK, deploy an approved public HTTPS gateway, test real ChatGPT discovery/consent/reads/revocation, validate the supported OpenAI identity route, and complete release/security/distribution review. The pending device upgrade requires acceptance of the specific liability waiver displayed by DSM; the Mac was locked on the last native check. These external gates do not prevent continued independent implementation. Do not mark the complete product achieved from local test evidence.
