# Product objective and acceptance evidence

The objective is a fully functional, simple, intuitive and secure open-source Synology NAS Connector for ordinary users, published to the owner's GitHub. The target is the complete product, not merely a local MCP demo. The first data capabilities remain read-only.

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

## Current checkpoint (2026-10-01)

Published management build `0002` and gateway-protocol build `0003` passed Linux CI (Node.js 22/24), Docker runtime and reproducible SPK checks. The gateway browser control plane now implements durable first-party sessions, NAS proof-based sign-in, explicit folder consent, cancellation, sign-out and disconnection. Local HTTP and browser fixtures verify those components. The NAS-facing SPK has no gateway pairing/relay agent yet. Implement outbound data transport and its DSM controls next; do not equate these control-plane checks with a deployed ChatGPT connection. The real NAS upgrade also awaits acceptance of the specific liability consent displayed by DSM.
