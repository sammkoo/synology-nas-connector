# Optional file creation and Synology Drive links (v0.2 preview)

Existing configurations and OAuth grants do not gain write access on upgrade. Creation and links start disabled and need both a NAS folder capability and a fresh client consent. The package never changes DSM ACLs automatically.

| Tool | NAS capability | OAuth scopes | Behavior |
| --- | --- | --- | --- |
| `create_file` | `allowCreate: true` | `nas:read nas:create` | New UTF-8 text file only, up to 16 KiB, existing parent, no overwrite |
| `create_drive_link` | `allowShare: true` and connected Drive account | `nas:read nas:share` | Create/retrieve Drive link, preserve existing permissions |

Supported creation extensions: TXT, MD, CSV, TSV, JSON, XML, YAML, YML, LOG and RST. This does not generate PDF, Office documents or images. The tools cannot delete, rename, overwrite, create directories or execute programs. Creation uses Linux/DSM pinned directory descriptors, a private staging file, synchronized contents and exclusive hard-link publication. It fails on non-Linux systems; use Linux Docker for development.

## DSM setup

1. Keep ordinary folders read-only. Use a dedicated, disposable test share for the first write test.
2. To create files, grant the internal package account `SynologyNASConnector` Read/Write on **that share only**, then enable creation in the package dashboard. DSM Read/Write is broader than the exposed create-only tool; do not grant it on household archives or backups.
3. For Drive links, enable the same share as a team folder in Drive Admin Console. Use a separate non-administrator DSM account, restricted to that team folder, with Drive application access and the Drive permissions needed to share files. Do not reuse an administrator password. The documented v1 login contract has no MFA field; MFA-only account compatibility is not claimed.
4. In the package dashboard, enter your NAS's canonical HTTPS origin and that account's credentials. The password travels only over your DSM session and the signed loopback management bridge to the configured NAS's HTTPS Drive login API. It is not stored. A private owner-only Drive session file stays on the NAS, never on the gateway or in tool responses. Configure a valid NAS certificate; there is no TLS bypass. When the Drive session expires, reconnect it here.
5. Enable Drive links per selected folder. The service checks Drive's folder mapping and sharing capability before saving. If `dsm_path` or `display_path` cannot be verified, the feature stays disabled. A Drive account change resets all link capabilities and requires enabling them again.
6. Rescan the updated tools in your ChatGPT connection and review a new OAuth consent for the chosen NAS and folders. All folder boxes start unchecked. A read-only grant cannot create files or links.

Drive REST v1 requires DSM 7.2.2 nano3 or later and Drive Server 3.5.2 or later. Compatibility must be tested on each target NAS. This implementation maps only top-level DSM shares to their matching Drive team folders. My Drive, arbitrary file IDs supplied by clients, USB/network mounts and cross-NAS mapping are not supported.

New files have mode `0600`. Whether a separate Drive account can access them also depends on inherited DSM ACLs and Drive indexing. Verify those on the test share; do not broaden modes or ACLs globally to work around a failed test. Newly created files may need time to appear in Drive's index.

## What a Drive link means

This version calls the official Drive link-creation endpoint. It does **not** change any sharing permissions or enable anonymous access. Recipients need whatever access Drive already permits. If the file is already public in Drive, that existing policy still applies. The tool does not promise a viewer-only link, password, expiry or access restriction that the API has not set. Set those policies directly in Drive.

Only HTTPS `/d/f/…` links from the configured trusted origin are returned. If Drive produces HTTP links, configure its HTTPS sharing address. A separate sharing domain can be explicitly allowlisted in private `drive.linkOrigins`; it is never accepted from an MCP request. Session credentials remain tied to `drive.baseUrl` and are never sent to a sharing URL.

Removing a folder or disconnecting this connector prevents new tool operations. **It does not revoke an existing Drive link or delete a created file.** Manage existing links and recipient permissions in Synology Drive.

## Revocation and uncertain outcomes

NAS capability changes invalidate previous grants for that folder, including after re-enabling it. Before committing a mutation, the NAS requests fresh authorization from the gateway, which checks the current token and folder grant. The NAS checks its current policy again after approval. Revocation before that decision prevents publication. An action authorized at that decision can finish even if revocation happens immediately afterward; there is no atomic transaction spanning the NAS and gateway.

If a connection drops after dispatch, a deadline expires or durability/response delivery cannot be confirmed, `WRITE_RESULT_UNKNOWN` means the action might have happened. Do not automatically retry. Inspect the target path or Drive first. `FILE_EXISTS` never means the connector replaced that file. No write payload or Drive cookie is logged or stored by the gateway.

## Local development

Add a dedicated root to private `.local/config.json`:

```json
{"id":"write-test","label":"Write test","path":"/data/write-test","allowCreate":true}
```

Keep the existing roots without `allowCreate` and run:

```sh
NAS_UID=$(id -u) NAS_GID=$(id -g) docker compose -f compose.yaml -f compose.create.yaml up --build
```

Only the example write-test bind mount becomes writable. Local tokens and stdio trust their owner/process; NAS capabilities are still required. They do not provide separate human consent screens. Drive needs a real HTTPS NAS and a private session, so fixture contract tests alone are not proof of a working live Drive connection.

## Official references and distribution

Checked 2026-10-02: [Synology productivity APIs](https://www.synology.com/en-global/dsm/feature/productivityapi), [Drive API v1](https://office-suite-api.synology.com/Synology-Drive/v1) and [OpenAI tool/authentication guidance](https://developers.openai.com/plugins/build/auth). The Drive documentation requires a Synology account/application and its own SDK agreement. Vendor SDKs, documentation, credentials and downloaded API specifications are not bundled or committed. This repository contains an independently written REST client; do not redistribute vendor material under this project's MIT license.

The Drive client uses the documented login, metadata and sharing-link routes, strict response checks and immutable file IDs. HTTP contract fixtures validate the implementation. Live NAS creation, inherited ACLs, Drive session expiry, index timing, metadata mapping, HTTPS sharing configuration and real ChatGPT consent are separate deployment acceptance checks.
