# Installation

## Choose the deployment

For a Synology NAS, use the graphical DSM setup below. This route does not require editing JSON, copying an MCP token or opening a home-router port. A separate trusted gateway is needed for remote ChatGPT access. There is no project-hosted gateway included in this preview.

For local development or a local MCP client, use the [README quick start](../README.md#quick-start). Gateway operators use the separate [gateway deployment guide](gateway-deployment.md).

## Synology DSM preview

Target: DSM 7.2 or newer with the official **Node.js v22** package available for that model. The payload is architecture-independent JavaScript, which does not certify every NAS model. Check [Synology's Node.js v22 page](https://www.synology.com/en-us/dsm/packages/Node.js_v22) and Package Center on the actual NAS. The inspected DSM 7 device had that package installed; ARM installation/upgrade is still unverified.

This is an unsigned community **developer preview**, not a Package Center listing or a finished consumer release. Real DSM authentication, package-user permissions, upgrades/reboots and a real ChatGPT connection remain release gates. See the [verification record](verification.md).

**Known device failure:** builds 0005 and 0006 installed and ran, but DSM management bootstrap returned HTTP 503 with DSM HTML. The build 0006 header correction did not resolve this failure. Source build 0007 adds bounded failure-stage reporting and a JSON error envelope; it has not yet been validated on DSM. The steps below describe the intended setup after successful administrator verification. Stop if the management interface cannot initialize.

1. Download `SynologyNASConnector-0.1.0-0006-noarch.spk` and its `.sha256` sidecar from the [preview release](https://github.com/sammkoo/synology-nas-connector/releases/tag/v0.1.0-preview.6). Check the downloaded filename and SHA-256 against that release before installing. Building source is optional; the release includes source and checksums.
2. Install official **Node.js v22** in Package Center. Sign in to DSM as an administrator over HTTPS. In Package Center, choose **Manual Install** and select the connector `.spk`. Review any community-package consent shown by DSM yourself.
3. Start the package and open **Synology NAS Connector** from Package Center/DSM. The app verifies your existing DSM administrator session. It never asks for your DSM password, OpenAI API key or private token. A fresh installation starts with no folders enabled and no outbound connection.
4. In **Choose folders**, select only the desired shares and save. For a folder marked **permission needed**, use Control Panel → Shared Folder → Edit → Permissions → System internal user and grant `SynologyNASConnector` **read-only** permission to that share, then refresh the app. Keep broad group/write permissions disabled. DSM wording can vary by version; the package does not edit ACLs.
5. Use **Check access** to list up to ten entry names from a selected folder. This confirms package-account access without sending document contents to a gateway.
6. Obtain the public HTTPS origin of a gateway you trust. In **Connect your NAS**, enter that origin, name the NAS and read the data-transit consent. Pair the NAS, enter the public code on the gateway page and compare the six-digit number on both pages. Select **Both numbers match** in DSM only when they match, then finish the gateway page. Detailed steps and recovery are in [DSM setup](dsm-management.md).
7. Once the NAS shows **connected**, use the displayed `/mcp` URL and [OpenAI's current connection instructions](https://developers.openai.com/apps-sdk/deploy/connect-chatgpt). Developer-mode/workspace eligibility and the exact OAuth callback must be validated with the real client. Review the NAS and folders on the gateway authorization page. NAS ownership pairing is separate from **Sign in with ChatGPT**, which remains unimplemented.

The app launch URL is `/webman/3rdparty/SynologyNASConnector/index.html`. If the new UI cannot verify your DSM administrator session, stop setup and follow the table below. Do not expose the loopback management service or make its key public to bypass an authentication failure.

### Change access

Remove a folder selection and save to revoke it. Live reads enforce the new policy and discard results started under the old policy. Re-adding a folder requires fresh gateway consent. **Disconnect NAS and revoke access** stops transmission and revokes gateway grants; an offline gateway leaves revocation pending while the NAS stays disconnected. Retry the shown action when the gateway returns. No selected document is deleted or modified.

### Troubleshooting

| What you see | Next action |
| --- | --- |
| DSM login or setup session expired | Sign back in to DSM over HTTPS and refresh the connector. |
| Administrator required | Open the app with a DSM account in the `administrators` group. |
| Management bridge unavailable | Stop setup. Check the package/runtime and verified CGI identity; report the fixed error code. Never broaden private key permissions. |
| DSM returns HTTP 503 or non-JSON HTML | Stop setup and report the HTTP status plus package version. Build 0006 did not resolve the observed device failure. Build 0007 requires real-device verification. |
| A fixed `DSM_AUTH_EXECUTION_FAILED`, `DSM_GROUP_LOOKUP_FAILED`, `DSM_CONFIG_READ_FAILED` or signing-key code appears | Stop setup and report only the code and package version. Do not post cookies, keys or raw logs, grant extra permissions, or bypass certificate checks. These codes identify a failed bridge stage; they do not prove its underlying cause. |
| Folder permission needed | Grant the package system user read-only access to that specific share and refresh. |
| Gateway address rejected | Use its public HTTPS origin, without credentials, query or `/mcp` path. Private/loopback/reserved destinations are denied. |
| Gateway unavailable or certificate error | Check NAS internet access, the gateway address and its operator's certificate/status. There is no certificate bypass. |
| Pairing expired or changed | Cancel and start a new pairing. Compare the new number; saved folder changes invalidate pending pairing. |
| Offline connection | The NAS retries with bounded backoff. Check the gateway/internet; retain the existing private NAS identity. |
| Gateway revocation pending | The NAS remains disconnected. Retry revocation when reachable, or restart the service after the gateway returns. |
| Saved connection/key could not be restored | The NAS has not reconnected. Restore consistent private package state with the administrator; do not regenerate the key silently. |
| Disconnection could not be persisted | The current transport is stopped, but restarting could revive old enabled state. Resolve storage errors before restarting. |

If the UI is unavailable and you need to stop transmission, **Stop** the package in Package Center. That prevents reads while it is stopped; a previously enabled connection can resume when the package starts again. For urgent grant revocation, also use the gateway's authenticated device-disconnection control if available.

### Upgrade, backup and uninstall

Stop the service before taking a consistent private backup of package-owned configuration, local token, management key and `relay` identity/connection state. Treat the backup as credentials, keep it outside selected shares and never attach it to a public issue. Upgrade through Package Center; migration retains these files rather than replacing their secrets. A paired connection resumes using the exact saved device/key after service restart.

A failed or partial installation needs administrator inspection rather than automatic secret repair. Package Center controls retention/removal of package-owned private data on uninstall, so back it up first. The lifecycle scripts do not delete selected NAS documents. Uninstall/upgrade behavior still requires real-device validation.

## Local development and diagnostics

The standalone local dashboard is separate from the DSM setup. Follow the README: `npm ci`, `npm run init`, select absolute roots in `.local/config.json`, and `npm run check`. Keep config/token outside shared roots. Stdio trusts its spawning process; local HTTP uses an owner-only bearer token. To rotate that local token, stop the service, replace it with a fresh value generated from 32 random bytes, retain owner/mode `0600` and restart.

An administrator may use an already-approved SSH connection for a local diagnostic tunnel; the connector does not enable SSH or open firewall ports:

```sh
ssh -N -L 8787:127.0.0.1:8787 your-admin@your-nas
```

The forwarded standalone dashboard at `http://127.0.0.1:8787` needs the NAS's private local token. That token is never entered into the DSM app or the gateway. Do not publish the local bearer/management service as a remote ChatGPT endpoint. The remote path uses the gateway's scoped OAuth and outbound NAS channel.

Package scripts use the package user, a fixed Node.js v22 runtime and a PID check tied to the exact bundle. Private `var/service.log` contains fixed diagnostics rather than document bodies, paths or credentials. Process status establishes liveness, not successful DSM authentication or gateway access. For startup failure, check runtime availability, private ownership/modes, chosen folder ACLs and loopback port 8787 availability.

## Build from source

```sh
npm ci
npm run check
npm run spk
npm run test:spk
```

The builder generates the SPK/checksum in `artifacts/`. Linux CI separately tests Node.js 22/24, Docker, read-only mounts, real TLS gateway/relay and reproducibility. The package structure follows the [DSM 7 Developer Guide](https://global.download.synology.com/download/Document/Software/DeveloperGuide/Os/DSM/All/enu/DSM_Developer_Guide_7_enu.pdf); the session bridge follows [Synology application authentication](https://help.synology.com/developer-guide/integrate_dsm/web_authentication.html).

## Real-device release checklist

Before promoting beyond preview, verify manual installation, runtime path, administrator/non-administrator sessions, exact HTTPS Origin/CSRF rejection, package-user ACLs, folder selection/removal, pairing/comparison, real protected MCP reads, offline disconnect, start/stop, reboot, credential-preserving upgrade and uninstall on supported x86_64 and ARM NAS hardware. Record model, DSM/runtime build and evidence. Run traversal/symlink tests on the NAS. Local tar/CI checks do not establish these device behaviors or a completed real ChatGPT connection.
