# DSM setup and gateway pairing (package build 0006)

This developer build provides folder selection, access checks, gateway pairing, connection status and disconnection. The backend is covered by actual HTTPS/WSS tests. Real DSM CGI executor/session permissions, installation, upgrade and reboot still require hardware validation; do not describe this as a finished consumer release.

The approved upgrade to `0006` was installed and showed Running on a DSM 7 device, but the cache-refreshed UI still received HTTP 503 instead of JSON. Folder selection and pairing therefore remain disabled on that device. The CGI header correction is validated by process tests; it did not resolve the observed DSM HTTP failure.

Open the app in Package Center while signed in as a DSM administrator. The launcher uses `/webman/3rdparty/SynologyNASConnector/index.html`. Build 0001 omitted `/webman`, producing a 404 even though its service was running; this was reproduced on a DSM 7 device and the correct URL was verified on that device. This observation does not prove the new CGI bridge works there.

## Setup

1. Select shared folders and save. No folders are enabled by default. Only discovered top-level shares on `/volume1` through `/volume16` are selectable; USB/network mounts are outside this selector.
2. For an unavailable folder, grant **read-only** access to the `SynologyNASConnector` system internal user in Control Panel → Shared Folder → Edit → Permissions → System internal user. Refresh the app. The package never changes ACLs itself.
3. Use **Check folder** to confirm access. This shows at most ten entry names and no document contents.
4. Deploy or obtain an approved [gateway](gateway-deployment.md). Enter its public HTTPS origin in **Connect your NAS**, choose a label and read the data-transit consent. Do not enter a DSM address, password, API key or bearer token. Local/private/reserved gateway destinations are rejected; TLS certificate checks cannot be disabled in the UI.
5. Select **Pair NAS**. Open the displayed gateway link and type the public pairing code there. It expires in ten minutes. On both pages compare the six-digit number, then select **Both numbers match** in DSM only if the numbers agree. Finish the gateway page. The private polling credential and NAS key remain on the NAS. If the approval response is lost, subsequent polling can recover that pairing only after the administrator has explicitly confirmed the matching proof.
6. Once the NAS status is **connected**, the app displays the gateway `/mcp` URL and a link to [current OpenAI connection instructions](https://developers.openai.com/apps-sdk/deploy/connect-chatgpt). Developer mode/workspace availability and the exact OAuth callback must be checked with the real client. ChatGPT's authorization page on the gateway asks for a specific NAS and folders; folder boxes start unchecked.

NAS ownership pairing signs in to this gateway using its NAS identity. It is separate from OpenAI identity. **Sign in with ChatGPT is not implemented**. No public directory acceptance, universal account availability or completed real ChatGPT connection is claimed.

The gateway terminates TLS and can see requested filenames, metadata and text. It stores ownership/policy/grant state but the implementation does not persist or log document contents. Only trust an operator whose hosting/logging policy you approve. The connector keeps originals read-only; requested contents travel to the client.

## Change access or disconnect

Deselect folders and save to remove access immediately in the local service. The relay applies the same live policy; a source change discards in-progress reads. Removing a folder narrows gateway grants. Re-adding it requires fresh consent. Changing folders during pairing invalidates that pending pairing.

**Disconnect NAS and revoke access** stops the outbound connection, durably disables restoration and sends a signed revocation request to the gateway. If the gateway is offline, the status explicitly shows pending revocation. The NAS remains disconnected; use **Retry gateway revocation** or restart the service once the gateway is reachable. Previously issued grants cannot read from an offline NAS and are invalidated when revocation succeeds. Re-pairing after revocation creates a new device ID, so old signatures and grants cannot authorize it.

A paired NAS automatically reconnects on service restart/upgrade using its saved key and exact device ID. Back up private `var/relay/identity.key` and `var/relay/connection.json` consistently; never post them in an issue. Missing/replaced keys, unsafe permissions or corrupt state prevent restoration and surface a connection error. The package does not silently regenerate a paired identity. A fresh unpaired installation creates no identity until explicit pairing.

If saving connection state fails, pairing stops and attempts revocation. If disconnection cannot replace or remove the saved record, `DISCONNECT_NOT_PERSISTED` warns that a restart could revive old enabled state. Resolve storage errors before restarting; do not broaden private key permissions. No claim of durable revocation is made on a failed write.

## Authentication and isolation

The same-origin CGI directly executes DSM's documented `authenticate.cgi`, then `/usr/bin/id -Gn` with an argument array and requires exact membership in `administrators`. Empty, invalid or unavailable DSM identity fails closed. Hardware testing must establish the actual CGI execution identity; no guessed authentication bypass is provided.

The bridge forwards only fixed management actions and the authenticated username to loopback. DSM cookies stay in the authentication process. A separate private HMAC key signs method, path, user, timestamp, nonce, CSRF token and body hash. The service rejects remote callers, signatures older than fifteen seconds and replayed nonces. POST actions additionally require a user-bound expiring CSRF token; the CGI requires the exact HTTPS Origin independently of DSM's optional CSRF settings.

Browser requests carry opaque share IDs rather than filesystem paths. Root and connection writes serialize, use private files and reject stale state. Pairing is bound to its initiating administrator, immutable proof and unchanged folder provider. Any verified administrator can disconnect an existing connection. The MCP bearer token never grants management access. If the CGI cannot read its private key or authenticate DSM, do not broaden secret permissions as a workaround.

Package upgrades preserve roots, local token, management key, NAS identity and connection record. The service stays on `127.0.0.1` with management enabled. Public access is through the optional outbound relay; opening DSM or the local service to the internet is unnecessary.

## Required device checks

Validate administrator/non-administrator sessions, cross-origin POST rejection, package-user ACLs, folder selection/revocation, pairing and comparison, actual gateway reads, offline disconnection, restart/reboot and upgrade. Confirm runtime paths and CGI executor identity through authorized diagnostics before changing package privileges. Keep household addresses, cookies, keys and NAS documents out of the public repository.

Reference: [Synology web authentication guide](https://help.synology.com/developer-guide/integrate_dsm/web_authentication.html).
