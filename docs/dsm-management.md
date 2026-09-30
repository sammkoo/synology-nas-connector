# DSM management preview (package build 0002)

This build adds graphical shared-folder selection and a read-only access check. It is a development build pending real-device validation of CGI execution permissions. ChatGPT OAuth and pairing remain under development. Do not present this build as a finished connector.

Open the app in Package Center while signed in as a DSM administrator. The launcher uses `/webman/3rdparty/SynologyNASConnector/index.html`. Build 0001 omitted `/webman`, resulting in a 404 even though the service was running; this was reproduced on DS224+ / DSM 7.4.1-90080 and the correct URL was verified on that device.

## Setup flow

1. Select shared folders and save. No folders are enabled by default. Only discovered top-level shares on `/volume1` through `/volume16` are selectable. USB/network mounts are not supported by this initial selector.
2. If a folder is unavailable, grant **read-only** access to the `SynologyNASConnector` system internal user through DSM's Shared Folder permissions dialog. Refresh the app. The package never changes ACLs itself.
3. Choose a selected folder and use **Check folder** to confirm directory access. The check shows at most ten entries, never document contents.
4. Deselect folders and save to revoke access. The live MCP service observes the new policy without a restart. An in-progress tool result is discarded if its policy changed before completion.

The account-linking step accurately reports that ChatGPT linking is not ready. The UI does not ask users for a NAS password, MCP token or OpenAI API key.

## Authentication and isolation

The same-origin CGI bridge directly executes DSM's documented `authenticate.cgi`, then runs `/usr/bin/id -Gn` with an argument array and requires exact membership in `administrators`. An empty, invalid or unavailable DSM identity fails closed. This path needs hardware testing; the implementation does not invent an alternative authentication bypass if DSM changes its behavior.

The bridge forwards only a fixed management action and the authenticated username to the loopback service. DSM cookies stay inside the authentication process and are not forwarded. A separate private HMAC key signs method, path, user, timestamp, nonce, CSRF token and body digest. The service rejects remote callers, signatures older than 15 seconds and replayed nonces. Writes also require a user-bound expiring CSRF token. The CGI independently requires the exact HTTPS Origin on mutations, even if optional DSM CSRF settings are disabled.

Only config writes are allowed. Browser requests contain opaque share IDs, not filesystem paths. Configuration updates serialize, reject stale revisions and replace a private file atomically. The MCP bearer token cannot access management routes. If the CGI execution user cannot read the private management key or authenticate the DSM session, setup reports unavailable; do not broaden secret permissions as a workaround.

Package upgrade adds a separate private management key and config option while preserving existing MCP credentials and roots. Both migration and file policy revocation have regression tests. The service must remain bound to `127.0.0.1` when DSM management is enabled.

## Device validation still required

Install/update build 0002 on a test NAS, verify administrator and non-administrator sessions, unauthorized cross-origin POST rejection, package-user ACL behavior, root selection, revocation, reboot and upgrades. Inspect CGI executor identity and runtime paths through authorized diagnostics before making any packaging privilege changes. Do not upload cookies, keys, private log contents or household domain/IP information to the public repository.

Reference: [Synology web authentication guide](https://help.synology.com/developer-guide/integrate_dsm/web_authentication.html).
