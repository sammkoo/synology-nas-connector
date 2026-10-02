# Native Synology Office integration

The user's chosen document surface is **native Synology Office**, with Synology Drive handling discovery, file lifecycle and sharing. Native documents are not treated as ordinary UTF-8 files. Google Drive feature parity remains the product target, not a completed capability.

## Implemented development module

`packages/office` contains an independently written client for the documented Spreadsheet 3.4.1 metadata and cell-value routes. `apps/office-dev` exposes four development stdio MCP tools: list approved spreadsheets, inspect sheets, read a bounded cell range, and replace a bounded range when editing is explicitly enabled.

This module is **not installed by the SPK, not available on the production gateway, and not yet tested against a real Office API service**. Existing NAS/ChatGPT grants do not gain native Office access. HTTP fixtures and actual MCP/stdio tests validate the code contracts, bounds, permission checks and revocation, not vendor compatibility.

Only private administrator bindings map aliases to immutable native Spreadsheet IDs. Requests cannot supply arbitrary IDs, URLs, Drive links or NAS paths. The ID is obtained from the administrator-selected native spreadsheet's URL, not inferred from a numeric Drive file ID. Moving or revoking a Drive folder does not automatically update this development allowlist; that is one reason it is not connected to production root consent yet.

## Limits and permission behavior

- HTTPS to a separately configured, trusted Office API service; no redirect or certificate bypass. Explicit `allowLoopbackHttp: true` permits a same-host proxy at literal `http://127.0.0.1:port` only. HTTP to hostnames, other addresses or the NAS login destination is rejected. This option trusts local processes on that host.
- Private owner-only token/config files; no password, token or vendor ID in MCP responses.
- Metadata and up to 1,000 cells from an explicit `Sheet1!A1:B2` rectangle. Read responses must identify that rectangle and fit its bounds. Other vendor range-normalization behavior needs live verification.
- Scalars and flattened rich text for reading. Styles remain available in Office but are not exposed as editable data by this preview.
- Editing defaults off for every document. Values must exactly fill the rectangle and remain below 32 KiB. Formula expressions and rich-text/style writes are unsupported.
- Edits replace existing values. The verified value API does not provide an atomic revision guard in the inspected contract; do not claim concurrent-edit protection. Use disposable documents without simultaneous collaborators for acceptance.
- After a successful edit response, a separate bounded read verifies the exact written values. A failed or mismatched readback is an uncertain outcome; it does not trigger another write. This confirms the observation at readback time, not a lock against subsequent collaborators.
- Configuration changes invalidate subsequent development operations and are checked again before writing. Revocation after the final authorization decision cannot undo an already committed edit.
- Lost/malformed mutation replies report `WRITE_RESULT_UNKNOWN`; never retry automatically. Inspect Office before another edit.
- No native document creation, deletion, presentations, text-document editing or sharing-permission changes are exposed by this module.

## Development configuration

Use a private `.local/office.json` with mode `0600`, owned by the launching user. The token is issued by the trusted Spreadsheet API service for a restricted NAS account; do not enter NAS credentials into the vendor documentation's interactive console. Obtain and store it through a secured local administration workflow. Credentials must be sent only to the explicitly trusted service; it authenticates against the selected NAS.

```json
{
  "apiOrigin": "https://office-api.example/",
  "tokenFile": "office-token",
  "spreadsheets": [
    {
      "alias": "test-budget",
      "label": "Disposable test budget",
      "spreadsheetId": "replaceWithVerifiedNativeSheetId",
      "allowEdit": false
    }
  ]
}
```

Start only with selected disposable documents:

```sh
npm run office:dev -- --config .local/office.json
```

This is a developer stdio process, not a browser setup screen or a ChatGPT connection instruction. The local spawning process is trusted. Production integration needs NAS-side document discovery/mapping, durable document capability consent, OAuth edit scopes, relay authorization and graphical onboarding before these tools can reach the deployed ChatGPT connector.

## Verified vendor support and remaining gaps

The [official proxy image](https://hub.docker.com/r/synology/spreadsheet-api) version 3.4.1 requires Office 3.7.0 or later. The Spreadsheet API runs in a separate proxy, not inside the Office package. Synology discourages running it on the same DSM as Office because spreadsheet workers consume substantial resources. A service placement and resource budget must be agreed before deployment; no service has been installed or exposed by this development change.

`compose.office-dev.yaml` is an optional development recipe with no NAS mounts, a non-root process, a read-only filesystem, loopback-only port and bounded resources. It requires a private signing secret and either TLS or explicit same-host loopback configuration. The CI smoke test starts the official image on an ephemeral runner and checks that unauthenticated document access is denied. It does not log in to a NAS or prove worker/document compatibility; 512 MiB is a test budget, not a sizing guarantee for real spreadsheets. The vendor image is pulled from its official registry, not bundled in our SPK or redistributed as our MIT code.

Authenticated Drive v1/v2 documentation also provides conversion of existing imported files to Office, with a destination folder and conflict policy. Conversion returns an asynchronous task ID, not a completed document or an openable URL. Completion tracking, destination identity and readback must be verified before a creation tool is exposed. The inspected create-file route accepts file/folder types; it does not establish direct text-document or presentation editing support.

Direct native text-document and slide content-editing contracts were not found in the inspected Office Suite catalog. Browser UI capabilities, import/export support and marketing descriptions are not proof of a supported editing API. Request vendor clarification rather than inventing internal endpoints, rewriting opaque Office files, or promising lossless export/edit/reimport.

References checked 2026-10-02: [Synology Office](https://www.synology.com/en-global/dsm/feature/office), [Office Suite APIs](https://www.synology.com/en-global/dsm/feature/productivityapi), [Spreadsheet documentation](https://office-suite-api.synology.com/Synology-Spreadsheet/v3-4-1), [Drive documentation](https://office-suite-api.synology.com/Synology-Drive/v1). Vendor SDKs, API specifications and documentation are not bundled.
