# Google Drive as the product benchmark

The target experience is one ChatGPT connection for discovering, reading, creating, editing, organizing and sharing authorized NAS files. The current connector is not feature-equivalent to Google Drive. A green build or similarly named tools does not establish equivalence.

| Workflow | Current connector | Required acceptance evidence |
| --- | --- | --- |
| Find files | Bounded filename search and folder listing | Content/type search, recent files, explicit partial results |
| Read documents | Bounded UTF-8 text only | PDF, DOCX, XLSX and PPTX reads with page/paragraph/cell/slide provenance and resource limits |
| Create documents | New text files up to 16 KiB; v0.2 awaits live testing | Useful document formats, upload, verified readback and observed openable links |
| Edit documents | Not implemented | Format-aware edits, revision/conflict checks, preservation of unrelated content and formatting |
| Work with spreadsheets | CSV/TSV text only | Bounded ranges, formulas and formatting; distinguish XLSX from native Synology Spreadsheet |
| Work with presentations | Not implemented | Slide-aware reading/editing and validated PPTX output |
| Organize files | Listing only | Folder creation, rename, move and copy within granted boundaries; verify destination and avoid silent overwrite |
| Share files | Drive links preserving existing permissions; v0.2 awaits live testing | Explicit recipient/role or public-viewer consent, resulting-permission verification; password/expiry only if supported and tested |
| Revoke sharing | Not implemented | Remove connector-created access without altering unrelated recipients; verify denial |
| Compare revisions | Not implemented | Discover and read available Drive revisions; identify exact versions and unavailable history |
| Comments | Not implemented | Verified support for each target format before exposing comment operations |
| Delete files | Not implemented | Recoverable trash where supported, separate destructive consent, no permanent-delete fallback |
| Connect and revoke | Real read-only NAS/ChatGPT tests passed | Same onboarding for optional capabilities, current permissions enforced for every operation |

Native Google Docs, Sheets and Slides have dedicated APIs. Uploading a file is not an equivalent editor. A Drive link does not itself grant anonymous access.

## Architecture and delivery

Keep portable filesystem policy and exclusive creation in the core. Add separate adapters for bounded file-format reading/writing, documented Drive lifecycle/permissions/revisions, and optional native Spreadsheet. Resolve vendor identities from authorized roots; arbitrary file IDs or URLs must not bypass root consent. Untrusted parsers need bounded workers, no macro execution or external resource loading. Updates require expected revisions and verified readback; uncertain mutations must not retry automatically.

Native Spreadsheet API requires Office 3.7.0 or later and a separate proxy service. Synology discourages hosting that service on the same DSM as Office because spreadsheet workers consume significant resources. This connector does not install or expose it. Native text-document/presentation editing contracts remain unverified; do not invent endpoints or claim parity.

Separate create, update, organize, recipient-sharing, public-publishing and deletion capabilities. Existing read-only grants gain none automatically. Any future content index is opt-in, private and bounded; removed folders must be purged and current permissions enforced at query time. Independent MCP integration is distinct from OpenAI-managed sync or public directory approval.

Delivery order: complete v0.2 live acceptance on a disposable share; add richer format reads/discovery; add document creation/upload; add revision-aware edits and organization; add explicit sharing/revocation; then optional native Spreadsheet and verified native document features. Verify each workflow in real ChatGPT before claiming support.

## Sources checked 2026-10-02

- [OpenAI Google Drive app documentation](https://help.openai.com/en/articles/10929079-google-drive-app-and-setup-in-chatgpt): enabled actions and permissions govern live capabilities; personal live access and administrator-managed sync differ.
- Installed Google Drive plugin tool descriptions and routing skill: discovery, lifecycle, sharing, revisions and dedicated document/table/presentation operations. No private Google Drive files were accessed.
- [Synology productivity API overview](https://www.synology.com/en-global/dsm/feature/productivityapi).
- Authenticated [Drive API](https://office-suite-api.synology.com/Synology-Drive/v1) and [Spreadsheet prerequisites](https://office-suite-api.synology.com/Synology-Spreadsheet/v3-4-1#docs-/Prerequisites/setup). Vendor SDKs, API specifications and documentation are not redistributed.
