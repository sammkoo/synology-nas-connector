# Installation

## Local development

Follow the root README. Run `npm ci`, `npm run init`, edit `.local/config.json`, and run `npm run check`. Use an absolute path for every root. Keep configuration and token outside any shared root. To rotate a local token, stop the service, replace `.local/token` with a fresh base64url value generated from 32 random bytes, preserve owner/mode `0600`, and restart. Existing clients then need the new token.

## Synology DSM developer preview

Target: DSM 7.2 or newer on models with the official **Node.js v22** package. The connector payload is `noarch` JavaScript; runtime availability determines model compatibility. This does not mean every NAS model is supported. The package structure follows the [Synology DSM 7 Developer Guide](https://global.download.synology.com/download/Document/Software/DeveloperGuide/Os/DSM/All/enu/DSM_Developer_Guide_7_enu.pdf), including explicit package-user privileges and DSM desktop URL configuration. Check [Node.js v22 model availability](https://www.synology.com/en-us/dsm/packages/Node.js_v22) for your NAS.

1. Build `.spk` with `npm ci`, `npm run check`, `npm run spk`, `npm run test:spk`. Compare the SHA-256 sidecar with the downloaded artifact.
2. Install official Node.js v22 in Package Center. Use Package Center → Manual Install to select the connector `.spk`. This is an unsigned community developer package, not a Package Center listing.
3. The installer creates `/var/packages/SynologyNASConnector/var/config.json` and `token`, owned by the package account. The service starts on loopback with an empty root allowlist. Initial start provides no file access.
4. In Control Panel → Shared Folder → permissions, select the internal system/package user `SynologyNASConnector` and grant **read-only** access only to chosen shares. Do not grant broad group permissions or write permission. UI wording can vary by DSM version.
5. With authorized NAS administrative access, edit `var/config.json` to add roots such as `{"id":"documents","label":"Documents","path":"/volume1/Documents"}`. Restart from Package Center. No DSM credentials are needed by the connector.
6. Open the DSM **NAS Connector** shortcut to see the packaged dashboard and setup information. The DSM static page does not proxy `/api/status` to Node; live status requires opening the service dashboard through local access or the reverse proxy below. No token should be entered into the static DSM page.

### Accessing a loopback service from your computer

For development, forward NAS loopback port 8787 through SSH:

```sh
ssh -N -L 8787:127.0.0.1:8787 your-admin@your-nas
```

Then open `http://127.0.0.1:8787` on that computer. Enter the token obtained from the NAS's private `var/token` through your existing authorized administration channel. The connector does not enable SSH or open firewall ports.

For ongoing use, configure a DSM HTTPS reverse proxy from a hostname you own to `127.0.0.1:8787`. Add that exact hostname to `http.allowedHosts` and its exact HTTPS origin to `http.allowedOrigins`; restart the connector. Preserve Authorization, Accept, Content-Type and MCP protocol headers, and proxy `/mcp` and `/api/status`. Trust in forwarded headers is disabled. Do not publish the local-token preview to the public internet. A remote ChatGPT deployment requires the complete OAuth integration described in [OpenAI integration](openai-integration.md).

### Lifecycle and troubleshooting

Package scripts run as the package user. `start-stop-status` starts the bundled server, checks process identity, handles graceful stop, and rejects stale PIDs. Startup logs contain fixed diagnostic codes rather than paths, credentials or document content. Private logs live in `var/service.log`; status reports only whether the service process exists, not a complete dependency health check. Upgrades reuse config and token; uninstall does not delete any selected NAS share. Package Center controls removal of package-owned `var` data; back it up before uninstalling.

If startup fails, check Node.js v22 dependency/runtime layout, token ownership and permissions, absolute folder paths, folder traversal/read ACLs, and whether port 8787 is available. The launcher checks two known runtime locations and refuses to use an arbitrary PATH runtime. See the verification report for what was actually tested locally.

## Real-device release checklist

Local tar validation cannot establish DSM lifecycle behavior. Before promoting v0.1 beyond preview, test manual installation, runtime location, generated account ACLs, shortcut, start/stop, reboot, upgrade with retained config, uninstall, and denied access on both an x86_64 and an ARM NAS. Record model, DSM build, runtime version and findings. Run traversal/symlink tests on the NAS. No such real-device test has been claimed by this repository.
