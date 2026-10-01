import path from 'node:path';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { loadConfig, NasFiles } from '../../../packages/core/src/index.js';
import { localTokenAuthenticator, NAS_READ_SCOPE } from '../../../packages/auth/src/index.js';
import { createMcpServer } from './mcp.js';
import { createHttpApp } from './http.js';
import { BridgeGuard, ConfigurationStore, readManagementSecret, ShareCatalog,NasConnectionController } from '../../../packages/management/src/index.js';
import { managementRouter } from './management.js';

async function main() {
  const args = process.argv.slice(2);
  if (args.some(a => !['--stdio', '--config'].includes(a) && args[args.indexOf(a) - 1] !== '--config'))
    throw new Error('Usage: server [--stdio] --config PATH');
  const configPath = args.includes('--config') ? args[args.indexOf('--config') + 1] : process.env.NAS_CONNECTOR_CONFIG;
  if (!configPath) throw new Error('Provide --config PATH or NAS_CONNECTOR_CONFIG');
  const config = await loadConfig(configPath);
  // Relative token paths are resolved against config, never the process cwd.
  config.http.tokenFile = path.resolve(path.dirname(configPath), config.http.tokenFile);
  const files = await NasFiles.create(config);
  if (args.includes('--stdio')) {
    const server = createMcpServer(files, {subject: 'local-process', scopes: [NAS_READ_SCOPE]});
    await server.connect(new StdioServerTransport());
    for (const signal of ['SIGTERM', 'SIGINT'] as const) process.once(signal, () => {void server.close().then(() => process.exit(0));});
  } else {
    const auth = await localTokenAuthenticator(config.http.tokenFile);
    const uiDir = process.env.NAS_CONNECTOR_UI_DIR ?? path.resolve('apps/dsm-ui/public');
    let source: NasFiles | (() => NasFiles) = files;
    let management;
    let connection:NasConnectionController|undefined;
    if (config.management) {
      if (config.http.host !== '127.0.0.1') throw new Error('Management requires loopback binding');
      const secretPath = path.resolve(path.dirname(configPath),config.management.secretFile);
      const store = await ConfigurationStore.create(path.resolve(configPath),config,ShareCatalog.dsm());
      connection=new NasConnectionController(path.resolve(path.dirname(configPath),'relay'),()=>store.getFiles());
      await connection.restore();
      management = managementRouter(store,new BridgeGuard(await readManagementSecret(secretPath)),connection);
      source = () => store.getFiles();
    }
    const app = createHttpApp(config, source, auth, uiDir, management);
    const listener = app.listen(config.http.port, config.http.host, () => console.error('NAS connector started (read-only)'));
    listener.requestTimeout = 15000;
    listener.headersTimeout = 10000;
    listener.on('error', () => {console.error('HTTP_LISTEN_FAILED'); process.exitCode = 1;void connection?.stop();});
    for (const signal of ['SIGTERM', 'SIGINT'] as const) process.once(signal, () => {
      void connection?.stop();
      listener.close(() => process.exit(0));
      setTimeout(() => {listener.closeAllConnections(); process.exit(0);}, 5000).unref();
    });
  }
}
main().catch(() => {console.error('STARTUP_FAILED: check configuration, token permissions, and root ACLs.'); process.exitCode = 1;});
