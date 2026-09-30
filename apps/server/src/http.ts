import express from 'express';
import path from 'node:path';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import type { Config, NasFiles } from '../../../packages/core/src/index.js';
import { NAS_READ_SCOPE, type Authenticator } from '../../../packages/auth/src/index.js';
import { createMcpServer, type FileProvider } from './mcp.js';

export function createHttpApp(config: Config, source: FileProvider, auth: Authenticator, uiDir: string, management?: express.Router) {
  const current = typeof source === 'function' ? source : () => source;
  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', false);
  let active = 0;
  let windowStart = Date.now();
  let count = 0;
  // Global bounds avoid attacker-controlled maps; applies before body parsing/auth.
  app.use((req, res, next) => {
    res.set({'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'Cache-Control': 'no-store',
      'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"});
    const host = req.headers.host;
    try {
      if (!host || /[\s/@\\]/.test(host) || !config.http.allowedHosts.includes(new URL(`http://${host}`).hostname))
        return res.status(403).json({error: 'HOST_DENIED'});
    } catch { return res.status(403).json({error: 'HOST_DENIED'}); }
    const origin = req.headers.origin;
    if (origin && !config.http.allowedOrigins.includes(origin)) return res.status(403).json({error: 'ORIGIN_DENIED'});
    if (origin) { res.set('Access-Control-Allow-Origin', origin); res.vary('Origin'); }
    if (Date.now() - windowStart >= 60000) { windowStart = Date.now(); count = 0; }
    if (++count > config.http.requestsPerMinute) return res.status(429).set('Retry-After', '60').json({error: 'RATE_LIMIT'});
    if (req.method === 'OPTIONS') return res.set({'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Authorization, Content-Type, Accept, MCP-Protocol-Version'}).status(204).end();
    next();
  });
  app.get('/healthz', (_req, res) => res.json({status: 'ok'}));
  if (management) app.use('/manage', management);
  if (auth.mode === 'oauth' && auth.resourceMetadata) {
    app.get('/.well-known/oauth-protected-resource', (_req, res) => res.json(auth.resourceMetadata));
  }
  app.use('/api', authorize);
  app.get('/api/status', (_req, res) => res.json({version: '0.1.0', mode: auth.mode, readOnly: true,
    roots: current().listRoots().filter(r => !res.locals.principal.rootIds || res.locals.principal.rootIds.includes(r.id)),
    limits: config.limits, chatgpt: {state: 'not-implemented'}}));
  app.use('/mcp', authorize);
  app.post('/mcp', (req, res, next) => {
    if (active >= config.http.maxConcurrent) { res.status(503).json({error: 'BUSY'}); return; }
    active++;
    let released = false;
    const release = () => {if (!released) {released = true; active--;}};
    res.once('close', release);
    res.once('finish', release);
    next();
  }, express.json({limit: '16kb', strict: true}), async (req, res) => {
    const server = createMcpServer(current, res.locals.principal);
    const transport = new StreamableHTTPServerTransport({sessionIdGenerator: undefined, enableJsonResponse: true});
    res.once('close', () => {void transport.close(); void server.close();});
    try {
      await server.connect(transport);
      await transport.handleRequest(req, res, req.body);
    } catch {
      if (!res.headersSent) res.status(500).json({error: 'MCP_REQUEST_FAILED'});
    }
  });
  app.all('/mcp', (_req, res) => res.status(405).set('Allow', 'POST').json({error: 'METHOD_NOT_ALLOWED'}));
  app.use(express.static(path.resolve(uiDir), {dotfiles: 'deny', index: 'index.html'}));
  app.use((_req, res) => res.status(404).json({error: 'NOT_FOUND'}));
  app.use((err: {status?: number}, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    res.status(err.status === 413 ? 413 : 400).json({error: 'INVALID_REQUEST'});
  });
  return app;

  async function authorize(req: express.Request, res: express.Response, next: express.NextFunction) {
    const match = /^Bearer ([A-Za-z0-9._~-]{1,4096})$/.exec(req.headers.authorization ?? '');
    let principal = null;
    try { principal = match ? await auth.authenticate(match[1]!) : null; } catch { /* Fail closed. */ }
    if (!principal) {res.status(401).set('WWW-Authenticate', auth.challenge).json({error: 'UNAUTHORIZED'}); return;}
    if (!principal.scopes.includes(NAS_READ_SCOPE)) {res.status(403).json({error: 'SCOPE_DENIED'}); return;}
    res.locals.principal = principal;
    next();
  }
}
