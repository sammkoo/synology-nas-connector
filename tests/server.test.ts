import { test, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, rm, chmod } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import type { Server } from 'node:http';
import { request } from 'node:http';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { createMcpServer } from '../apps/server/src/mcp.js';
import { createHttpApp } from '../apps/server/src/http.js';
import { NasFiles, configSchema, type Config } from '../packages/core/src/index.js';
import { localTokenAuthenticator, oauthResourceMetadata } from '../packages/auth/src/index.js';
let dir: string, files: NasFiles, config: Config, server: Server, base: string;
const token = 'a'.repeat(43);
beforeEach(async () => {
  dir = await mkdtemp(path.join(tmpdir(), 'nas-http-'));
  await writeFile(path.join(dir, 'note.txt'), 'hello MCP');
  await writeFile(path.join(dir, 'token'), token, {mode: 0o600});
  config = configSchema.parse({roots:[{id:'docs',path:dir,label:'Docs'}], http:{tokenFile:path.join(dir,'token'), allowedOrigins:['http://trusted.local']}});
  files = await NasFiles.create(config);
  const app = createHttpApp(config, files, await localTokenAuthenticator(config.http.tokenFile), path.resolve('apps/dsm-ui/public'));
  server = app.listen(0, '127.0.0.1');
  await new Promise<void>(resolve => server.once('listening', resolve));
  base = `http://127.0.0.1:${(server.address() as {port:number}).port}`;
});
afterEach(async () => {server.closeAllConnections(); await new Promise<void>(r => server.close(() => r())); await rm(dir,{recursive:true,force:true});});
test('HTTP authorization, host/origin guards and static UI headers', async () => {
  assert.equal((await fetch(base+'/api/status')).status,401);
  assert.equal((await fetch(base+'/mcp',{method:'POST'})).status,401);
  assert.equal((await fetch(base+'/api/status',{headers:{Authorization:'Bearer wrong'}})).status,401);
  const hostStatus = await new Promise<number>(resolve => {
    const req = request(base+'/healthz', {headers:{Host:'evil.example'}}, res => {res.resume(); resolve(res.statusCode!);});
    req.end();
  });
  assert.equal(hostStatus,403);
  assert.equal((await fetch(base+'/healthz',{headers:{Origin:'https://evil.example'}})).status,403);
  const response = await fetch(base+'/api/status',{headers:{Authorization:`Bearer ${token}`}});
  assert.equal(response.status,200);
  assert.ok(!(await response.text()).includes(dir));
  const ui = await fetch(base+'/');
  assert.match(ui.headers.get('content-security-policy')!, /frame-ancestors 'none'/);
  assert.match(await ui.text(), /Synology NAS Connector/);
  assert.equal((await fetch(base+'/.well-known/oauth-protected-resource')).status,404);
});
test('official SDK client initializes, lists read-only tools and reads via real HTTP', async () => {
  const client = new Client({name:'test',version:'1.0'});
  await client.connect(new StreamableHTTPClientTransport(new URL(base+'/mcp'),{requestInit:{headers:{Authorization:`Bearer ${token}`}}}));
  try {
    const tools = await client.listTools();
    assert.equal(tools.tools.length,5);
    assert.ok(tools.tools.every(t => t.annotations?.readOnlyHint));
    const result = await client.callTool({name:'read_text',arguments:{rootId:'docs',path:'note.txt'}});
    assert.match(JSON.stringify(result),/hello MCP/);
    const denied = await client.callTool({name:'read_text',arguments:{rootId:'docs',path:'../outside.txt'}});
    assert.equal(denied.isError,true);
    const unknown = await client.callTool({name:'delete_file',arguments:{path:'note.txt'}});
    assert.equal(unknown.isError,true);
  } finally {await client.close();}
});
test('invalid JSON and oversized requests do not disclose parser errors', async () => {
  const headers = {Authorization:`Bearer ${token}`,'Content-Type':'application/json'};
  assert.equal((await fetch(base+'/mcp',{method:'POST',headers,body:'{bad'})).status,400);
  assert.equal((await fetch(base+'/mcp',{method:'POST',headers,body:JSON.stringify({data:'x'.repeat(20000)})})).status,413);
});
test('principal root restrictions hold at MCP tool boundary', async () => {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const mcp = createMcpServer(files, {subject:'limited',scopes:['nas:read'],rootIds:[]});
  const client = new Client({name:'test',version:'1'});
  await mcp.connect(serverTransport); await client.connect(clientTransport);
  const result = await client.callTool({name:'read_text',arguments:{rootId:'docs',path:'note.txt'}});
  assert.equal(result.isError,true);
  await client.close(); await mcp.close();
});
test('reject unsafe token permissions and compare tokens without exposing them', async () => {
  const auth = await localTokenAuthenticator(config.http.tokenFile);
  assert.equal(await auth.authenticate('b'.repeat(43)),null);
  assert.equal((await auth.authenticate(token))?.subject,'local-owner');
  await chmod(config.http.tokenFile,0o644);
  await assert.rejects(localTokenAuthenticator(config.http.tokenFile),/0600/);
});
test('OAuth metadata uses HTTPS and only NAS read scope', () => {
  assert.deepEqual(oauthResourceMetadata('https://nas.example/mcp','https://identity.example'),{
    resource:'https://nas.example/mcp', authorization_servers:['https://identity.example'],scopes_supported:['nas:read']
  });
  assert.throws(() => oauthResourceMetadata('http://nas.example','https://auth.example'));
});
test('global rate bound throttles before authentication', async () => {
  config.http.requestsPerMinute = 1;
  const app = createHttpApp(config, files, await localTokenAuthenticator(config.http.tokenFile), path.resolve('apps/dsm-ui/public'));
  const limited = app.listen(0, '127.0.0.1');
  await new Promise<void>(r => limited.once('listening', r));
  const url = `http://127.0.0.1:${(limited.address() as {port:number}).port}`;
  try {
    assert.equal((await fetch(url+'/mcp',{method:'POST'})).status,401);
    const throttled = await fetch(url+'/mcp',{method:'POST'});
    assert.equal(throttled.status,429);
    assert.equal(throttled.headers.get('retry-after'),'60');
  } finally {limited.closeAllConnections(); await new Promise<void>(r => limited.close(() => r()));}
});
test('OAuth adapter errors and missing scope fail closed at HTTP boundary', async () => {
  for (const authenticate of [async () => {throw new Error('provider unavailable');}, async () => ({subject:'limited',scopes:[]})]) {
    const app = createHttpApp(config, files, {mode:'oauth',challenge:'Bearer',authenticate},path.resolve('apps/dsm-ui/public'));
    const listener = app.listen(0,'127.0.0.1');
    await new Promise<void>(r => listener.once('listening',r));
    try {
      const response = await fetch(`http://127.0.0.1:${(listener.address() as {port:number}).port}/mcp`,{method:'POST',headers:{Authorization:'Bearer candidate'}});
      assert.ok([401,403].includes(response.status));
    } finally {listener.closeAllConnections(); await new Promise<void>(r => listener.close(() => r()));}
  }
});
