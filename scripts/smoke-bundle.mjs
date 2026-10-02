import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import assert from 'node:assert/strict';
const dir = await mkdtemp(path.join(tmpdir(), 'nas-bundle-'));
const client = new Client({name:'bundle-smoke', version:'1'});
try {
  await writeFile(path.join(dir, 'document.md'), 'portable bundled runtime');
  await writeFile(path.join(dir, 'config.json'), JSON.stringify({roots:[{id:'docs',path:dir,label:'Docs'}],http:{tokenFile:'unused'}}));
  await client.connect(new StdioClientTransport({command:process.execPath,
    args:[path.resolve(process.argv[2] ?? 'dist/server.cjs'),'--stdio','--config',path.join(dir,'config.json')],stderr:'pipe'}));
  assert.equal((await client.listTools()).tools.length, 7);
  const result = await client.callTool({name:'read_text',arguments:{rootId:'docs',path:'document.md'}});
  assert.match(JSON.stringify(result), /portable bundled runtime/);
  console.log('Bundled stdio server initialized and read document through official MCP SDK client');
} finally {await client.close(); await rm(dir,{recursive:true,force:true});}
