import {mkdtemp,writeFile,rm} from 'node:fs/promises';
import path from 'node:path';
import {tmpdir} from 'node:os';
import assert from 'node:assert/strict';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StdioClientTransport} from '@modelcontextprotocol/sdk/client/stdio.js';
const directory=await mkdtemp(path.join(tmpdir(),'office-bundle-'));
const config=path.join(directory,'config.json');
await writeFile(config,JSON.stringify({apiOrigin:'https://office.invalid/',tokenFile:'unused',spreadsheets:[]}),{mode:0o600});
const client=new Client({name:'office-bundle-test',version:'1'});
try{
  await client.connect(new StdioClientTransport({command:process.execPath,args:[path.resolve('dist/office-dev.cjs'),'--config',config],stderr:'pipe'}));
  const tools=await client.listTools();assert.equal(tools.tools.length,4);
  const empty=await client.callTool({name:'list_spreadsheets',arguments:{}});assert.equal(empty.isError,undefined);
  assert.equal(empty.content[0].text,'[]');
  const denied=await client.callTool({name:'read_spreadsheet_cells',arguments:{alias:'unapproved',range:'Sheet1!A1'}});
  assert.equal(denied.isError,true);assert.match(JSON.stringify(denied),/OFFICE_DOCUMENT_DENIED/);
  console.log('Standalone Office bundle initialized over real MCP stdio; unapproved documents denied without network access');
}finally{await client.close();await rm(directory,{recursive:true,force:true});}
