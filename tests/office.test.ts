import {test,beforeEach,afterEach,mock} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,writeFile,rm,chmod,symlink} from 'node:fs/promises';
import path from 'node:path';
import {tmpdir} from 'node:os';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {InMemoryTransport} from '@modelcontextprotocol/sdk/inMemory.js';
import {StdioClientTransport} from '@modelcontextprotocol/sdk/client/stdio.js';
import {SynologySpreadsheet,officeConfigSchema,parseCellRange,OfficeError,type OfficeConfig} from '../packages/office/src/index.js';
import {createOfficeDevMcp} from '../apps/office-dev/src/mcp.js';

let directory:string,config:OfficeConfig,office:SynologySpreadsheet,calls:{url:string;init:RequestInit}[];
const id='abcdefghijklmnop1234567890ABCDEF',token='synthetic.office.token',range='Sheet1!A1:B2';
const metadata={id,properties:{title:'Budget',locale:'en_US'},sheets:[{properties:{title:'Sheet1',sheetId:'sh_1',index:0,hidden:false},rowCount:100,colCount:20}]};
const cells={range,majorDimension:'ROWS',values:[[1,'Budget'],[false,{t:'r',v:[{tx:'rich ',s:{b:true}},{tx:'text'}]}]]};
beforeEach(async()=>{
  directory=await mkdtemp(path.join(tmpdir(),'nas-office-'));
  await writeFile(path.join(directory,'token'),token,{mode:0o600});
  config=officeConfigSchema.parse({apiOrigin:'https://office.example',tokenFile:path.join(directory,'token'),spreadsheets:[{alias:'budget',label:'Budget',spreadsheetId:id}]});
  office=new SynologySpreadsheet(config);calls=[];
});
afterEach(async()=>{mock.restoreAll();await rm(directory,{recursive:true,force:true});});
function replies(values:unknown[]){mock.method(globalThis,'fetch',async(url:URL,init:RequestInit)=>{
  calls.push({url:String(url),init});assert.equal(init.redirect,'error');assert.equal((init.headers as Record<string,string>).Authorization,`Bearer ${token}`);
  return new Response(JSON.stringify(values.shift()),{headers:{'Content-Type':'application/json'}});
});}
test('Office bounds explicit A1 rectangles and rejects whole sheets, injection and excessive cells',()=>{
  assert.deepEqual(parseCellRange("'Sam''s rozpočet'!Z10:AA11"),{sheet:"Sam's rozpočet",firstRow:10,firstColumn:26,rows:2,columns:2});
  assert.equal(parseCellRange('Sheet1!A1:J100').rows,100);
  for(const value of ['A1','Sheet1!A:A','Sheet1!1:10','Sheet1!A1:J101','Sheet1!B2:A1','Sheet1!A0','Sheet1!XFE1','Sheet1!A100001',"'[External]'!A1",'Sheet1!A1/../../other','Sheet1!A1?target=other'])assert.throws(()=>parseCellRange(value),/OFFICE_RANGE_INVALID/);
});
test('Office configuration is HTTPS-only, bindings are unique and editing defaults off',()=>{
  assert.equal(config.spreadsheets[0]!.allowEdit,false);
  for(const apiOrigin of ['http://office.example','https://user:pass@office.example','https://office.example/path','https://office.example/?token=private'])assert.throws(()=>new SynologySpreadsheet({...config,apiOrigin}),/OFFICE_CONFIGURATION_INVALID/);
  assert.equal(officeConfigSchema.safeParse({...config,spreadsheets:[config.spreadsheets[0],config.spreadsheets[0]]}).success,false);
  assert.deepEqual(office.list(),[{alias:'budget',label:'Budget',allowEdit:false}]);
});
test('native metadata and cells use documented routes and aliases without returning native IDs or credentials',async()=>{
  replies([metadata,cells]);
  const description=await office.metadata('budget');assert.equal(description.sheets[0]!.title,'Sheet1');
  const read=await office.readCells('budget',range);
  assert.deepEqual(read.values,[[1,'Budget'],[false,'rich text']]);assert.equal(read.trust,'untrusted-document-data');
  assert.equal(calls[0]!.url,`https://office.example/spreadsheets/${id}`);
  assert.equal(calls[1]!.url,`https://office.example/spreadsheets/${id}/values/Sheet1!A1%3AB2`);
  assert.equal(JSON.stringify([description,read]).includes(id),false);assert.equal(JSON.stringify(read).includes(token),false);
});
test('unknown documents and default read-only bindings never dispatch edits',async()=>{
  replies([]);
  await assert.rejects(office.readCells(id,range),/OFFICE_DOCUMENT_DENIED/);
  await assert.rejects(office.writeCells('budget',range,[[1,2],[3,4]],async()=>{}),/OFFICE_EDIT_DENIED/);
  assert.equal(calls.length,0);
});
test('editing validates exact shape, bytes and formula policy before dispatch',async()=>{
  office=new SynologySpreadsheet({...config,spreadsheets:[{...config.spreadsheets[0]!,allowEdit:true}]});replies([]);
  for(const values of [[[1]],[[1,2,3],[4,5,6]],[['=IMPORTXML("secret")',2],[3,4]],[[' +SUM(A1)',2],[3,4]],[['\u0000',2],[3,4]],[[Infinity,2],[3,4]],[['x'.repeat(16384),'x'.repeat(16384)],['more',4]]])
    await assert.rejects(office.writeCells('budget',range,values,async()=>{}),/OFFICE_(VALUES_INVALID|FORMULA_UNSUPPORTED)/);
  assert.equal(calls.length,0);
});
test('fresh authorization precedes PUT and revocation/cancellation prevent dispatch',async()=>{
  office=new SynologySpreadsheet({...config,spreadsheets:[{...config.spreadsheets[0]!,allowEdit:true}]});replies([{...cells,values:[[1,2],[3,4]]},{...cells,values:[[1,2],[3,4]]}]);
  await assert.rejects(office.writeCells('budget',range,[[1,2],[3,4]],async()=>{throw new OfficeError('REVOKED');}),/REVOKED/);
  const cancelled=new AbortController();
  await assert.rejects(office.writeCells('budget',range,[[1,2],[3,4]],async()=>{cancelled.abort();},cancelled.signal),/CANCELLED/);
  assert.equal(calls.length,0);
  const receipt=await office.writeCells('budget',range,[[1,2],[3,4]],async()=>{});
  assert.equal(receipt.updated,true);assert.equal(receipt.concurrency,'no-atomic-revision-check');
  assert.equal(calls[0]!.init.method,'PUT');assert.deepEqual(JSON.parse(calls[0]!.init.body as string),{values:[[1,2],[3,4]]});
  assert.equal(calls[1]!.init.method,'GET');assert.equal(receipt.verification,'readback-matched');
});
test('unexpected document IDs, sheet ranges, response shapes and oversized responses fail closed',async()=>{
  replies([{...metadata,id:'different-document'}, {...cells,range:'Other!A1:B2'}, {...cells,values:[[1,2,3],[4,5,6]]}]);
  await assert.rejects(office.metadata('budget'),/OFFICE_RESPONSE_INVALID/);
  await assert.rejects(office.readCells('budget',range),/OFFICE_RESPONSE_INVALID/);
  await assert.rejects(office.readCells('budget',range),/OFFICE_RESPONSE_INVALID/);
  mock.restoreAll();mock.method(globalThis,'fetch',async()=>new Response('x'.repeat(262145)));
  await assert.rejects(office.readCells('budget',range),/OFFICE_RESPONSE_INVALID/);
});
test('private token permissions and symlinks are checked before any network request',async()=>{
  replies([]);await chmod(config.tokenFile,0o644);
  await assert.rejects(office.readCells('budget',range),/OFFICE_SESSION_REQUIRED/);
  await chmod(config.tokenFile,0o600);const alias=path.join(directory,'symlink');await symlink(config.tokenFile,alias);
  await assert.rejects(new SynologySpreadsheet({...config,tokenFile:alias}).readCells('budget',range),/OFFICE_SESSION_REQUIRED/);
  assert.equal(calls.length,0);
});
test('lost or malformed PUT replies report uncertain outcome without retries or raw secrets',async()=>{
  office=new SynologySpreadsheet({...config,spreadsheets:[{...config.spreadsheets[0]!,allowEdit:true}]});
  let count=0;mock.method(globalThis,'fetch',async()=>{count++;throw new Error('private token or response');});
  await assert.rejects(office.writeCells('budget',range,[[1,2],[3,4]],async()=>{}),/^Error: WRITE_RESULT_UNKNOWN$/);assert.equal(count,1);
  mock.restoreAll();replies([{error:'private vendor details'}]);
  await assert.rejects(office.writeCells('budget',range,[[1,2],[3,4]],async()=>{}),/^Error: WRITE_RESULT_UNKNOWN$/);
});
test('actual MCP client sees destructive edit annotations and cannot bypass bindings or read-only policy',async()=>{
  const [clientTransport,serverTransport]=InMemoryTransport.createLinkedPair();
  const server=createOfficeDevMcp(office),client=new Client({name:'office-test',version:'1'});
  try {
    await server.connect(serverTransport);await client.connect(clientTransport);
    const catalog=await client.listTools();assert.equal(catalog.tools.length,4);
    assert.equal(catalog.tools.find(tool=>tool.name==='write_spreadsheet_cells')!.annotations!.destructiveHint,true);
    const list=await client.callTool({name:'list_spreadsheets',arguments:{}});assert.equal(JSON.stringify(list).includes(id),false);
    const denied=await client.callTool({name:'write_spreadsheet_cells',arguments:{alias:'budget',range,values:[[1,2],[3,4]]}});
    assert.equal(denied.isError,true);assert.match(JSON.stringify(denied),/OFFICE_EDIT_DENIED/);
    const arbitrary=await client.callTool({name:'read_spreadsheet_cells',arguments:{alias:id,range}});
    assert.equal(arbitrary.isError,true);assert.match(JSON.stringify(arbitrary),/OFFICE_DOCUMENT_DENIED/);
  }finally{await client.close();await server.close();}
});
test('development CLI refuses subsequent operations after its private authorization configuration changes',async()=>{
  const filename=path.join(directory,'office.json');await writeFile(filename,JSON.stringify(config),{mode:0o600});
  const transport=new StdioClientTransport({command:process.execPath,args:['--import','tsx','apps/office-dev/src/cli.ts','--config',filename],stderr:'pipe'});
  const client=new Client({name:'office-stdio-test',version:'1'});
  try {
    await client.connect(transport);const before=await client.callTool({name:'list_spreadsheets',arguments:{}});assert.notEqual(before.isError,true);
    await writeFile(filename,JSON.stringify({...config,spreadsheets:[]}),{mode:0o600});
    const after=await client.callTool({name:'list_spreadsheets',arguments:{}});assert.equal(after.isError,true);assert.match(JSON.stringify(after),/OFFICE_CONFIGURATION_CHANGED/);
  }finally{await client.close();}
});
test('authorization uses only the explicitly trusted proxy and HTTPS NAS origin; credentials never appear in errors',async()=>{
  mock.method(globalThis,'fetch',async(url:URL,init:RequestInit)=>{
    assert.equal(String(url),'https://office.example/spreadsheets/authorize');assert.equal(init.redirect,'error');
    assert.deepEqual(JSON.parse(init.body as string),{username:'office-test',password:'synthetic-password',host:'nas.example:5001',protocol:'https'});
    return new Response(JSON.stringify({token}));
  });
  assert.equal(await SynologySpreadsheet.authorize('https://office.example/','https://nas.example:5001/','office-test','synthetic-password'),token);
  mock.restoreAll();let count=0;mock.method(globalThis,'fetch',async()=>{count++;throw new Error('synthetic-password');});
  await assert.rejects(SynologySpreadsheet.authorize('http://office.example/','https://nas.example/','office-test','synthetic-password'),/^Error: OFFICE_LOGIN_FAILED$/);assert.equal(count,0);
  await assert.rejects(SynologySpreadsheet.authorize('https://office.example/','https://nas.example/','office-test','synthetic-password'),/^Error: OFFICE_LOGIN_FAILED$/);assert.equal(count,1);
});
test('a committed edit with a mismatched or unavailable readback is uncertain and is never written twice',async()=>{
  office=new SynologySpreadsheet({...config,spreadsheets:[{...config.spreadsheets[0]!,allowEdit:true}]});
  replies([cells,cells]);
  await assert.rejects(office.writeCells('budget',range,[[1,2],[3,4]],async()=>{}),/^Error: WRITE_RESULT_UNKNOWN$/);
  assert.deepEqual(calls.map(call=>call.init.method),['PUT','GET']);
  mock.restoreAll();calls=[];let count=0;
  mock.method(globalThis,'fetch',async(url:URL,init:RequestInit)=>{calls.push({url:String(url),init});if(count++===0)return new Response(JSON.stringify(cells));throw new Error('readback unavailable');});
  await assert.rejects(office.writeCells('budget',range,[[1,2],[3,4]],async()=>{}),/^Error: WRITE_RESULT_UNKNOWN$/);
  assert.deepEqual(calls.map(call=>call.init.method),['PUT','GET']);
});
