import {test,before,after} from 'node:test';
import assert from 'node:assert/strict';
import {createServer,type Server} from 'node:http';
import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {build} from 'esbuild';
import {officeAcceptance,hiddenPassword} from '../scripts/office-live-acceptance.js';

let directory:string,bundle:string;
before(async()=>{directory=await mkdtemp(path.join(tmpdir(),'office-live-fixture-'));bundle=path.join(directory,'office-dev.cjs');
  await build({entryPoints:['apps/office-dev/src/cli.ts'],bundle:true,platform:'node',target:'node22',format:'cjs',outfile:bundle});});
after(async()=>{await rm(directory,{recursive:true,force:true});});
const id='abcdefghijklmnop1234567890ABCDEF';
async function fixture(mode:'success'|'bad-read'|'uncertain-write',run:(origin:string,writes:()=>number)=>Promise<void>){
  let writes=0;let values:unknown[][]=[['synthetic original',1],['test',false]];
  const server:Server=createServer(async(req,res)=>{
    res.setHeader('Content-Type','application/json');
    const reply=(status:number,value:unknown)=>{res.writeHead(status);res.end(JSON.stringify(value));};
    if(req.url==='/spreadsheets/authorize'){
      const chunks:Buffer[]=[];for await(const chunk of req)chunks.push(Buffer.from(chunk));
      assert.deepEqual(JSON.parse(Buffer.concat(chunks).toString()),{username:'restricted-test',password:'synthetic-password',host:'nas.example',protocol:'https'});
      reply(200,{token:'synthetic.office.token'});return;
    }
    if(req.headers.authorization!=='Bearer synthetic.office.token'){reply(401,{error:'unauthorized'});return;}
    if(req.url===`/spreadsheets/${id}`){reply(200,{id,properties:{title:'Disposable test',locale:'en_US'},
      sheets:[{properties:{title:'Sheet1',sheetId:'sh_1',index:0,hidden:false},rowCount:100,colCount:20}]});return;}
    if(req.url===`/spreadsheets/${id}/values/Sheet1!A1%3AB2`){
      if(req.method==='PUT'){
        writes++;const chunks:Buffer[]=[];for await(const chunk of req)chunks.push(Buffer.from(chunk));values=JSON.parse(Buffer.concat(chunks).toString()).values;
        if(mode==='uncertain-write'){res.writeHead(200);res.end('not-json');return;}
      }
      reply(200,{range:mode==='bad-read'?'Sheet2!A1:B2':'Sheet1!A1:B2',majorDimension:'ROWS',values});return;
    }
    reply(404,{error:'unexpected route'});
  });
  await new Promise<void>(resolve=>server.listen(0,'127.0.0.1',resolve));const address=server.address();
  assert.ok(address&&typeof address!=='string');
  try{await run(`http://127.0.0.1:${address.port}/`,()=>writes);}finally{await new Promise<void>((resolve,reject)=>server.close(error=>error?reject(error):resolve()));}
}
const base=()=>({bundle,nasOrigin:'https://nas.example/',username:'restricted-test',spreadsheetId:id,passwordPrompt:async()=>'synthetic-password'});
test('manual acceptance uses real MCP stdio, one bounded edit, separate readback and configuration revocation',async()=>{
  const reports:string[]=[];
  await fixture('success',async(apiOrigin,writes)=>{
    await officeAcceptance({...base(),apiOrigin,report:message=>reports.push(message)});assert.equal(writes(),1);
  });
  assert.deepEqual(reports,['UNAUTHENTICATED_ACCESS_DENIED','RESTRICTED_ACCOUNT_AUTHORIZED','UNCONFIGURED_ALIAS_DENIED',
    'NATIVE_METADATA_VERIFIED','BOUNDED_READ_VERIFIED','BOUNDED_EDIT_READBACK_VERIFIED','DEVELOPMENT_CONFIGURATION_REVOCATION_VERIFIED']);
  assert.equal(reports.join(' ').includes(id),false);assert.equal(reports.join(' ').includes('synthetic.office.token'),false);
});
test('manual acceptance fails before editing when the read response describes another sheet',async()=>{
  await fixture('bad-read',async(apiOrigin,writes)=>{
    await assert.rejects(officeAcceptance({...base(),apiOrigin,report:()=>{}}),/OFFICE_RESPONSE_INVALID/);assert.equal(writes(),0);
  });
});
test('manual acceptance never retries a write with an uncertain response',async()=>{
  await fixture('uncertain-write',async(apiOrigin,writes)=>{
    await assert.rejects(officeAcceptance({...base(),apiOrigin,report:()=>{}}),/WRITE_RESULT_UNKNOWN/);assert.equal(writes(),1);
  });
});
test('manual acceptance validates target configuration before prompting for a password',async()=>{
  let prompts=0;
  await assert.rejects(officeAcceptance({...base(),apiOrigin:'http://untrusted.example/',passwordPrompt:async()=>{prompts++;return 'secret';},report:()=>{}}));
  assert.equal(prompts,0);
  if(!process.stdin.isTTY||!process.stdout.isTTY)assert.throws(hiddenPassword,/INTERACTIVE_TERMINAL_REQUIRED/);
});
