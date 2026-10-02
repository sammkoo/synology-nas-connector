import {test,beforeEach,afterEach,mock} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,writeFile,rm,chmod,symlink} from 'node:fs/promises';
import path from 'node:path';
import {tmpdir} from 'node:os';
import {SynologyDrive,NasError} from '../packages/core/src/index.js';
let directory:string,drive:SynologyDrive,calls:{url:string;init:RequestInit}[];
const origin='https://nas.example',sid='synthetic-session',virtual='/team-folders/Test/file.txt',physical='/volume1/Test/file.txt';
const metadata={file_id:'123456789',dsm_path:physical,display_path:virtual,type:'file',removed:false,capabilities:{can_share:true}};
beforeEach(async()=>{
  directory=await mkdtemp(path.join(tmpdir(),'nas-drive-'));await writeFile(path.join(directory,'session'),sid,{mode:0o600});calls=[];
  drive=new SynologyDrive({baseUrl:origin+'/',sessionFile:path.join(directory,'session'),linkOrigins:[origin]});
});
afterEach(async()=>{mock.restoreAll();await rm(directory,{recursive:true,force:true});});
function replies(values:unknown[]) {mock.method(globalThis,'fetch',async(url:URL,init:RequestInit)=>{
  calls.push({url:String(url),init});assert.equal(init.redirect,'error');assert.equal((init.headers as Record<string,string>).Cookie,`id=${sid}`);
  return new Response(JSON.stringify(values.shift()),{headers:{'Content-Type':'application/json'}});
});}
test('Drive resolves a verified local file and creates a link by immutable ID without changing permissions',async()=>{
  replies([{success:true,data:metadata},{success:true,data:{url:origin+'/d/f/abcdefghijklmnop'}}]);let approved=false;
  const result=await drive.createLink(virtual,physical,undefined,async()=>{approved=true;});
  assert.equal(approved,true);assert.deepEqual(result,{url:origin+'/d/f/abcdefghijklmnop',provider:'synology-drive',access:'existing-permissions'});
  assert.equal(new URL(calls[0]!.url).searchParams.get('path'),virtual);
  assert.equal(calls[1]!.url,origin+'/api/SynologyDrive/default/v1/sharing/create-link');
  assert.deepEqual(JSON.parse(calls[1]!.init.body as string),{path:'id:123456789'});
  assert.ok(calls.every(c=>c.init.method!=='PUT'));assert.equal(JSON.stringify(result).includes(sid),false);
});
test('mismatched physical path, virtual path, type or capabilities prevent link creation',async()=>{
  for(const change of [{dsm_path:'/volume1/Other/file.txt'},{dsm_path:''},{display_path:'/team-folders/Other/file.txt'},{type:'dir'},{removed:true},{capabilities:{can_share:false}}]){
    mock.restoreAll();calls=[];replies([{success:true,data:{...metadata,...change}}]);
    await assert.rejects(drive.createLink(virtual,physical),/DRIVE_PATH_MISMATCH/);assert.equal(calls.length,1);
  }
});
test('revocation before mutation stops Drive from receiving a POST',async()=>{
  replies([{success:true,data:metadata}]);
  await assert.rejects(drive.createLink(virtual,physical,undefined,async()=>{throw new NasError('CONFIGURATION_CHANGED');}),/CONFIGURATION_CHANGED/);
  assert.equal(calls.length,1);
});
test('links require HTTPS and an explicit trusted origin; returned URLs cannot leak credentials',async()=>{
  for(const url of ['http://nas.example/d/f/link','https://evil.example/d/f/link','https://user:secret@nas.example/d/f/link']){
    mock.restoreAll();replies([{success:true,data:metadata},{success:true,data:{url}}]);
    await assert.rejects(drive.createLink(virtual,physical),/DRIVE_LINK_URL_DENIED/);
  }
  for(const baseUrl of ['http://nas.example/','https://nas.example/path','https://user:pass@nas.example/'])assert.throws(()=>new SynologyDrive({baseUrl,sessionFile:'unused',linkOrigins:[origin]}),/DRIVE_CONFIGURATION_INVALID/);
});
test('expired sessions, malformed replies, redirects and uncertain mutation responses stay sanitized',async()=>{
  replies([{success:false,error:{code:105,private:'hidden'}}]);await assert.rejects(drive.createLink(virtual,physical),/DRIVE_REQUEST_DENIED/);
  mock.restoreAll();replies([{success:true,data:metadata},{success:true,data:{unexpected:'secret'}}]);await assert.rejects(drive.createLink(virtual,physical),/WRITE_RESULT_UNKNOWN/);
  mock.restoreAll();mock.method(globalThis,'fetch',async()=>{throw new Error('private cookie and OS error');});await assert.rejects(drive.createLink(virtual,physical),/^Error: DRIVE_UNAVAILABLE$/);
  mock.restoreAll();await chmod(path.join(directory,'session'),0o644);await assert.rejects(drive.createLink(virtual,physical),/DRIVE_SESSION_REQUIRED/);
  await chmod(path.join(directory,'session'),0o600);await symlink(path.join(directory,'session'),path.join(directory,'alias'));
  const unsafe=new SynologyDrive({baseUrl:origin+'/',sessionFile:path.join(directory,'alias'),linkOrigins:[origin]});await assert.rejects(unsafe.createLink(virtual,physical),/DRIVE_SESSION_REQUIRED/);
});
test('responses are bounded before JSON parsing and a lost POST reports uncertain outcome',async()=>{
  mock.method(globalThis,'fetch',async()=>new Response('x'.repeat(65537)));await assert.rejects(drive.createLink(virtual,physical),/DRIVE_RESPONSE_INVALID/);
  mock.restoreAll();let count=0;mock.method(globalThis,'fetch',async()=>{if(count++===0)return new Response(JSON.stringify({success:true,data:metadata}));throw new Error('connection lost');});
  await assert.rejects(drive.createLink(virtual,physical),/WRITE_RESULT_UNKNOWN/);assert.equal(count,2);
});
test('Drive login uses the documented JSON contract and never exposes passwords in failures',async()=>{
  mock.method(globalThis,'fetch',async(url:URL,init:RequestInit)=>{
    assert.equal(String(url),origin+'/api/SynologyDrive/default/v1/login');assert.equal(init.redirect,'error');
    assert.deepEqual(JSON.parse(init.body as string),{format:'sid',account:'connector-drive',passwd:'synthetic-password'});
    return new Response(JSON.stringify({success:true,data:{sid,did:'ignored'}}));
  });
  assert.equal(await SynologyDrive.login(origin+'/','connector-drive','synthetic-password'),sid);
  mock.restoreAll();mock.method(globalThis,'fetch',async()=>{throw new Error('synthetic-password');});
  await assert.rejects(SynologyDrive.login(origin+'/','connector-drive','synthetic-password'),/^Error: DRIVE_LOGIN_FAILED$/);
});
