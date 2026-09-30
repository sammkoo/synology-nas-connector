import assert from 'node:assert/strict';
import { mkdtemp,readFile,writeFile,rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawn,spawnSync } from 'node:child_process';
import { createServer } from 'node:net';
import { request } from 'node:https';
import { createHash } from 'node:crypto';

const directory=await mkdtemp(path.join(tmpdir(),'nas-gateway-bundle-')),configPath=path.join(directory,'config.json'),bundle=path.resolve('dist/gateway.cjs');
let child;
const reserve=createServer();await new Promise(resolve=>reserve.listen(0,'127.0.0.1',resolve));const port=reserve.address().port;await new Promise(resolve=>reserve.close(resolve));
const issuer=`https://localhost:${port}/`,callback='https://client.example/callback';
const command=(args,env={})=>spawnSync(process.execPath,[bundle,...args],{env:{...process.env,...env},encoding:'utf8',timeout:10000});
async function start() {
  child=spawn(process.execPath,[bundle,'--config',configPath],{stdio:['ignore','pipe','pipe']});let output='';
  await new Promise((resolve,reject)=>{
    const timer=setTimeout(()=>reject(new Error('Gateway startup deadline')),10000);
    child.once('error',e=>{clearTimeout(timer);reject(e);});child.once('exit',()=>{clearTimeout(timer);reject(new Error('Gateway exited before readiness'));});
    child.stderr.on('data',chunk=>{output=(output+chunk).slice(-8192);if(output.includes('GATEWAY_READY')){clearTimeout(timer);resolve();}});
  });
}
async function stop() {
  const current=child;if(!current||current.exitCode!==null||current.signalCode!==null)return;
  await new Promise((resolve,reject)=>{
    const timer=setTimeout(()=>{current.kill('SIGKILL');reject(new Error('Gateway shutdown deadline'));},7000);
    current.once('exit',(code,signal)=>{clearTimeout(timer);if(code===0&&!signal)resolve();else reject(new Error('Gateway did not stop cleanly'));});current.kill('SIGTERM');
  });
}
let cert;
async function http(route,body) {
  const encoded=body===undefined?undefined:JSON.stringify(body);
  return new Promise((resolve,reject)=>{
    const req=request({hostname:'127.0.0.1',port,servername:'localhost',ca:cert,rejectUnauthorized:true,path:route,method:encoded?'POST':'GET',
      headers:{Host:new URL(issuer).host,...(encoded?{'Content-Type':'application/json',Accept:'application/json, text/event-stream'}:{})}},response=>{
      let data='';response.setEncoding('utf8');response.on('data',chunk=>data+=chunk);response.on('error',reject);
      response.on('end',()=>resolve({status:response.statusCode,headers:response.headers,body:data}));
    });req.on('error',reject);req.end(encoded);
  });
}
try{
  const initialized=command(['--init','--config',configPath,'--issuer',issuer,'--callback',callback]);assert.equal(initialized.status,0);
  const certPath=path.join(directory,'tls','cert.pem'),keyPath=path.join(directory,'tls','key.pem');
  const generated=spawnSync('openssl',['req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:prime256v1','-nodes','-days','2','-subj','/CN=localhost',
    '-addext','subjectAltName=DNS:localhost','-keyout',keyPath,'-out',certPath],{encoding:'utf8',timeout:10000});assert.equal(generated.status,0);
  cert=await readFile(certPath);const config=JSON.parse(await readFile(configPath,'utf8'));config.transport.port=port;await writeFile(configPath,JSON.stringify(config));
  const authKey=await readFile(path.join(directory,'state','auth.key'));
  await start();assert.equal(command(['--healthcheck','--config',configPath],{NODE_EXTRA_CA_CERTS:certPath}).status,0);
  assert.equal(command(['--healthcheck','--config',configPath],{NODE_EXTRA_CA_CERTS:''}).status,1,'Health must reject an untrusted TLS certificate');
  assert.deepEqual(JSON.parse((await http('/health')).body),{status:'ready',relay:'attached'});
  const catalog=await http('/mcp',{jsonrpc:'2.0',id:1,method:'tools/list'});assert.equal(catalog.status,200);
  const tools=JSON.parse(catalog.body).result.tools;assert.equal(tools.length,5);for(const tool of tools)assert.deepEqual(tool.securitySchemes,[{type:'oauth2',scopes:['nas:read']}]);
  const denied=JSON.parse((await http('/mcp',{jsonrpc:'2.0',id:2,method:'tools/call',params:{name:'list_roots'}})).body).result;
  assert.equal(denied.isError,true);assert.ok(denied._meta['mcp/www_authenticate']);
  const metadata=JSON.parse((await http('/.well-known/oauth-protected-resource/mcp')).body);assert.equal(metadata.resource,new URL('mcp',issuer).href);
  const registered=await http('/register',{redirect_uris:[callback],token_endpoint_auth_method:'none'});assert.equal(registered.status,201);const client=JSON.parse(registered.body);
  assert.equal(command(['--config',configPath]).status,1,'A second process must not share the live database');
  await stop();await start();assert.deepEqual(await readFile(path.join(directory,'state','auth.key')),authKey);
  const params=new URLSearchParams({client_id:client.client_id,redirect_uri:callback,response_type:'code',resource:new URL('mcp',issuer).href,scope:'nas:read',state:'fixture-state',code_challenge_method:'S256',code_challenge:createHash('sha256').update('a'.repeat(43)).digest('base64url')});
  const authorization=await http('/authorize?'+params);assert.equal(authorization.status,302);assert.match(authorization.headers.location,/\/connect\/authorize\?request=/);
  await stop();await rm(path.join(directory,'state','auth.key'));const failed=command(['--config',configPath]);assert.equal(failed.status,1);assert.match(failed.stderr,/GATEWAY_STARTUP_FAILED/);assert.equal(failed.stderr.includes(authKey.toString('hex')),false);
  await assert.rejects(readFile(path.join(directory,'state','auth.key')));
  console.log('Bundled gateway TLS, OAuth discovery/catalog, private state, single-instance restart and key-loss refusal verified');
}finally{
  if(child&&child.exitCode===null&&child.signalCode===null)await stop();await rm(directory,{recursive:true,force:true});
}
