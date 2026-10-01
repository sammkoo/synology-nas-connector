import { test,before,after,beforeEach,afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp,mkdir,writeFile,readFile,rm,chmod,stat,symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { createServer,type Server } from 'node:https';
import { randomBytes,sign,generateKeyPairSync,createHash } from 'node:crypto';
import type { LookupFunction } from 'node:net';
import { lookup as dnsLookup } from 'node:dns';
import express from 'express';
import { configSchema,NasFiles,type ReadOnlyFiles } from '../packages/core/src/index.js';
import { NasConnectionController,ConfigurationStore,ShareCatalog,BridgeGuard,signBridgeRequest } from '../packages/management/src/index.js';
import { managementRouter } from '../apps/server/src/management.js';
import { GatewayStore,GatewayOAuthProvider,DevicePairing,createGatewayRuntime,GatewayRelay } from '../packages/gateway/src/index.js';
import { GatewayAgentClient,isPublicGatewayAddress,publicGatewayLookup,canonicalGatewayIssuer,loadOrCreateRelayIdentity,deviceRevocationMessage,NasRelayAgent } from '../packages/relay/src/index.js';

let certDirectory:string,cert:Buffer,key:Buffer,directory:string,store:GatewayStore,oauth:GatewayOAuthProvider,pairing:DevicePairing,server:Server,hub:GatewayRelay,issuer:string;
let files:ReadOnlyFiles,source:ReadOnlyFiles,controllers:NasConnectionController[];
const lookup:LookupFunction=(_hostname,options,cb)=>{if(options.all)cb(null,[{address:'127.0.0.1',family:4}]);else cb(null,'127.0.0.1',4);};
const wait=async(predicate:()=>boolean)=>{const end=Date.now()+4000;while(!predicate()){if(Date.now()>end)throw new Error('Fixture deadline');await new Promise(r=>setTimeout(r,10));}};
before(async()=>{
  certDirectory=await mkdtemp(path.join(tmpdir(),'nas-connection-ca-'));const certPath=path.join(certDirectory,'cert.pem'),keyPath=path.join(certDirectory,'key.pem');
  const r=spawnSync('openssl',['req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:prime256v1','-nodes','-days','2','-subj','/CN=gateway.example','-addext','subjectAltName=DNS:gateway.example','-keyout',keyPath,'-out',certPath],{encoding:'utf8'});
  assert.equal(r.status,0);cert=await readFile(certPath);key=await readFile(keyPath);
});
after(async()=>{await rm(certDirectory,{recursive:true,force:true});});
beforeEach(async()=>{
  directory=await mkdtemp(path.join(tmpdir(),'nas-connection-'));controllers=[];
  await mkdir(path.join(directory,'docs'));await writeFile(path.join(directory,'docs','note.txt'),'NAS setup integration fixture');
  files=await NasFiles.create(configSchema.parse({roots:[{id:'docs',label:'Documents',path:path.join(directory,'docs')}],http:{tokenFile:'unused'}}));source=files;
  store=await GatewayStore.open(path.join(directory,'gateway'),Buffer.alloc(32,7));
  let app:ReturnType<typeof createGatewayRuntime>['app']|undefined;
  server=createServer({key,cert},(req,res)=>{if(app)app(req,res);else res.writeHead(503).end();});server.listen(0,'127.0.0.1');await new Promise<void>(r=>server.once('listening',r));
  issuer=`https://gateway.example:${(server.address() as {port:number}).port}/`;
  oauth=new GatewayOAuthProvider(store,{issuer,resource:new URL('mcp',issuer).href,redirectUris:['https://client.example/callback']});pairing=new DevicePairing(oauth);
  const runtime=createGatewayRuntime(oauth);app=runtime.app;hub=runtime.relay;hub.attach(server);
});
afterEach(async()=>{
  for(const c of controllers)await c.stop();hub.close();server.closeAllConnections();await new Promise<void>(r=>server.close(()=>r()));store.close();await rm(directory,{recursive:true,force:true});
});
function controller(folder='nas',provider:()=>ReadOnlyFiles=()=>source){const c=new NasConnectionController(path.join(directory,folder),provider,{ca:cert,lookup});controllers.push(c);return c;}
function alterPoll(mutate:(reply:ReturnType<DevicePairing['poll']>)=>unknown) {
  const original=server.listeners('request')[0]!;server.removeAllListeners('request');
  server.on('request',(req,res)=>{
    if(req.url!=='/agent/pair/poll'){original.call(server,req,res);return;}
    const chunks:Buffer[]=[];req.on('data',chunk=>chunks.push(Buffer.from(chunk)));req.on('end',()=>{
      const body=JSON.parse(Buffer.concat(chunks).toString());res.writeHead(200,{'Content-Type':'application/json'}).end(JSON.stringify(mutate(pairing.poll(body.deviceCode))));
    });
  });return ()=>{server.removeAllListeners('request');server.on('request',original as Parameters<Server['on']>[1]);};
}
async function confirm(c:NasConnectionController) {
  const start=await c.begin('admin',issuer,'Home NAS',source);assert.ok('userCode' in start&&start.userCode);
  const browser=randomBytes(32).toString('base64url');pairing.claim(start.userCode,browser);
  const proof=await c.poll('admin');assert.ok('pairId' in proof&&'proofHash' in proof&&'comparison' in proof);
  await c.confirm('admin',proof.pairId!,proof.proofHash!,proof.comparison!);return pairing.completeBrowser(browser);
}
async function grant(account:{subject:string;deviceId:string}) {
  const client=await oauth.clientsStore.registerClient!({redirect_uris:['https://client.example/callback'],token_endpoint_auth_method:'none'}),verifier=randomBytes(32).toString('base64url');
  const h=oauth.beginAuthorization(client,{redirectUri:client.redirect_uris[0]!,state:'fixture-state',scopes:['nas:read'],resource:new URL(oauth.resource),codeChallenge:createHash('sha256').update(verifier).digest('base64url')});
  const callback=new URL(oauth.approveAuthorization(h,account.subject,account.deviceId,source.listRoots().map(r=>r.id)));
  return oauth.exchangeAuthorizationCode(client,callback.searchParams.get('code')!,verifier,client.redirect_uris[0],new URL(oauth.resource));
}
test('pairing over verified HTTPS keeps private credentials off the DSM response; restart restores real NAS reads',async()=>{
  const c=controller();await c.restore();assert.equal(c.status('admin').state,'not-configured');
  await assert.rejects(()=>stat(path.join(directory,'nas')),/ENOENT/);
  const start=await c.begin('admin',issuer,'Home NAS',source);assert.ok('userCode' in start&&start.userCode);
  assert.doesNotMatch(JSON.stringify(start),/deviceCode|privateKey|identity.key|challenge|browserKey/);assert.equal(c.status('other').state,'busy');
  await assert.rejects(()=>c.poll('other'),/PAIRING_OTHER_ADMIN/);
  const browser=randomBytes(32).toString('base64url');pairing.claim(start.userCode,browser);
  const proof=await c.poll('admin');assert.ok('pairId' in proof&&'proofHash' in proof&&'comparison' in proof);
  assert.doesNotMatch(JSON.stringify(proof),/deviceCode|privateKey|challenge|browserKey/);
  await assert.rejects(()=>c.confirm('other',proof.pairId!,proof.proofHash!,proof.comparison!),/PAIRING_OTHER_ADMIN/);
  await assert.rejects(()=>c.confirm('admin',proof.pairId!,'0'.repeat(64),proof.comparison!),/PAIRING_CHANGED/);
  assert.equal(hub.onlineCount,0);
  await c.confirm('admin',proof.pairId!,proof.proofHash!,proof.comparison!);const account=pairing.completeBrowser(browser),tokens=await grant(account);
  await wait(()=>c.status('admin').state==='online');const principal=await oauth.authenticator().authenticate(tokens.access_token);assert.ok(principal);
  assert.match((await hub.filesFor(principal).readText('docs','note.txt')).text,/integration fixture/);
  const record=JSON.parse(await readFile(path.join(directory,'nas','connection.json'),'utf8'));assert.equal(record.deviceId,account.deviceId);assert.equal(record.enabled,true);
  for(const f of ['identity.key','connection.json'])assert.equal((await stat(path.join(directory,'nas',f))).mode&0o777,0o600);
  assert.equal((await stat(path.join(directory,'nas'))).mode&0o777,0o700);
  await c.stop();const restored=controller();await restored.restore();await wait(()=>restored.status('admin').state==='online');
  assert.match((await hub.filesFor((await oauth.authenticator().authenticate(tokens.access_token))!).readText('docs','note.txt')).text,/integration fixture/);
  await restored.disconnect('admin');assert.equal(restored.status('admin').state,'disconnected');assert.equal((restored.status('admin') as {revocationPending:boolean}).revocationPending,false);
  await assert.rejects(()=>oauth.verifyAccessToken(tokens.access_token));assert.equal(hub.isOnline(account.deviceId,account.subject),false);
});
test('a folder policy change invalidates pending proof and the previous administrator cannot confirm',async()=>{
  const c=controller(),start=await c.begin('admin',issuer,'Home NAS',source);assert.ok('userCode' in start&&start.userCode);
  const browser=randomBytes(32).toString('base64url');pairing.claim(start.userCode,browser);const proof=await c.poll('admin');assert.ok('pairId' in proof&&'proofHash' in proof&&'comparison' in proof);
  source=await NasFiles.create(configSchema.parse({roots:[],http:{tokenFile:'unused'}}));
  await assert.rejects(()=>c.confirm('admin',proof.pairId!,proof.proofHash!,proof.comparison!),/CONFIGURATION_CHANGED/);
  assert.equal(hub.onlineCount,0);assert.equal(c.status('admin').state,'not-configured');assert.throws(()=>pairing.completeBrowser(browser));
  await assert.rejects(()=>c.begin('admin',issuer,'Home NAS',source),/SELECT_FOLDERS_FIRST/);
});
test('a validly shaped gateway reply cannot substitute issuer, identity, label, folders or pre-approved state',async()=>{
  const replacements=[{issuer:'https://other.example/'},{publicKey:generateKeyPairSync('ed25519').publicKey.export({type:'spki',format:'der'}).toString('base64url')},{label:'Another NAS'},{rootIds:['secret']}];
  for(let i=0;i<replacements.length;i++){
    const c=controller(`substitution-${i}`),start=await c.begin('admin',issuer,'Home NAS',source);assert.ok('userCode' in start&&start.userCode);
    pairing.claim(start.userCode,randomBytes(32).toString('base64url'));const restore=alterPoll(reply=>({...reply,...replacements[i]}));
    try{await assert.rejects(()=>c.poll('admin'),/PAIRING_PROOF_INVALID/);assert.equal(hub.onlineCount,0);assert.equal(c.status('admin').state,'pairing');}finally{restore();}
  }
  const c=controller('pre-approved');await c.begin('admin',issuer,'Home NAS',source);
  const restore=alterPoll(()=>({state:'approved',deviceId:'00000000-0000-4000-8000-000000000000'}));
  try{await assert.rejects(()=>c.poll('admin'),/PAIRING_PROOF_INVALID/);assert.equal(hub.onlineCount,0);}finally{restore();}
});
test('confirmation re-polls and refuses a replaced comparison proof even when its visible number is unchanged',async()=>{
  const c=controller(),start=await c.begin('admin',issuer,'Home NAS',source);assert.ok('userCode' in start&&start.userCode);
  pairing.claim(start.userCode,randomBytes(32).toString('base64url'));const proof=await c.poll('admin');assert.ok('pairId' in proof&&'proofHash' in proof&&'comparison' in proof);
  const restore=alterPoll(reply=>({...reply,challenge:randomBytes(32).toString('base64url')}));
  try{await assert.rejects(()=>c.confirm('admin',proof.pairId!,proof.proofHash!,proof.comparison!),/PAIRING_CHANGED/);assert.equal(hub.onlineCount,0);}
  finally{restore();}
});
test('a policy change after remote approval rolls back connection state and revokes the approved device',async()=>{
  const c=controller(),start=await c.begin('admin',issuer,'Home NAS',source);assert.ok('userCode' in start&&start.userCode);
  const browser=randomBytes(32).toString('base64url');pairing.claim(start.userCode,browser);const proof=await c.poll('admin');assert.ok('pairId' in proof&&'proofHash' in proof&&'comparison' in proof);
  const original=server.listeners('request')[0]!;server.removeAllListeners('request');
  server.on('request',(req,res)=>{
    if(req.url!=='/agent/pair/approve'){original.call(server,req,res);return;}
    const chunks:Buffer[]=[];req.on('data',chunk=>chunks.push(Buffer.from(chunk)));req.on('end',()=>{void(async()=>{
      const body=JSON.parse(Buffer.concat(chunks).toString()),approved=pairing.approve(body.deviceCode,body.signature);
      source=await NasFiles.create(configSchema.parse({roots:[],http:{tokenFile:'unused'}}));res.writeHead(200,{'Content-Type':'application/json'}).end(JSON.stringify(approved));
    })();});
  });
  await assert.rejects(()=>c.confirm('admin',proof.pairId!,proof.proofHash!,proof.comparison!),/CONFIGURATION_CHANGED/);
  const account=pairing.completeBrowser(browser);assert.equal(oauth.deviceIsActive(account.deviceId,account.subject),false);assert.equal(hub.onlineCount,0);
  const record=JSON.parse(await readFile(path.join(directory,'nas','connection.json'),'utf8'));assert.equal(record.enabled,false);assert.equal(record.revocationPending,false);
});
test('a lost approval response can recover on a later poll only after explicit NAS confirmation',async()=>{
  const c=controller(),start=await c.begin('admin',issuer,'Home NAS',source);assert.ok('userCode' in start&&start.userCode);
  const browser=randomBytes(32).toString('base64url');pairing.claim(start.userCode,browser);const proof=await c.poll('admin');assert.ok('pairId' in proof&&'proofHash' in proof&&'comparison' in proof);
  const original=server.listeners('request')[0]!;server.removeAllListeners('request');let approved=false,denyRecovery=true;
  server.on('request',(req,res)=>{
    if(req.url==='/agent/pair/poll'&&approved&&denyRecovery){denyRecovery=false;res.writeHead(503,{'Content-Type':'application/json'}).end('{}');return;}
    if(req.url!=='/agent/pair/approve'){original.call(server,req,res);return;}
    const chunks:Buffer[]=[];req.on('data',chunk=>chunks.push(Buffer.from(chunk)));req.on('end',()=>{
      const body=JSON.parse(Buffer.concat(chunks).toString());pairing.approve(body.deviceCode,body.signature);approved=true;res.destroy();
    });
  });
  await assert.rejects(()=>c.confirm('admin',proof.pairId!,proof.proofHash!,proof.comparison!),/GATEWAY_REQUEST_DENIED/);
  assert.equal(hub.onlineCount,0);assert.equal(c.status('admin').state,'confirmation-required');
  await c.poll('admin');await wait(()=>c.status('admin').state==='online');const account=pairing.completeBrowser(browser);
  assert.equal(hub.isOnline(account.deviceId,account.subject),true);
});
test('missing identity, replaced identity, private-file symlinks and writable-by-others state fail closed on restart',async()=>{
  const c=controller();await confirm(c);await wait(()=>c.status('admin').state==='online');await c.stop();
  const identityPath=path.join(directory,'nas','identity.key'),original=await readFile(identityPath);
  await rm(identityPath);const missing=controller();await missing.restore();assert.equal(missing.status('admin').state,'error');await assert.rejects(()=>stat(identityPath),/ENOENT/);
  await assert.rejects(()=>missing.begin('admin',issuer,'Home NAS',source),/CONNECTION_RESTORE_FAILED/);
  const replacement=generateKeyPairSync('ed25519').privateKey.export({format:'pem',type:'pkcs8'});await writeFile(identityPath,replacement,{mode:0o600});const changed=controller();await changed.restore();assert.equal(changed.status('admin').state,'error');
  await writeFile(identityPath,original);await chmod(identityPath,0o644);const permissions=controller();await permissions.restore();assert.equal(permissions.status('admin').state,'error');
  await rm(identityPath);await symlink(path.join(directory,'docs','note.txt'),identityPath);const linked=controller();await linked.restore();assert.equal(linked.status('admin').state,'error');assert.equal(hub.onlineCount,0);
});
test('an offline gateway cannot resume NAS transmission after disconnect; revocation completes on restart',async()=>{
  const c=controller();const account=await confirm(c),tokens=await grant(account);await wait(()=>c.status('admin').state==='online');
  hub.close();server.closeAllConnections();await new Promise<void>(r=>server.close(()=>r()));
  const status=await c.disconnect('admin');assert.equal(status.state,'disconnected');assert.equal('revocationPending' in status&&status.revocationPending,true);
  const saved=JSON.parse(await readFile(path.join(directory,'nas','connection.json'),'utf8'));assert.equal(saved.enabled,false);assert.equal(saved.revocationPending,true);await c.stop();
  const runtime=createGatewayRuntime(oauth);hub=runtime.relay;server=createServer({key,cert},runtime.app);hub.attach(server);server.listen(Number(new URL(issuer).port),'127.0.0.1');await new Promise<void>(r=>server.once('listening',r));
  const restored=controller();await restored.restore();assert.equal(restored.status('admin').state,'disconnected');assert.equal('revocationPending' in restored.status('admin')&&(restored.status('admin') as {revocationPending:boolean}).revocationPending,false);
  assert.equal(hub.onlineCount,0);await assert.rejects(()=>oauth.verifyAccessToken(tokens.access_token));
});
test('NAS revocation signatures reject wrong issuer, key, device, old timestamps and replay; re-pairing changes the revoked device ID',async()=>{
  const c=controller();const account=await confirm(c),identity=await loadOrCreateRelayIdentity(path.join(directory,'nas'),false),client=new GatewayAgentClient(issuer,{ca:cert,lookup});
  const request={publicKey:identity.publicKey,deviceId:account.deviceId,timestamp:Date.now(),nonce:randomBytes(32).toString('base64url')};
  const signed=(value= request,issuerValue=issuer,keyValue=identity.privateKey)=>({...value,signature:sign(null,deviceRevocationMessage(issuerValue,value),keyValue).toString('base64url')});
  await assert.rejects(()=>client.revoke(signed(request,'https://wrong.example/')),/GATEWAY_REQUEST_DENIED/);
  await assert.rejects(()=>client.revoke(signed(request,issuer,generateKeyPairSync('ed25519').privateKey)),/GATEWAY_REQUEST_DENIED/);
  await assert.rejects(()=>client.revoke(signed({...request,deviceId:'00000000-0000-4000-8000-000000000000'})),/GATEWAY_REQUEST_DENIED/);
  await assert.rejects(()=>client.revoke(signed({...request,timestamp:Date.now()-120000})),/GATEWAY_REQUEST_DENIED/);
  await client.revoke(signed());await assert.rejects(()=>client.revoke(signed()),/GATEWAY_REQUEST_DENIED/);
  await c.disconnect('admin');const again=await confirm(c);assert.notEqual(again.deviceId,account.deviceId);
  await assert.rejects(()=>client.revoke(signed({...request,nonce:randomBytes(32).toString('base64url')})),/GATEWAY_REQUEST_DENIED/);
  assert.equal(oauth.deviceIsActive(again.deviceId,again.subject),true);
});
test('public-only DNS validation rejects private, mapped, reserved, mixed-answer and rebinding targets',async()=>{
  for(const address of ['127.0.0.1','10.0.0.1','172.16.0.2','192.168.1.1','100.64.0.1','169.254.169.254','192.0.2.1','198.18.0.1','224.0.0.1','::1','::2','::ffff:127.0.0.1','fc00::1','fe80::1','2001:db8::1','64:ff9b::a00:1'])assert.equal(isPublicGatewayAddress(address),false,address);
  for(const address of ['1.1.1.1','8.8.8.8','2606:4700:4700::1111','::ffff:8.8.8.8'])assert.equal(isPublicGatewayAddress(address),true,address);
  assert.equal(canonicalGatewayIssuer(' https://gateway.example '),'https://gateway.example/');
  for(const value of ['http://gateway.example/','https://admin:secret@gateway.example/','https://gateway.example/mcp','https://gateway.example/?q=x'])assert.throws(()=>new GatewayAgentClient(value));
  for(const value of ['https://127.0.0.1/','https://2130706433/','https://[::1]/'])assert.throws(()=>new GatewayAgentClient(value),/GATEWAY_ADDRESS_DENIED/);
  let addresses=[{address:'8.8.8.8',family:4}];const resolver=((_host:unknown,_options:unknown,callback:(error:null,values:typeof addresses)=>void)=>callback(null,addresses)) as typeof dnsLookup;
  const safe=publicGatewayLookup(resolver),call=()=>new Promise<unknown>((resolve,reject)=>safe('gateway.example',{all:true},(e,address)=>e?reject(e):resolve(address)));
  assert.deepEqual(await call(),addresses);addresses=[{address:'8.8.8.8',family:4},{address:'10.0.0.1',family:4}];await assert.rejects(call,/GATEWAY_ADDRESS_DENIED/);
  addresses=[{address:'127.0.0.1',family:4}];await assert.rejects(call,/GATEWAY_ADDRESS_DENIED/);
});
test('untrusted TLS, mismatched verification endpoint, redirects and oversized JSON never pair',async()=>{
  const identity=await loadOrCreateRelayIdentity(path.join(directory,'key'));
  await assert.rejects(()=>new GatewayAgentClient(issuer,{lookup}).begin(identity.publicKey,'NAS',['docs']),/GATEWAY_TLS_REQUIRED/);
  const bad=createServer({key,cert},(_req,res)=>res.writeHead(302,{Location:issuer}).end());bad.listen(0,'127.0.0.1');await new Promise<void>(r=>bad.once('listening',r));
  const badIssuer=`https://gateway.example:${(bad.address() as {port:number}).port}/`,client=new GatewayAgentClient(badIssuer,{lookup,ca:cert});
  try{
    await assert.rejects(()=>client.begin(identity.publicKey,'NAS',['docs']),/GATEWAY_REQUEST_DENIED/);
    bad.removeAllListeners('request');bad.on('request',(_req,res)=>res.writeHead(200,{'Content-Type':'application/json'}).end(JSON.stringify({deviceCode:'a'.repeat(43),userCode:'A'.repeat(16),expiresIn:600,verificationUri:'https://attacker.example/'})));
    await assert.rejects(()=>client.begin(identity.publicKey,'NAS',['docs']),/GATEWAY_RESPONSE_INVALID/);
    bad.removeAllListeners('request');bad.on('request',(_req,res)=>res.writeHead(200,{'Content-Type':'application/json'}).end('x'.repeat(17000)));
    await assert.rejects(()=>client.begin(identity.publicKey,'NAS',['docs']),/GATEWAY_RESPONSE_INVALID/);
  }finally{bad.closeAllConnections();await new Promise<void>(r=>bad.close(()=>r()));}
});
test('a persisted device ID cannot silently switch when a gateway returns another paired identity',async()=>{
  const c=controller(),account=await confirm(c);await wait(()=>c.status('admin').state==='online');await c.stop();
  const identity=await loadOrCreateRelayIdentity(path.join(directory,'nas'),false),agent=new NasRelayAgent({issuer,privateKey:identity.privateKey,expectedDeviceId:'00000000-0000-4000-8000-000000000000',source,trust:{ca:cert,lookup}});
  try{await assert.rejects(()=>agent.connect(),/RELAY_CONNECTION_FAILED/);assert.equal(agent.state,'offline');assert.equal(oauth.deviceIsActive(account.deviceId,account.subject),true);}finally{await agent.stop();}
});
test('signed DSM routes enforce administrator-bound CSRF and explicit destination consent through the full pairing flow',async()=>{
  const volume=path.join(directory,'volume1');await mkdir(volume);await mkdir(path.join(volume,'Documents'));await writeFile(path.join(volume,'Documents','note.txt'),'DSM route fixture');
  const filename=path.join(directory,'config.json'),config=configSchema.parse({roots:[],http:{tokenFile:'unused'}});await writeFile(filename,JSON.stringify(config),{mode:0o600});
  const configuration=await ConfigurationStore.create(filename,config,new ShareCatalog([volume])),c=controller('managed',()=>configuration.getFiles());
  const secret=Buffer.alloc(32,10),guard=new BridgeGuard(secret),app=express();app.use('/manage',managementRouter(configuration,guard,c));const listener=app.listen(0,'127.0.0.1');await new Promise<void>(r=>listener.once('listening',r));
  const base=`http://127.0.0.1:${(listener.address() as {port:number}).port}`;
  async function call(action:string,body?:unknown,csrf='',user='admin'){
    const bytes=body===undefined?Buffer.alloc(0):Buffer.from(JSON.stringify(body)),request={method:body===undefined?'GET':'POST',path:`/manage/${action}`,user,csrf,timestamp:String(Date.now()),nonce:randomBytes(32).toString('hex'),body:bytes};
    return fetch(base+request.path,{method:request.method,headers:{'Content-Type':'application/json','x-nas-user':user,'x-nas-csrf':csrf,'x-nas-timestamp':request.timestamp,'x-nas-nonce':request.nonce,'x-nas-signature':signBridgeRequest(secret,request)},...(body===undefined?{}:{body:bytes.toString()})});
  }
  try{
    const bootstrap=await (await call('bootstrap')).json() as {csrf:string;revision:string;shares:{id:string}[]};
    const saved=await (await call('roots',{ids:[bootstrap.shares[0]!.id],revision:bootstrap.revision},bootstrap.csrf)).json() as {revision:string};
    const begin={issuer,label:'Home NAS',consent:true,revision:saved.revision};
    assert.equal((await call('pair-begin',begin)).status,419);assert.equal((await call('pair-begin',{...begin,consent:false},bootstrap.csrf)).status,400);
    assert.equal((await call('pair-begin',{...begin,revision:bootstrap.revision},bootstrap.csrf)).status,409);
    const response=await call('pair-begin',begin,bootstrap.csrf);assert.equal(response.status,200);const start=await response.json() as {userCode:string};assert.doesNotMatch(JSON.stringify(start),/deviceCode|identity.key|privateKey/);
    const browser=randomBytes(32).toString('base64url');pairing.claim(start.userCode,browser);
    const proof=await (await call('pair-status',{},bootstrap.csrf)).json() as {pairId:string;proofHash:string;comparison:string};
    assert.equal((await call('pair-confirm',proof,bootstrap.csrf,'other-admin')).status,419);
    assert.equal((await call('pair-confirm',{pairId:proof.pairId,proofHash:proof.proofHash,comparison:proof.comparison},bootstrap.csrf)).status,200);
    const account=pairing.completeBrowser(browser);await wait(()=>c.status('admin').state==='online');assert.equal(hub.isOnline(account.deviceId,account.subject),true);
    assert.equal((await call('pair-disconnect',{},bootstrap.csrf)).status,200);assert.equal(oauth.deviceIsActive(account.deviceId,account.subject),false);
  }finally{listener.closeAllConnections();await new Promise<void>(r=>listener.close(()=>r()));}
});
