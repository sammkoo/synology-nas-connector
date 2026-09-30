import { test,before,after,beforeEach,afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp,readFile,writeFile,rm,chmod,stat,symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { createServer as netServer,connect as netConnect,type Socket } from 'node:net';
import { request as httpsRequest } from 'node:https';
import { request as httpRequest } from 'node:http';
import { generateKeyPairSync,sign,randomBytes,createHash } from 'node:crypto';
import { initializeGateway,loadGatewayDeployment,gatewayDeploymentSchema,readGatewayKey,type GatewayDeploymentConfig } from '../packages/gateway/src/deployment.js';
import { startGateway,checkGatewayHealth } from '../packages/gateway/src/service.js';
import { GatewayStore,DevicePairing,pairingApprovalMessage } from '../packages/gateway/src/index.js';
import { NasRelayAgent } from '../packages/relay/src/index.js';
import { NasFiles,configSchema } from '../packages/core/src/index.js';

let certificates:string,cert:Buffer,tlsKey:Buffer,directory:string;
let runtimes:Awaited<ReturnType<typeof startGateway>>[],agents:NasRelayAgent[];
before(async()=>{
  certificates=await mkdtemp(path.join(tmpdir(),'nas-gateway-certs-'));
  const generated=spawnSync('openssl',['req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:prime256v1','-nodes','-days','2','-subj','/CN=localhost',
    '-addext','subjectAltName=DNS:localhost','-keyout',path.join(certificates,'key.pem'),'-out',path.join(certificates,'cert.pem')],{encoding:'utf8'});
  assert.equal(generated.status,0,'OpenSSL must generate the TLS fixture');cert=await readFile(path.join(certificates,'cert.pem'));tlsKey=await readFile(path.join(certificates,'key.pem'));
});
after(async()=>{await rm(certificates,{recursive:true,force:true});});
beforeEach(async()=>{directory=await mkdtemp(path.join(tmpdir(),'nas-gateway-deploy-'));runtimes=[];agents=[];});
afterEach(async()=>{for(const agent of agents)await agent.stop();for(const runtime of runtimes)await runtime.close();await rm(directory,{recursive:true,force:true});});
async function freePort() {
  const server=netServer();await new Promise<void>(resolve=>server.listen(0,'127.0.0.1',resolve));const address=server.address();
  if(!address||typeof address==='string')throw new Error('No test port');await new Promise<void>(resolve=>server.close(()=>resolve()));return address.port;
}
async function initialized() {
  const port=await freePort(),configPath=path.join(directory,'install','config.json');
  await initializeGateway(configPath,`https://localhost:${port}/`,['https://client.example/callback']);
  const config=await loadGatewayDeployment(configPath);config.transport.port=port;
  await writeFile(path.join(directory,'install','tls','cert.pem'),cert,{mode:0o600});await writeFile(path.join(directory,'install','tls','key.pem'),tlsKey,{mode:0o600});
  return {configPath,config};
}
async function running(config:GatewayDeploymentConfig) {const runtime=await startGateway(config);runtimes.push(runtime);return runtime;}
async function request(config:GatewayDeploymentConfig,route:string,body?:unknown,extra:Record<string,string>={}) {
  const encoded=body===undefined?undefined:JSON.stringify(body);
  return new Promise<{status:number;headers:import('node:http').IncomingHttpHeaders;body:string}>((resolve,reject)=>{
    const req=httpsRequest({hostname:'127.0.0.1',port:config.transport.port,servername:'localhost',ca:cert,rejectUnauthorized:true,path:route,method:encoded?'POST':'GET',
      headers:{Host:new URL(config.issuer).host,...(encoded?{'Content-Type':'application/json',Accept:'application/json, text/event-stream'}:{}),...extra}},response=>{
      let body='';response.setEncoding('utf8');response.on('data',chunk=>body+=chunk);response.on('end',()=>resolve({status:response.statusCode!,headers:response.headers,body}));response.on('error',reject);
    });req.on('error',reject);req.end(encoded);
  });
}
test('explicit initialization keeps config, key and database private and never overwrites an installation',async()=>{
  const {configPath,config}=await initialized(),key=await readFile(path.join(config.dataDirectory,'auth.key'));
  assert.equal(key.length,32);
  for(const file of [configPath,path.join(config.dataDirectory,'auth.key'),path.join(config.dataDirectory,'installation.json'),path.join(config.dataDirectory,'gateway.sqlite')])assert.equal((await stat(file)).mode&0o777,0o600);
  assert.equal((await stat(config.dataDirectory)).mode&0o777,0o700);
  await assert.rejects(initializeGateway(configPath,config.issuer,config.redirectUris));
  assert.deepEqual(await readGatewayKey(config),key);
  const loaded=await loadGatewayDeployment(configPath);assert.equal(path.isAbsolute(loaded.dataDirectory),true);
  assert.equal(gatewayDeploymentSchema.safeParse({...config,extra:true}).success,false);
  for(const bad of ['http://gateway.example/','https://gateway.example','https://user:password@gateway.example/','https://gateway.example/?token=x'])
    assert.equal(gatewayDeploymentSchema.safeParse({...config,issuer:bad}).success,false);
  assert.equal(gatewayDeploymentSchema.safeParse({...config,redirectUris:['https://client.example/*#fragment']}).success,false);
});
test('startup rejects lost/replaced keys, changed issuer, missing database and unsafe file permissions',async()=>{
  const {configPath,config}=await initialized(),keyPath=path.join(config.dataDirectory,'auth.key'),key=await readFile(keyPath);
  await assert.rejects(startGateway({...config,issuer:'https://other.example/'}),/issuer or key changed/);
  await rm(keyPath);await assert.rejects(startGateway(config));await assert.rejects(readFile(keyPath));
  await writeFile(keyPath,randomBytes(32),{mode:0o600});await assert.rejects(startGateway(config),/issuer or key changed/);
  await writeFile(keyPath,key);await chmod(keyPath,0o644);await assert.rejects(startGateway(config),/Unsafe/);await chmod(keyPath,0o600);
  await chmod(configPath,0o644);await assert.rejects(loadGatewayDeployment(configPath),/Unsafe/);await chmod(configPath,0o600);
  const keyFile=(config.transport as Extract<GatewayDeploymentConfig['transport'],{mode:'https'}>).privateKeyFile;
  await chmod(keyFile,0o644);await assert.rejects(startGateway(config),/Unsafe/);await chmod(keyFile,0o600);
  await rm(path.join(config.dataDirectory,'gateway.sqlite'));await assert.rejects(startGateway(config));
  await assert.rejects(readFile(path.join(config.dataDirectory,'gateway.sqlite')));
});
test('symlink replacements and partial installations fail closed rather than bootstrap a new identity',async()=>{
  const {configPath,config}=await initialized(),keyPath=path.join(config.dataDirectory,'auth.key'),original=await readFile(keyPath),replacement=path.join(directory,'replacement');
  await writeFile(replacement,original,{mode:0o600});await rm(keyPath);await symlink(replacement,keyPath);await assert.rejects(startGateway(config));
  await rm(keyPath);await writeFile(keyPath,original,{mode:0o600});
  await rm(path.join(config.dataDirectory,'installation.json'));await assert.rejects(startGateway(config));
  await assert.rejects(initializeGateway(configPath,config.issuer,config.redirectUris));assert.deepEqual(await readFile(keyPath),original);
});
test('a database restored from a different installation cannot silently invalidate an existing key',async()=>{
  const {config}=await initialized(),key=await readFile(path.join(config.dataDirectory,'auth.key'));
  await rm(path.join(config.dataDirectory,'gateway.sqlite'));
  const replacement=await GatewayStore.open(config.dataDirectory,randomBytes(32));
  replacement.put('installation','gateway',{version:1,issuer:config.issuer,keyCheck:replacement.key('installation','gateway-deployment-v1')},Number.MAX_SAFE_INTEGER);replacement.close();
  await assert.rejects(startGateway(config),/backup mismatch/);assert.deepEqual(await readFile(path.join(config.dataDirectory,'auth.key')),key);
});
test('real HTTPS runtime preserves paired ownership/grants across restart and rejects a concurrent instance',async()=>{
  const {config}=await initialized(),first=await running(config),nas=generateKeyPairSync('ed25519');
  assert.deepEqual(JSON.parse((await request(config,'/health')).body),{status:'ready',relay:'attached'});
  const browser=await request(config,'/connect/');assert.match(browser.headers['set-cookie']![0]!,/Secure/);assert.match(String(browser.headers['content-security-policy']),/frame-ancestors 'none'/);
  const pairing=new DevicePairing(first.oauth),begun=pairing.begin(nas.publicKey.export({type:'spki',format:'der'}).toString('base64url'),'NAS fixture',['docs']);
  const browserKey=randomBytes(32).toString('base64url');pairing.claim(begun.userCode,browserKey);const proof=pairing.poll(begun.deviceCode);if(proof.state!=='confirmation-required')throw new Error('No challenge');
  pairing.approve(begun.deviceCode,sign(null,pairingApprovalMessage(proof),nas.privateKey).toString('base64url'));const account=pairing.completeBrowser(browserKey);
  const client=await first.oauth.clientsStore.registerClient!({redirect_uris:config.redirectUris,token_endpoint_auth_method:'none'}),verifier=randomBytes(32).toString('base64url');
  const pending=first.oauth.beginAuthorization(client,{redirectUri:config.redirectUris[0]!,resource:new URL(first.oauth.resource),state:'state',scopes:['nas:read'],codeChallenge:createHash('sha256').update(verifier).digest('base64url')});
  const code=new URL(first.oauth.approveAuthorization(pending,account.subject,account.deviceId,['docs'])).searchParams.get('code')!;
  const tokens=await first.oauth.exchangeAuthorizationCode(client,code,verifier,config.redirectUris[0],new URL(first.oauth.resource));
  await writeFile(path.join(directory,'hello.md'),'runtime TLS document');const files=await NasFiles.create(configSchema.parse({roots:[{id:'docs',label:'Documents',path:directory}],http:{tokenFile:'unused'}}));
  const agent=new NasRelayAgent({issuer:config.issuer,privateKey:nas.privateKey,source:files,trust:{ca:cert,lookup:(_host,options,cb)=>{if(options.all)cb(null,[{address:'127.0.0.1',family:4}]);else cb(null,'127.0.0.1',4);}}});agents.push(agent);await agent.connect();
  const read=()=>request(config,'/mcp',{jsonrpc:'2.0',id:1,method:'tools/call',params:{name:'read_text',arguments:{rootId:'docs',path:'hello.md'}}},{Authorization:`Bearer ${tokens.access_token}`});
  assert.match((await read()).body,/runtime TLS document/);await assert.rejects(startGateway(config),/locked/);
  await agent.stop();await first.close();const second=await running(config);await agent.connect();
  assert.deepEqual(second.oauth.devicesFor(account.subject).map(d=>d.id),[account.deviceId]);assert.match((await read()).body,/runtime TLS document/);
  await second.oauth.revokeToken(client,{token:tokens.access_token});assert.equal((await read()).status,401);
});
test('proxy mode is loopback-only and requires exact overwritten provenance; its health probe is local',async()=>{
  const {config}=await initialized();
  config.transport={mode:'proxy',host:'127.0.0.1',port:config.transport.port,trustedProxyAddresses:['127.0.0.1']};
  assert.equal(gatewayDeploymentSchema.safeParse({...config,transport:{...config.transport,host:'0.0.0.0'}}).success,false);
  assert.equal(gatewayDeploymentSchema.safeParse({...config,transport:{...config.transport,trustedProxyAddresses:['192.0.2.1']}}).success,false);
  await running(config);
  const get=(headers:Record<string,string>)=>new Promise<number>((resolve,reject)=>{const req=httpRequest({host:'127.0.0.1',port:config.transport.port,path:'/health',headers:{Host:new URL(config.issuer).host,...headers}},res=>{res.resume();res.on('end',()=>resolve(res.statusCode!));});req.on('error',reject);req.end();});
  assert.equal(await get({}),403);assert.equal(await get({'X-Forwarded-Proto':'https','X-Forwarded-For':'127.0.0.1, 192.0.2.1'}),403);
  assert.equal(await get({'X-Forwarded-Proto':'https','X-Forwarded-For':'192.0.2.1'}),200);await checkGatewayHealth(config);
});
test('listener caps pending TLS sockets and continues serving after excess connections are dropped',async()=>{
  const {config}=await initialized();config.limits.maxConnections=2;const runtime=await running(config),sockets:Socket[]=[],incoming:Socket[]=[];
  runtime.server.on('connection',socket=>incoming.push(socket));
  try{
    for(let i=0;i<2;i++){
      const accepted=new Promise<void>(resolve=>runtime.server.once('connection',()=>resolve()));const socket=netConnect(config.transport.port,'127.0.0.1');sockets.push(socket);socket.on('error',()=>{});await accepted;
    }
    const denied=netConnect(config.transport.port,'127.0.0.1');sockets.push(denied);denied.on('error',()=>{});
    await new Promise<void>((resolve,reject)=>{const timer=setTimeout(()=>reject(new Error('Excess connection remained open')),2000);denied.once('close',()=>{clearTimeout(timer);resolve();});});
  }finally{for(const socket of sockets)socket.destroy();}
  await Promise.all(incoming.map(socket=>new Promise<void>(resolve=>{if(socket.destroyed)resolve();else socket.once('close',()=>resolve());})));
  assert.equal((await request(config,'/health')).status,200);
});
test('database budget rejects excess writes while retaining committed records and releases its exclusive lock',async()=>{
  const state=path.join(directory,'bounded');const store=await GatewayStore.open(state,Buffer.alloc(32,4),Date.now,{exclusive:true,maxDatabaseBytes:65536});
  try{
    store.put('fixture','retained',{value:'committed'},Date.now()+60000);
    assert.throws(()=>store.put('fixture','too-large',{value:'x'.repeat(128*1024)},Date.now()+60000),/full/);
    assert.deepEqual(store.get('fixture','retained'),{value:'committed'});assert.equal(store.get('fixture','too-large'),undefined);
  }finally{store.close();}
  const again=await GatewayStore.open(state,Buffer.alloc(32,4),Date.now,{exclusive:true,create:false});assert.deepEqual(again.get('fixture','retained'),{value:'committed'});again.close();
});
