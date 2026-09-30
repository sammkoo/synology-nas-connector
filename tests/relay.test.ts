import { test,before,after,beforeEach,afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp,mkdir,writeFile,readFile,rm,chmod,symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { createServer,request as httpsRequest,type Server } from 'node:https';
import type { LookupFunction } from 'node:net';
import { generateKeyPairSync,randomBytes,createHash,sign } from 'node:crypto';
import WebSocket from 'ws';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { NasFiles,configSchema,type ReadOnlyFiles,type ReadOnlyOperation } from '../packages/core/src/index.js';
import { NasRelayAgent,RELAY_PROTOCOL,relayProofMessage,loadOrCreateRelayIdentity,type RelayChallenge } from '../packages/relay/src/index.js';
import { GatewayStore,GatewayOAuthProvider,DevicePairing,createGatewayRuntime,GatewayRelay,GatewayEdgeGuard,pairingApprovalMessage } from '../packages/gateway/src/index.js';
import type { Principal } from '../packages/auth/src/index.js';

let certificateDir:string,cert:Buffer,tlsKey:Buffer,directory:string,store:GatewayStore,oauth:GatewayOAuthProvider,hub:GatewayRelay,server:Server,issuer:string;
let files:ReadOnlyFiles,source:ReadOnlyFiles,agents:NasRelayAgent[],rawSockets:WebSocket[],clients:Client[];
const nasKey=generateKeyPairSync('ed25519'),pub=nasKey.publicKey.export({type:'spki',format:'der'}).toString('base64url');
const lookup:LookupFunction=(_host,options,callback)=>{if(options.all)callback(null,[{address:'127.0.0.1',family:4}]);else callback(null,'127.0.0.1',4);};
const timeout=<T>(promise:Promise<T>,ms=3000)=>new Promise<T>((resolve,reject)=>{const timer=setTimeout(()=>reject(new Error('Test deadline exceeded')),ms);promise.then(v=>{clearTimeout(timer);resolve(v);},e=>{clearTimeout(timer);reject(e);});});
const deferred=<T=void>()=>{let resolve!:(value:T)=>void;const promise=new Promise<T>(r=>resolve=r);return {promise,resolve};};
before(async()=>{
  certificateDir=await mkdtemp(path.join(tmpdir(),'nas-relay-ca-'));const certPath=path.join(certificateDir,'cert.pem'),keyPath=path.join(certificateDir,'key.pem');
  const generated=spawnSync('openssl',['req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:prime256v1','-nodes','-days','2','-subj','/CN=gateway.example',
    '-addext','subjectAltName=DNS:gateway.example','-keyout',keyPath,'-out',certPath],{encoding:'utf8'});
  assert.equal(generated.status,0,'OpenSSL must generate a disposable TLS fixture');cert=await readFile(certPath);tlsKey=await readFile(keyPath);
});
after(async()=>{await rm(certificateDir,{recursive:true,force:true});});
beforeEach(async()=>{
  directory=await mkdtemp(path.join(tmpdir(),'nas-relay-'));store=await GatewayStore.open(directory,Buffer.alloc(32,9));agents=[];rawSockets=[];clients=[];
  await mkdir(path.join(directory,'docs'));await mkdir(path.join(directory,'private'));
  await writeFile(path.join(directory,'docs','hello.md'),'Relay fixture document: only the first NAS.');await writeFile(path.join(directory,'private','hidden.txt'),'THIS PRIVATE FOLDER IS NOT GRANTED');
  files=await NasFiles.create(configSchema.parse({roots:[{id:'docs',label:'Documents',path:path.join(directory,'docs')},{id:'private',label:'Private',path:path.join(directory,'private')}],http:{tokenFile:'unused'}}));source=files;
  let app:ReturnType<typeof createGatewayRuntime>['app']|undefined;
  server=createServer({key:tlsKey,cert},(req,res)=>{if(app)app(req,res);else res.writeHead(503).end();});
  server.listen(0,'127.0.0.1');await new Promise<void>(resolve=>server.once('listening',resolve));const address=server.address();
  if(!address||typeof address==='string')throw new Error('No TLS port');issuer=`https://gateway.example:${address.port}/`;
  oauth=new GatewayOAuthProvider(store,{issuer,resource:new URL('mcp',issuer).href,redirectUris:['https://client.example/callback']});
  const runtime=createGatewayRuntime(oauth);app=runtime.app;hub=runtime.relay;hub.attach(server);
});
afterEach(async()=>{
  for(const client of clients)await client.close();for(const agent of agents)await agent.stop();for(const ws of rawSockets)ws.terminate();hub.close();
  await new Promise<void>(resolve=>server.close(()=>resolve()));store.close();await rm(directory,{recursive:true,force:true});
});
async function paired(key=nasKey,label='Demo NAS') {
  const publicKey=key.publicKey.export({type:'spki',format:'der'}).toString('base64url'),pairing=new DevicePairing(oauth),start=pairing.begin(publicKey,label,['docs','private']);
  const browser=randomBytes(32).toString('base64url');pairing.claim(start.userCode,browser);const proof=pairing.poll(start.deviceCode);
  if(proof.state!=='confirmation-required')throw new Error('No NAS challenge');
  pairing.approve(start.deviceCode,sign(null,pairingApprovalMessage(proof),key.privateKey).toString('base64url'));return pairing.completeBrowser(browser);
}
async function authorized(account:{subject:string;deviceId:string},roots=['docs']) {
  const client=await oauth.clientsStore.registerClient!({redirect_uris:['https://client.example/callback'],token_endpoint_auth_method:'none'}),verifier=randomBytes(32).toString('base64url');
  const handle=oauth.beginAuthorization(client,{redirectUri:client.redirect_uris[0]!,state:'test-state',scopes:['nas:read'],resource:new URL(oauth.resource),codeChallenge:createHash('sha256').update(verifier).digest('base64url')});
  const callback=new URL(oauth.approveAuthorization(handle,account.subject,account.deviceId,roots));
  const tokens=await oauth.exchangeAuthorizationCode(client,callback.searchParams.get('code')!,verifier,client.redirect_uris[0],new URL(oauth.resource));
  const principal=(await oauth.authenticator().authenticate(tokens.access_token))!;return {tokens,client,principal};
}
async function agent(key=nasKey,provider:()=>ReadOnlyFiles=()=>source) {
  const a=new NasRelayAgent({issuer,privateKey:key.privateKey,source:provider,trust:{ca:cert,lookup}});agents.push(a);await timeout(a.connect());return a;
}
async function tlsFetch(input:string|URL|Request,init?:RequestInit):Promise<Response> {
  const url=input instanceof Request?new URL(input.url):new URL(input),headers=new Headers(init?.headers);
  return new Promise((resolve,reject)=>{
    const req=httpsRequest(url,{ca:cert,rejectUnauthorized:true,lookup,method:init?.method??'GET',headers:Object.fromEntries(headers)},incoming=>{
      const chunks:Buffer[]=[];incoming.on('data',chunk=>chunks.push(Buffer.from(chunk)));incoming.on('error',reject);
      incoming.on('end',()=>{const h=new Headers();for(const [name,value] of Object.entries(incoming.headers))for(const item of Array.isArray(value)?value:value===undefined?[]:[value])h.append(name,item);
        resolve(new Response(incoming.statusCode===204?null:Buffer.concat(chunks),{status:incoming.statusCode!,headers:h}));});
    });const abort=()=>req.destroy(new Error('Request aborted'));init?.signal?.addEventListener('abort',abort,{once:true});req.once('close',()=>init?.signal?.removeEventListener('abort',abort));req.on('error',reject);
    req.end(typeof init?.body==='string'?init.body:undefined);
  });
}
async function mcp(token?:string) {
  const client=new Client({name:'relay-integration',version:'0.1.0'});clients.push(client);
  await client.connect(new StreamableHTTPClientTransport(new URL(oauth.resource),{fetch:tlsFetch,requestInit:{headers:token?{Authorization:`Bearer ${token}`}:{}}}));return client;
}
function value(result:Awaited<ReturnType<Client['callTool']>>) {
  assert.ok('content' in result);const content=result.content as {type:string;text?:string}[];assert.equal(content[0]?.type,'text');return JSON.parse(content[0]!.text!);
}
function delayedFiles() {
  const entered=deferred(),release=deferred();
  const wrapped:ReadOnlyFiles={listRoots:files.listRoots.bind(files),listDirectory:files.listDirectory.bind(files),searchFiles:files.searchFiles.bind(files),metadata:files.metadata.bind(files),
    readText:async(...args)=>{const result=await files.readText(...args);entered.resolve();await release.promise;return result;}};
  source=wrapped;return {entered,release};
}
test('real TLS NAS proof and official Streamable HTTP client exercise all five read-only tools',async()=>{
  const account=await paired(),granted=await authorized(account);const a=await agent();assert.equal(a.deviceId,account.deviceId);assert.equal(hub.onlineCount,1);
  const client=await mcp(granted.tokens.access_token),catalog=await client.listTools();assert.equal(catalog.tools.length,5);
  for(const tool of catalog.tools){assert.equal(tool.annotations?.readOnlyHint,true);assert.deepEqual(tool._meta?.securitySchemes,[{type:'oauth2',scopes:['nas:read']}]);}
  // The pinned generic SDK client strips unknown top-level properties. Check
  // the actual wire catalog as well as its backward-compatible _meta field.
  const wire=await tlsFetch(oauth.resource,{method:'POST',headers:{'Content-Type':'application/json',Accept:'application/json, text/event-stream'},body:JSON.stringify({jsonrpc:'2.0',id:7,method:'tools/list'})});
  const rawCatalog=await wire.json() as {result:{tools:{securitySchemes:unknown}[]}};
  for(const tool of rawCatalog.result.tools)assert.deepEqual(tool.securitySchemes,[{type:'oauth2',scopes:['nas:read']}]);
  assert.deepEqual(value(await client.callTool({name:'list_roots'})),[{id:'docs',label:'Documents'}]);
  assert.equal(value(await client.callTool({name:'list_directory',arguments:{rootId:'docs'}})).entries[0].name,'hello.md');
  assert.equal(value(await client.callTool({name:'search_files',arguments:{rootId:'docs',query:'hello'}})).entries[0].path,'hello.md');
  assert.equal(value(await client.callTool({name:'get_metadata',arguments:{rootId:'docs',path:'hello.md'}})).type,'file');
  assert.match(value(await client.callTool({name:'read_text',arguments:{rootId:'docs',path:'hello.md'}})).text,/first NAS/);
  const denied=await client.callTool({name:'read_text',arguments:{rootId:'private',path:'hidden.txt'}});assert.equal(denied.isError,true);assert.doesNotMatch(JSON.stringify(denied),/THIS PRIVATE/);
  const traversal=await client.callTool({name:'read_text',arguments:{rootId:'docs',path:'../private/hidden.txt'}});assert.equal(traversal.isError,true);
  const db=await readFile(path.join(directory,'gateway.sqlite'));assert.equal(db.includes(Buffer.from('Relay fixture document')),false);
});
test('anonymous clients can discover OAuth tools but cannot execute them; malformed tokens are rejected',async()=>{
  const client=await mcp(),catalog=await client.listTools();assert.equal(catalog.tools.length,5);
  const result=await client.callTool({name:'list_roots'});assert.equal(result.isError,true);assert.match(JSON.stringify(result._meta),/mcp\/www_authenticate/);assert.match(JSON.stringify(result._meta),/invalid_token/);
  const res=await tlsFetch(oauth.resource,{method:'POST',headers:{Authorization:'Bearer forged','Content-Type':'application/json'},body:'{}'});assert.equal(res.status,401);assert.match(res.headers.get('www-authenticate')!,/resource_metadata/);
});
test('two NAS with the same folder alias never cross device/account boundaries',async()=>{
  const first=await paired(),firstAuth=await authorized(first);await agent();
  const key=generateKeyPairSync('ed25519'),second=await paired(key,'Second NAS'),secondAuth=await authorized(second);
  await mkdir(path.join(directory,'second'));await writeFile(path.join(directory,'second','hello.md'),'Only the SECOND NAS');
  const other=await NasFiles.create(configSchema.parse({roots:[{id:'docs',label:'Other Documents',path:path.join(directory,'second')}],http:{tokenFile:'unused'}}));await agent(key,()=>other);
  assert.match(value(await (await mcp(firstAuth.tokens.access_token)).callTool({name:'read_text',arguments:{rootId:'docs',path:'hello.md'}})).text,/first NAS/);
  assert.match(value(await (await mcp(secondAuth.tokens.access_token)).callTool({name:'read_text',arguments:{rootId:'docs',path:'hello.md'}})).text,/SECOND NAS/);
  assert.throws(()=>hub.filesFor({...firstAuth.principal,deviceId:second.deviceId}));assert.throws(()=>hub.filesFor({...firstAuth.principal,scopes:[]}));
});
test('grant revocation during an in-flight relay read discards document contents and triggers reauthentication',async()=>{
  const account=await paired(),auth=await authorized(account),held=delayedFiles();await agent();const client=await mcp(auth.tokens.access_token);
  const reading=client.callTool({name:'read_text',arguments:{rootId:'docs',path:'hello.md'}});await timeout(held.entered.promise);
  await oauth.revokeToken(auth.client,{token:auth.tokens.access_token});held.release.resolve();
  const result=await timeout(reading);assert.equal(result.isError,true);assert.doesNotMatch(JSON.stringify(result),/Relay fixture document/);assert.match(JSON.stringify(result._meta),/mcp\/www_authenticate/);
});
test('NAS policy changes discard in-flight data and device revocation invalidates grants',async()=>{
  const account=await paired(),auth=await authorized(account),held=delayedFiles();await agent();const client=await mcp(auth.tokens.access_token);
  const reading=client.callTool({name:'read_text',arguments:{rootId:'docs',path:'hello.md'}});await timeout(held.entered.promise);
  source=await NasFiles.create(configSchema.parse({roots:[],http:{tokenFile:'unused'}}));held.release.resolve();
  const result=await timeout(reading);assert.equal(result.isError,true);assert.doesNotMatch(JSON.stringify(result),/Relay fixture document/);
  oauth.revokeDevice(account.deviceId,account.subject);assert.equal(hub.isOnline(account.deviceId,account.subject),false);
  await assert.rejects(()=>oauth.verifyAccessToken(auth.tokens.access_token));
});
test('device revocation during an in-flight read discards data and rejects further key authentication',async()=>{
  const account=await paired(),auth=await authorized(account),held=delayedFiles();await agent();const client=await mcp(auth.tokens.access_token);
  const reading=client.callTool({name:'read_text',arguments:{rootId:'docs',path:'hello.md'}});await timeout(held.entered.promise);
  oauth.revokeDevice(account.deviceId,account.subject);held.release.resolve();
  const result=await timeout(reading);assert.equal(result.isError,true);assert.doesNotMatch(JSON.stringify(result),/Relay fixture document/);assert.match(JSON.stringify(result._meta),/mcp\/www_authenticate/);
  await assert.rejects(()=>agent());
});
test('cancellation retains NAS I/O slots until work finishes; excess operations return BUSY',async()=>{
  const account=await paired(),auth=await authorized(account);const releases:{promise:Promise<void>;resolve:(value:void)=>void}[]=[];let started=0;
  source={listRoots:files.listRoots.bind(files),listDirectory:files.listDirectory.bind(files),searchFiles:files.searchFiles.bind(files),metadata:files.metadata.bind(files),
    readText:async(...args)=>{const result=await files.readText(...args),gate=deferred();releases.push(gate);started++;await gate.promise;return result;}};
  await agent();const remote=hub.filesFor(auth.principal);
  for(let i=0;i<4;i++){
    const signal=new AbortController(),read=remote.readText('docs','hello.md',1,200,signal.signal);const rejected=assert.rejects(read,/CANCELLED/);
    await timeout((async()=>{while(started<i+1)await new Promise(r=>setTimeout(r,5));})());signal.abort();await rejected;
  }
  await assert.rejects(()=>remote.readText('docs','hello.md'),/BUSY/);assert.equal(started,4);for(const gate of releases)gate.resolve();
});
test('a signed NAS cannot return another root or path through a granted operation',async()=>{
  const account=await paired(),auth=await authorized(account);
  source={listRoots:files.listRoots.bind(files),listDirectory:files.listDirectory.bind(files),searchFiles:files.searchFiles.bind(files),metadata:files.metadata.bind(files),
    readText:async()=>({rootId:'private',path:'hidden.txt',text:'LEAK FROM WRONG ROOT',startLine:1,totalLines:1,truncated:false,trust:'untrusted-document-content'})};
  await agent();const result=await (await mcp(auth.tokens.access_token)).callTool({name:'read_text',arguments:{rootId:'docs',path:'hello.md'}});
  assert.equal(result.isError,true);assert.doesNotMatch(JSON.stringify(result),/LEAK FROM WRONG ROOT/);
});
test('private identity survives restart and rejects unsafe permissions and symlink replacement',async()=>{
  const identityDir=path.join(directory,'identity'),first=await loadOrCreateRelayIdentity(identityDir),again=await loadOrCreateRelayIdentity(identityDir);assert.equal(first.publicKey,again.publicKey);
  const filename=path.join(identityDir,'identity.key');await chmod(filename,0o644);await assert.rejects(()=>loadOrCreateRelayIdentity(identityDir));await chmod(filename,0o600);
  await rm(filename);await symlink(path.join(directory,'docs','hello.md'),filename);await assert.rejects(()=>loadOrCreateRelayIdentity(identityDir));
});
test('unpaired keys, wrong TLS trust and browser-style upgrade credentials cannot establish a channel',async()=>{
  const unpaired=new NasRelayAgent({issuer,privateKey:generateKeyPairSync('ed25519').privateKey,source:files,trust:{ca:cert,lookup}});agents.push(unpaired);await assert.rejects(()=>timeout(unpaired.connect()));
  await paired();const untrusted=new NasRelayAgent({issuer,privateKey:nasKey.privateKey,source:files,trust:{lookup}});agents.push(untrusted);await assert.rejects(()=>timeout(untrusted.connect()));
  const wsUrl=new URL('agent/relay',issuer);wsUrl.protocol='wss:';
  for(const headers of [{Origin:issuer},{Cookie:'session=ambient'},{Authorization:'Bearer unrelated'}]){
    const closed=new Promise<number>(resolve=>{const ws=new WebSocket(wsUrl,RELAY_PROTOCOL,{ca:cert,lookup,headers});rawSockets.push(ws);ws.on('unexpected-response',(_request,res)=>{resolve(res.statusCode!);ws.terminate();});ws.on('error',()=>{});});
    assert.equal(await timeout(closed),403);
  }
  assert.equal(hub.onlineCount,0);
});
test('relay signatures are connection-specific and cannot be replayed on a fresh socket',async()=>{
  await paired();const url=new URL('agent/relay',issuer);url.protocol='wss:';let firstProof:string|undefined;
  async function attempt(replay=false) {
    const ws=new WebSocket(url,RELAY_PROTOCOL,{ca:cert,lookup,perMessageDeflate:false});rawSockets.push(ws);
    return timeout(new Promise<{ready:boolean;ws:WebSocket}>(resolve=>{
      ws.on('open',()=>ws.send(JSON.stringify({type:'hello',publicKey:pub})));ws.on('error',()=>{});
      ws.on('message',raw=>{const message=JSON.parse(raw.toString());if(message.type==='challenge'){
        const roots=files.listRoots(),signature=replay?firstProof!:sign(null,relayProofMessage(message as RelayChallenge,pub,roots),nasKey.privateKey).toString('base64url');
        if(!replay)firstProof=signature;ws.send(JSON.stringify({type:'proof',roots,signature}));
      }else if(message.type==='ready')resolve({ready:true,ws});});ws.on('close',()=>resolve({ready:false,ws}));
    }));
  }
  const first=await attempt();assert.equal(first.ready,true);const closing=new Promise<void>(r=>first.ws.once('close',()=>r()));first.ws.terminate();await closing;
  const replay=await attempt(true);assert.equal(replay.ready,false);assert.equal(hub.onlineCount,0);
});
test('outbound agent reconnects after gateway restart while the original OAuth grant remains device-bound',async()=>{
  const account=await paired(),auth=await authorized(account);
  const a=new NasRelayAgent({issuer,privateKey:nasKey.privateKey,source:()=>source,trust:{ca:cert,lookup}});agents.push(a);a.start();
  const online=()=>timeout((async()=>{while(a.state!=='online'||hub.onlineCount!==1)await new Promise(r=>setTimeout(r,10));})(),6000);
  await online();const old=hub.filesFor(auth.principal);
  hub.close();await new Promise<void>(resolve=>server.close(()=>resolve()));
  const runtime=createGatewayRuntime(oauth);hub=runtime.relay;server=createServer({key:tlsKey,cert},runtime.app);hub.attach(server);
  server.listen(Number(new URL(issuer).port),'127.0.0.1');await new Promise<void>(resolve=>server.once('listening',resolve));await online();
  await assert.rejects(()=>old.readText('docs','hello.md'),/DEVICE_OFFLINE/);
  const current=(await oauth.authenticator().authenticate(auth.tokens.access_token))!;assert.equal(current.deviceId,account.deviceId);
  assert.match((await hub.filesFor(current).readText('docs','hello.md')).text,/first NAS/);await a.stop();assert.equal(a.state,'stopped');
});
test('signed manifest changes remove roots and never restore an old grant on re-addition',async()=>{
  const account=await paired(),auth=await authorized(account,['docs','private']);await agent();
  source=await NasFiles.create(configSchema.parse({roots:[{id:'private',label:'Private',path:path.join(directory,'private')}],http:{tokenFile:'unused'}}));
  await timeout((async()=>{while((await oauth.authenticator().authenticate(auth.tokens.access_token))?.rootIds?.includes('docs'))await new Promise(r=>setTimeout(r,20));})());
  source=files;
  await timeout((async()=>{while(oauth.devicesFor(account.subject)[0]?.rootIds.length!==2)await new Promise(r=>setTimeout(r,20));})());
  assert.deepEqual((await oauth.authenticator().authenticate(auth.tokens.access_token))?.rootIds,['private']);
});
test('relay deadlines cancel pending calls and do not release a late document response',async()=>{
  hub.close();hub=new GatewayRelay(oauth,new GatewayEdgeGuard(oauth),1000);hub.attach(server);
  const account=await paired(),auth=await authorized(account),held=delayedFiles();await agent();
  const reading=hub.filesFor(auth.principal).readText('docs','hello.md');const timedOut=assert.rejects(reading,/RELAY_TIMEOUT/);
  await timeout(held.entered.promise);await timedOut;source=files;held.release.resolve();
  assert.match((await hub.filesFor(auth.principal).readText('docs','hello.md')).text,/first NAS/);
});
test('malformed upgrades release handshake capacity before a valid NAS connects',async()=>{
  await paired();
  for(let i=0;i<18;i++){
    const response=await tlsFetch(new URL('agent/relay',issuer),{headers:{Upgrade:'websocket',Connection:'Upgrade','Sec-WebSocket-Protocol':RELAY_PROTOCOL,'Sec-WebSocket-Version':'13'}});
    assert.equal(response.status,400);
  }
  await agent();assert.equal(hub.onlineCount,1);
});
