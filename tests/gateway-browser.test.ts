import { test,beforeEach,afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp,rm,readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { generateKeyPairSync,sign,randomBytes,createHash } from 'node:crypto';
import { request as httpRequest,type Server } from 'node:http';
import { GatewayStore,GatewayOAuthProvider,createGatewayApp,pairingApprovalMessage,SESSION_COOKIE,type PairingProof } from '../packages/gateway/src/index.js';

let directory:string,store:GatewayStore,oauth:GatewayOAuthProvider,server:Server,base:string,now:number,cookie:string;
const issuer='https://gateway.example/',origin='https://gateway.example';
const identity=generateKeyPairSync('ed25519'),publicKey=identity.publicKey.export({type:'spki',format:'der'}).toString('base64url');
beforeEach(async()=>{
  directory=await mkdtemp(path.join(tmpdir(),'nas-browser-'));now=Date.now();cookie='';
  store=await GatewayStore.open(directory,Buffer.alloc(32,8),()=>now);
  oauth=new GatewayOAuthProvider(store,{issuer,resource:`${origin}/mcp`,redirectUris:['https://client.example/callback']});
  server=createGatewayApp(oauth,{trustedProxyAddresses:['127.0.0.1']}).listen(0,'127.0.0.1');
  await new Promise<void>(resolve=>server.once('listening',resolve));const address=server.address();
  if(!address||typeof address==='string')throw new Error('No listening address');base=`http://127.0.0.1:${address.port}`;
});
afterEach(async()=>{await new Promise<void>(resolve=>server.close(()=>resolve()));store.close();await rm(directory,{recursive:true,force:true});});
async function request(url:string,body?:Record<string,string|string[]>,options:{agent?:boolean;headers?:Record<string,string>;raw?:string}={}) {
  const headers:Record<string,string>={host:'gateway.example','x-forwarded-proto':'https','x-forwarded-for':'192.0.2.1',...(cookie?{cookie}:{}),...options.headers};
  let encoded:string|undefined;
  if(body||options.raw!==undefined){headers['content-type']=options.agent?'application/json':'application/x-www-form-urlencoded';
    if(!options.agent)headers.origin=origin;
    if(options.headers)Object.assign(headers,options.headers);
    const params=new URLSearchParams();for(const [k,v] of Object.entries(body??{}))for(const item of Array.isArray(v)?v:[v])params.append(k,item);
    encoded=options.raw??(options.agent?JSON.stringify(body):params.toString());
  }
  // Node fetch normalizes Host to its URL; use an HTTP request to exercise the
  // exact reverse-proxy Host header instead of bypassing the production guard.
  const res=await new Promise<Response>((resolve,reject)=>{
    const req=httpRequest(`${base}${url}`,{method:encoded===undefined?'GET':'POST',headers},incoming=>{
      const chunks:Buffer[]=[];incoming.on('data',chunk=>chunks.push(Buffer.from(chunk)));incoming.on('error',reject);
      incoming.on('end',()=>{
        const responseHeaders=new Headers();for(const [name,value] of Object.entries(incoming.headers))
          for(const item of Array.isArray(value)?value:value===undefined?[]:[String(value)])responseHeaders.append(name,item);
        resolve(new Response(Buffer.concat(chunks),{status:incoming.statusCode!,headers:responseHeaders}));
      });
    });req.on('error',reject);req.end(encoded);
  });
  const set=res.headers.getSetCookie().find(x=>x.startsWith(`${SESSION_COOKIE}=`));if(set)cookie=set.split(';')[0]!;
  return res;
}
const csrf=(html:string)=>{const match=html.match(/name="csrf" value="([a-f0-9]{64})"/);assert.ok(match,'CSRF field is rendered');return match[1]!;};
async function start(handle='',label='Home NAS') {
  const res=await request('/agent/pair/begin',undefined,{agent:true,raw:JSON.stringify({publicKey,label,rootIds:['docs','constructor']})});assert.equal(res.status,200);
  const begin=await res.json() as {deviceCode:string;userCode:string};
  const page=await request(`/connect/pair${handle?`?request=${handle}`:''}`),token=csrf(await page.text());
  const claimed=await request('/connect/pair',{csrf:token,request:handle,code:begin.userCode});assert.equal(claimed.status,303);
  return {...begin,token,handle};
}
async function proof(deviceCode:string) {
  const res=await request('/agent/pair/poll',{deviceCode},{agent:true});assert.equal(res.status,200);
  const status=await res.json() as PairingProof&{state:string};assert.equal(status.state,'confirmation-required');
  const signature=sign(null,pairingApprovalMessage(status),identity.privateKey).toString('base64url');
  const approved=await request('/agent/pair/approve',{deviceCode,signature},{agent:true});assert.equal(approved.status,200);
  return await approved.json() as {deviceId:string};
}
async function login(handle='') {
  const begun=await start(handle),approved=await proof(begun.deviceCode);
  const oldCookie=cookie,res=await request('/connect/complete',{csrf:begun.token,request:handle});assert.equal(res.status,303);
  return {...begun,...approved,oldCookie};
}
async function authorization() {
  const client=await oauth.clientsStore.registerClient!({redirect_uris:['https://client.example/callback'],token_endpoint_auth_method:'none',client_name:'ChatGPT <script>alert(1)</script>'});
  const verifier=randomBytes(32).toString('base64url'),handle=oauth.beginAuthorization(client,{redirectUri:client.redirect_uris[0]!,codeChallenge:createHash('sha256').update(verifier).digest('base64url'),state:'client-state',scopes:['nas:read'],resource:new URL(oauth.resource)});
  return {client,verifier,handle};
}
test('browser login needs a signed NAS confirmation, rotates its session and never adopts submitted identity',async()=>{
  const anonymous=await request('/connect/?subject=attacker',undefined,{headers:{'x-user-id':'attacker'}}),anonymousHtml=await anonymous.text();
  assert.match(anonymousHtml,/Connect your NAS/);assert.doesNotMatch(anonymousHtml,/Your NAS connections/);
  const set=anonymous.headers.getSetCookie()[0]!;for(const attribute of ['HttpOnly','Secure','SameSite=Lax','Path=/'])assert.ok(set.includes(attribute));
  const begun=await start();
  const premature=await request('/connect/complete',{csrf:begun.token});assert.equal(premature.status,409);
  const status=await request('/connect/confirm'),html=await status.text();assert.match(html,/Comparison number/);assert.doesNotMatch(html,/browserKey|challenge|deviceCode/);
  const approved=await proof(begun.deviceCode),oldCookie=cookie;
  const finished=await request('/connect/complete',{csrf:begun.token});assert.equal(finished.status,303);assert.notEqual(cookie,oldCookie);
  assert.match(await (await request('/connect/')).text(),/Your NAS connections/);
  assert.match(await (await request('/connect/',undefined,{headers:{cookie:oldCookie}})).text(),/Connect your NAS/);
  const device=store.list<{subject:string}>('device',10).find(x=>x.id===approved.deviceId);assert.ok(device);assert.notEqual(device.data.subject,'attacker');
  const db=await readFile(path.join(directory,'gateway.sqlite'));assert.equal(db.includes(Buffer.from(cookie.split('=')[1]!)),false);
});
test('Origin, CSRF, unknown fields and wrong NAS signatures cannot establish or change a session',async()=>{
  const begun=await start();
  assert.equal((await request('/connect/complete',{csrf:begun.token},{headers:{origin:'https://evil.example'}})).status,400);
  assert.equal((await request('/connect/complete',{csrf:'0'.repeat(64)})).status,400);
  assert.equal((await request('/connect/complete',{csrf:begun.token,subject:'attacker'})).status,400);
  assert.equal((await request('/agent/pair/approve',{deviceCode:begun.deviceCode,signature:'a'.repeat(86)},{agent:true})).status,400);
  assert.equal((await request('/agent/pair/poll',{deviceCode:begun.deviceCode},{agent:true,headers:{origin}})).status,403);
  assert.equal(store.count('device'),0);
  await proof(begun.deviceCode);assert.equal((await request('/connect/complete',{csrf:begun.token})).status,303);
  const fresh=csrf(await (await request('/connect/')).text());
  assert.equal((await request('/connect/logout',{csrf:fresh},{headers:{origin:'null'}})).status,400);
  assert.match(await (await request('/connect/')).text(),/Your NAS connections/);
});
test('consent is browser-bound, shows escaped client metadata and grants only explicitly selected owned folders',async()=>{
  const auth=await authorization(),logged=await login(auth.handle);
  const res=await request(`/connect/authorize?request=${auth.handle}`),html=await res.text(),token=csrf(html);
  assert.match(html,/ChatGPT &lt;script&gt;/);assert.doesNotMatch(html,/<script>/);assert.doesNotMatch(html,/type="checkbox"[^>]*checked/);
  assert.match(res.headers.get('content-security-policy')!,/frame-ancestors 'none'/);assert.equal(res.headers.get('referrer-policy'),'same-origin');
  const signedCookie=cookie;
  cookie='';const otherHtml=await (await request('/connect/pair')).text(),otherCsrf=csrf(otherHtml);
  assert.equal((await request('/connect/authorize',{csrf:otherCsrf,request:auth.handle,device:logged.deviceId,decision:'approve',roots:'docs'})).status,400);
  cookie=signedCookie;
  assert.equal((await request('/connect/authorize',{csrf:token,request:auth.handle,device:logged.deviceId,decision:'approve'})).status,400);
  assert.equal((await request('/connect/authorize',{csrf:token,request:auth.handle,device:logged.deviceId,decision:'approve',roots:'private'})).status,400);
  const result=await request('/connect/authorize',{csrf:token,request:auth.handle,device:logged.deviceId,decision:'approve',roots:['docs','constructor']});assert.equal(result.status,303);
  const callback=new URL(result.headers.get('location')!);assert.equal(callback.origin,'https://client.example');assert.equal(callback.searchParams.get('iss'),issuer);assert.equal(callback.searchParams.get('state'),'client-state');
  const tokens=await oauth.exchangeAuthorizationCode(auth.client,callback.searchParams.get('code')!,auth.verifier,auth.client.redirect_uris[0],new URL(oauth.resource));
  const info=await oauth.verifyAccessToken(tokens.access_token);assert.deepEqual(info.extra!.rootIds,['docs','constructor']);assert.equal(info.extra!.deviceId,logged.deviceId);
  oauth.setDeviceRoots(logged.deviceId,String(info.extra!.subject),['docs']);oauth.setDeviceRoots(logged.deviceId,String(info.extra!.subject),['docs','constructor']);
  assert.deepEqual((await oauth.verifyAccessToken(tokens.access_token)).extra!.rootIds,['docs']);
  assert.equal((await request('/connect/authorize',{csrf:token,request:auth.handle,device:logged.deviceId,decision:'approve',roots:'docs'})).status,400);
});
test('device selection and revocation cannot cross owners; sign-out invalidates the server session',async()=>{
  const logged=await login(),other=oauth.registerDevice('another-owner','Other NAS',['secret']);
  const auth=await authorization();
  assert.equal((await request(`/connect/authorize?request=${auth.handle}&device=${other}`)).status,400);
  const home=await request('/connect/'),html=await home.text(),token=csrf(html);assert.doesNotMatch(html,/Other NAS|secret/);
  assert.equal((await request('/connect/revoke-device',{csrf:token,device:other})).status,400);
  assert.equal((await request('/connect/revoke-device',{csrf:token,device:logged.deviceId})).status,303);
  assert.match(await (await request('/connect/')).text(),/Your NAS connections/);
  const saved=cookie;assert.equal((await request('/connect/logout',{csrf:token})).status,303);
  assert.match(await (await request('/connect/',undefined,{headers:{cookie:saved}})).text(),/Connect your NAS/);
});
test('secure gateway rejects Host/proxy spoofing, plaintext provenance and oversized agent/browser input',async()=>{
  const badHeaders:Record<string,string>[]=[{host:'evil.example'},{'x-forwarded-proto':'http'},{'x-forwarded-proto':'https,http'},{'x-forwarded-for':'192.0.2.1, 192.0.2.2'}];
  for(const headers of badHeaders)
    assert.equal((await request('/connect/',undefined,{headers})).status,403);
  assert.equal((await request('/agent/pair/begin',undefined,{agent:true,raw:JSON.stringify({label:'x'.repeat(17000)})})).status,413);
  assert.equal((await request('/connect/pair',undefined,{raw:`code=${'x'.repeat(17000)}`})).status,413);
  const health=await request('/health');assert.deepEqual(await health.json(),{status:'control-plane-ready',relay:'not-attached'});
});
test('durable account sessions survive gateway restart and expire without sliding renewal',async()=>{
  await login();const saved=cookie,token=csrf(await (await request('/connect/')).text());
  await new Promise<void>(resolve=>server.close(()=>resolve()));store.close();store=await GatewayStore.open(directory,Buffer.alloc(32,8),()=>now);
  oauth=new GatewayOAuthProvider(store,{issuer,resource:`${origin}/mcp`,redirectUris:['https://client.example/callback']});
  server=createGatewayApp(oauth,{trustedProxyAddresses:['127.0.0.1']}).listen(0,'127.0.0.1');await new Promise<void>(resolve=>server.once('listening',resolve));
  const address=server.address();if(!address||typeof address==='string')throw new Error('No address');base=`http://127.0.0.1:${address.port}`;
  cookie=saved;assert.equal(csrf(await (await request('/connect/')).text()),token);
  now+=12*3600_000+1;assert.equal((await request('/connect/logout',{csrf:token})).status,400);
  assert.match(await (await request('/connect/')).text(),/Connect your NAS/);
});
test('a browser can cancel a pending pairing and restart without waiting for expiration',async()=>{
  const begun=await start();assert.match(await (await request('/connect/pair')).text(),/Pairing in progress/);
  assert.equal((await request('/connect/cancel-pair',{csrf:begun.token},{headers:{origin:'null'}})).status,400);
  assert.equal((await request('/connect/cancel-pair',{csrf:begun.token})).status,303);
  assert.equal((await request('/agent/pair/poll',{deviceCode:begun.deviceCode},{agent:true})).status,400);
  assert.equal(store.count('device'),0);const fresh=await login();assert.ok(fresh.deviceId);
});
