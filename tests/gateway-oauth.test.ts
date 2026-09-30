import { test,beforeEach,afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp,rm,readFile,chmod,symlink } from 'node:fs/promises';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { createHash } from 'node:crypto';
import express from 'express';
import type { OAuthClientInformationFull } from '@modelcontextprotocol/sdk/shared/auth.js';
import { GatewayStore,GatewayOAuthProvider,gatewayOAuthRouter } from '../packages/gateway/src/index.js';

let directory:string,store:GatewayStore,provider:GatewayOAuthProvider,client:OAuthClientInformationFull,device:string,now:number;
const pepper=Buffer.alloc(32,42),issuer='https://gateway.example/',resource='https://gateway.example/mcp',callback='https://client.example/callback';
const verifier='a'.repeat(43),challenge=createHash('sha256').update(verifier).digest('base64url');
beforeEach(async()=>{
  directory=await mkdtemp(path.join(tmpdir(),'nas-oauth-'));now=Date.now();
  store=await GatewayStore.open(directory,pepper,()=>now);
  provider=new GatewayOAuthProvider(store,{issuer,resource,redirectUris:[callback]});
  client=await provider.clientsStore.registerClient!({redirect_uris:[callback],token_endpoint_auth_method:'none',client_name:'Test MCP client'});
  device=provider.registerDevice('owner','Home NAS',['docs','media']);
});
afterEach(async()=>{store.close();await rm(directory,{recursive:true,force:true});});
function authorization(scopes=['nas:read']) {
  return provider.beginAuthorization(client,{redirectUri:callback,resource:new URL(resource),codeChallenge:challenge,state:'browser-state',scopes});
}
async function tokens(roots=['docs']) {
  const handle=authorization();
  const location=new URL(provider.approveAuthorization(handle,'owner',device,roots));
  assert.equal(location.searchParams.get('iss'),issuer);assert.equal(location.searchParams.get('state'),'browser-state');
  return provider.exchangeAuthorizationCode(client,location.searchParams.get('code')!,verifier,callback,new URL(resource));
}
test('public client registration rejects unknown callbacks, extra scopes and credentials',async()=>{
  await assert.rejects(async()=>provider.clientsStore.registerClient!({redirect_uris:['https://evil.example/cb'],token_endpoint_auth_method:'none'}));
  await assert.rejects(async()=>provider.clientsStore.registerClient!({redirect_uris:[callback],token_endpoint_auth_method:'client_secret_post',client_secret:'secret'}));
  assert.throws(()=>authorization(['nas:write']));
  assert.throws(()=>provider.beginAuthorization(client,{redirectUri:callback,codeChallenge:challenge,state:'x'}));
  assert.throws(()=>provider.beginAuthorization(client,{redirectUri:callback,resource:new URL('https://other.example/mcp'),codeChallenge:challenge,state:'x'}));
});
test('consent cannot claim another account, device or unselected folder; approved handle is one-time',()=>{
  const handle=authorization();
  const other=provider.registerDevice('other','Other NAS',['docs']);
  assert.throws(()=>provider.approveAuthorization(handle,'owner',other,['docs']));
  assert.throws(()=>provider.approveAuthorization(handle,'other',device,['docs']));
  assert.throws(()=>provider.approveAuthorization(handle,'owner',device,['private']));
  assert.throws(()=>provider.approveAuthorization(handle,'owner',device,[]));
  const location=provider.approveAuthorization(handle,'owner',device,['docs']);assert.match(location,/code=/);
  assert.throws(()=>provider.approveAuthorization(handle,'owner',device,['docs']));
});
test('code exchange binds callback, resource, client and S256 verifier and consumes atomically',async()=>{
  const code=new URL(provider.approveAuthorization(authorization(),'owner',device,['docs'])).searchParams.get('code')!;
  const other=await provider.clientsStore.registerClient!({redirect_uris:[callback],token_endpoint_auth_method:'none'});
  await assert.rejects(provider.exchangeAuthorizationCode(other,code,verifier,callback,new URL(resource)));
  await assert.rejects(provider.exchangeAuthorizationCode(client,code,'b'.repeat(43),callback,new URL(resource)));
  await assert.rejects(provider.exchangeAuthorizationCode(client,code,verifier,callback,new URL('https://other.example/mcp')));
  await assert.rejects(provider.exchangeAuthorizationCode(client,code,verifier,'https://evil.example/cb',new URL(resource)));
  const simultaneous=await Promise.allSettled([provider.exchangeAuthorizationCode(client,code,verifier,callback,new URL(resource)),provider.exchangeAuthorizationCode(client,code,verifier,callback,new URL(resource))]);
  assert.equal(simultaneous.filter(r=>r.status==='fulfilled').length,1);
  const successful=simultaneous.find(r=>r.status==='fulfilled') as PromiseFulfilledResult<Awaited<ReturnType<typeof tokens>>>;
  const auth=await provider.authenticator().authenticate(successful.value.access_token);
  assert.deepEqual(auth,{subject:'owner',scopes:['nas:read'],rootIds:['docs'],deviceId:device});
});
test('refresh rotates; reuse revokes all sibling access/refresh credentials',async()=>{
  const first=await tokens();
  const second=await provider.exchangeRefreshToken(client,first.refresh_token!,undefined,new URL(resource));
  assert.notEqual(first.refresh_token,second.refresh_token);
  await provider.verifyAccessToken(first.access_token);await provider.verifyAccessToken(second.access_token);
  await assert.rejects(provider.exchangeRefreshToken(client,first.refresh_token!,undefined,new URL(resource)),/reuse/);
  await assert.rejects(provider.verifyAccessToken(first.access_token));await assert.rejects(provider.verifyAccessToken(second.access_token));
  await assert.rejects(provider.exchangeRefreshToken(client,second.refresh_token!,undefined,new URL(resource)));
});
test('wrong refresh client or audience cannot revoke a legitimate family',async()=>{
  const first=await tokens();
  const other=await provider.clientsStore.registerClient!({redirect_uris:[callback],token_endpoint_auth_method:'none'});
  await assert.rejects(provider.exchangeRefreshToken(other,first.refresh_token!,undefined,new URL(resource)));
  await assert.rejects(provider.exchangeRefreshToken(client,first.refresh_token!,undefined,new URL('https://other.example/mcp')));
  await assert.rejects(provider.exchangeRefreshToken(client,first.refresh_token!,['nas:write'],new URL(resource)));
  await provider.verifyAccessToken(first.access_token);
  await provider.exchangeRefreshToken(client,first.refresh_token!,undefined,new URL(resource));
});
test('folder removal is immediate and permanent for old grants even after re-adding the folder',async()=>{
  const grant=await tokens(['docs','media']);
  provider.setDeviceRoots(device,'owner',['media']);
  assert.deepEqual((await provider.verifyAccessToken(grant.access_token)).extra!.rootIds,['media']);
  provider.setDeviceRoots(device,'owner',['docs','media']);
  assert.deepEqual((await provider.verifyAccessToken(grant.access_token)).extra!.rootIds,['media']);
  provider.setDeviceRoots(device,'owner',[]);await assert.rejects(provider.verifyAccessToken(grant.access_token));
  provider.setDeviceRoots(device,'owner',['docs','media']);await assert.rejects(provider.verifyAccessToken(grant.access_token));
  const renewed=await tokens(['docs']);await provider.verifyAccessToken(renewed.access_token);
});
test('device revocation is owner-only and immediately invalidates codes, access and refresh',async()=>{
  const grant=await tokens();const handle=authorization();
  assert.throws(()=>provider.revokeDevice(device,'other'));
  provider.revokeDevice(device,'owner');
  assert.throws(()=>provider.approveAuthorization(handle,'owner',device,['docs']));
  await assert.rejects(provider.verifyAccessToken(grant.access_token));
  await assert.rejects(provider.exchangeRefreshToken(client,grant.refresh_token!,undefined,new URL(resource)));
});
test('token revocation cannot target another client and revokes the whole authorized grant',async()=>{
  const grant=await tokens();const other=await provider.clientsStore.registerClient!({redirect_uris:[callback],token_endpoint_auth_method:'none'});
  await provider.revokeToken(other,{token:grant.access_token});await provider.verifyAccessToken(grant.access_token);
  await provider.revokeToken(client,{token:grant.refresh_token!});
  await assert.rejects(provider.verifyAccessToken(grant.access_token));
  await provider.revokeToken(client,{token:'unknown'});
});
test('expiration is checked on requests and restart preserves grants without raw tokens in the database',async()=>{
  const grant=await tokens();store.close();
  const database=await readFile(path.join(directory,'gateway.sqlite'));
  assert.ok(!database.includes(Buffer.from(grant.access_token)));assert.ok(!database.includes(Buffer.from(grant.refresh_token!)));
  store=await GatewayStore.open(directory,pepper,()=>now);
  provider=new GatewayOAuthProvider(store,{issuer,resource,redirectUris:[callback]});
  await provider.verifyAccessToken(grant.access_token);
  now+=301000;await assert.rejects(provider.verifyAccessToken(grant.access_token));
  const refreshed=await provider.exchangeRefreshToken(client,grant.refresh_token!,undefined,new URL(resource));await provider.verifyAccessToken(refreshed.access_token);
  now+=31*86400_000;await assert.rejects(provider.exchangeRefreshToken(client,refreshed.refresh_token!,undefined,new URL(resource)));
});
test('pending requests and authorization codes expire; denial preserves issuer/state and consumes request',async()=>{
  let handle=authorization();now+=11*60_000;assert.throws(()=>provider.approveAuthorization(handle,'owner',device,['docs']));
  handle=authorization();const denied=new URL(provider.denyAuthorization(handle));
  assert.equal(denied.searchParams.get('error'),'access_denied');assert.equal(denied.searchParams.get('iss'),issuer);assert.equal(denied.searchParams.get('state'),'browser-state');
  assert.throws(()=>provider.denyAuthorization(handle));
  const code=new URL(provider.approveAuthorization(authorization(),'owner',device,['docs'])).searchParams.get('code')!;
  now+=61_000;await assert.rejects(provider.exchangeAuthorizationCode(client,code,verifier,callback,new URL(resource)));
});
test('a DCR client remains stable across expired grants and later reauthorization',async()=>{
  const original=await tokens();now+=91*86400_000;
  await assert.rejects(provider.verifyAccessToken(original.access_token));
  const same=await provider.clientsStore.getClient(client.client_id);assert.equal(same?.client_id,client.client_id);
  const renewed=await tokens();await provider.verifyAccessToken(renewed.access_token);
});
test('opaque grant verifier rejects issuer/audience changes and foreign credentials',async()=>{
  const grant=await tokens();
  const changed=new GatewayOAuthProvider(store,{issuer:'https://new-issuer.example/',resource,redirectUris:[callback]});
  await assert.rejects(changed.verifyAccessToken(grant.access_token));
  const audience=new GatewayOAuthProvider(store,{issuer,resource:'https://gateway.example/other',redirectUris:[callback]});
  await assert.rejects(audience.verifyAccessToken(grant.access_token));
  assert.equal(await provider.authenticator().authenticate('OpenAI-ID-token'),null);
});
test('database rejects unsafe permissions/symlinks and transactions roll back writes',async()=>{
  assert.throws(()=>store.transaction(()=>{store.put('sample','x',{v:1},now+1000);throw new Error('rollback');}));
  assert.equal(store.get('sample','x'),undefined);
  assert.throws(()=>store.transaction(()=>Promise.resolve(1)),/synchronous/);
  const alias=directory+'-alias';await symlink(directory,alias);
  try{await assert.rejects(GatewayStore.open(alias,pepper));}finally{await rm(alias);}
  await chmod(directory,0o755);await assert.rejects(GatewayStore.open(directory,pepper));await chmod(directory,0o700);
});
test('actual HTTP discovery, DCR, PKCE token exchange, refresh and revocation satisfy the advertised contract',async()=>{
  const app=express();app.use(gatewayOAuthRouter(provider));
  const listener=app.listen(0,'127.0.0.1');await new Promise<void>(r=>listener.once('listening',r));
  const base=`http://127.0.0.1:${(listener.address() as {port:number}).port}`;
  const post=(endpoint:string,body:Record<string,string>)=>fetch(base+endpoint,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams(body)});
  try{
    const metadata=await (await fetch(base+'/.well-known/oauth-authorization-server')).json() as Record<string,unknown>;
    assert.equal(metadata.issuer,issuer);assert.deepEqual(metadata.code_challenge_methods_supported,['S256']);
    assert.deepEqual(metadata.token_endpoint_auth_methods_supported,['none']);assert.equal(metadata.authorization_response_iss_parameter_supported,true);
    const prm=await (await fetch(base+'/.well-known/oauth-protected-resource/mcp')).json() as Record<string,unknown>;
    assert.equal(prm.resource,resource);
    const registration=await fetch(base+'/register',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({redirect_uris:[callback],token_endpoint_auth_method:'none',client_name:'HTTP client'})});
    assert.equal(registration.status,201);const httpClient=await registration.json() as OAuthClientInformationFull;
    assert.equal(httpClient.client_secret,undefined);
    const query=new URLSearchParams({client_id:httpClient.client_id,redirect_uri:callback,response_type:'code',code_challenge:challenge,code_challenge_method:'S256',state:'http-state',resource,scope:'nas:read'});
    const start=await fetch(base+'/authorize?'+query,{redirect:'manual'});assert.equal(start.status,302);
    const handle=new URL(start.headers.get('location')!).searchParams.get('request')!;
    // This fixture supplies a trusted owner; real account/session/consent UI is a separate integration gate.
    const approved=new URL(provider.approveAuthorization(handle,'owner',device,['docs']));
    const exchanged=await post('/token',{grant_type:'authorization_code',client_id:httpClient.client_id,code:approved.searchParams.get('code')!,code_verifier:verifier,redirect_uri:callback,resource});
    assert.equal(exchanged.status,200);const grant=await exchanged.json() as {access_token:string;refresh_token:string};
    await provider.verifyAccessToken(grant.access_token);
    const refresh=await post('/token',{grant_type:'refresh_token',client_id:httpClient.client_id,refresh_token:grant.refresh_token,resource});assert.equal(refresh.status,200);
    const next=await refresh.json() as {access_token:string;refresh_token:string};
    assert.equal((await post('/revoke',{client_id:httpClient.client_id,token:next.refresh_token})).status,200);
    await assert.rejects(provider.verifyAccessToken(next.access_token));
    query.set('response_type','invalid');
    const bad=await fetch(base+'/authorize?'+query,{redirect:'manual'});assert.equal(bad.status,302);
    const error=new URL(bad.headers.get('location')!);assert.equal(error.searchParams.get('iss'),issuer);assert.equal(error.searchParams.get('state'),'http-state');
    assert.equal((await fetch(base+'/register',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({payload:'x'.repeat(20000)})})).status,413);
  }finally{listener.closeAllConnections();await new Promise<void>(r=>listener.close(()=>r()));}
});
