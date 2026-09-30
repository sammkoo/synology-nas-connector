import { test,beforeEach,afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp,rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { generateKeyPairSync,sign,randomBytes } from 'node:crypto';
import { DevicePairing,GatewayStore,GatewayOAuthProvider,pairingApprovalMessage,type PairingProof } from '../packages/gateway/src/index.js';

let directory:string,store:GatewayStore,oauth:GatewayOAuthProvider,pairing:DevicePairing,now:number;
const identity=generateKeyPairSync('ed25519');
const publicKey=identity.publicKey.export({type:'spki',format:'der'}).toString('base64url');
const browser=()=>randomBytes(32).toString('base64url');
beforeEach(async()=>{
  directory=await mkdtemp(path.join(tmpdir(),'nas-pair-'));now=Date.now();store=await GatewayStore.open(directory,Buffer.alloc(32,7),()=>now);
  oauth=new GatewayOAuthProvider(store,{issuer:'https://gateway.example/',resource:'https://gateway.example/mcp',redirectUris:['https://client.example/callback']});pairing=new DevicePairing(oauth);
});
afterEach(async()=>{store.close();await rm(directory,{recursive:true,force:true});});
function signature(deviceCode:string,alter:(proof:PairingProof)=>PairingProof=x=>x) {
  const status=pairing.poll(deviceCode);assert.equal(status.state,'confirmation-required');
  if(status.state!=='confirmation-required')throw new Error('Not ready');
  return sign(null,pairingApprovalMessage(alter(status)),identity.privateKey).toString('base64url');
}
function complete(subject?:string) {
  const start=pairing.begin(publicKey,'Home NAS',['docs']),session=browser();
  pairing.claim(start.userCode,session,subject);pairing.approve(start.deviceCode,signature(start.deviceCode));
  return {...pairing.completeBrowser(session),start,session};
}
test('pairing requires both browser claim and private NAS key proof; browser completion is one-time',()=>{
  const start=pairing.begin(publicKey,'Home NAS',['docs']),session=browser();
  assert.equal(pairing.poll(start.deviceCode).state,'waiting-for-browser');
  assert.throws(()=>pairing.completeBrowser(session));assert.throws(()=>pairing.approve(start.deviceCode,'x'.repeat(86)));
  const claimed=pairing.claim(start.userCode,session);assert.match(claimed.comparison,/^\d{6}$/);
  assert.throws(()=>pairing.completeBrowser(session));
  const proof=signature(start.deviceCode);pairing.approve(start.deviceCode,proof);
  const account=pairing.completeBrowser(session);assert.ok(account.subject);assert.ok(oauth.deviceIsActive(account.deviceId,account.subject));
  assert.equal(pairing.deviceIdentity(publicKey).subject,account.subject);
  assert.throws(()=>pairing.completeBrowser(session));assert.throws(()=>pairing.approve(start.deviceCode,proof));
});
test('NAS signature binds gateway, folders, public key, label and browser comparison',()=>{
  const start=pairing.begin(publicKey,'Home NAS',['docs']);pairing.claim(start.userCode,browser());
  for(const change of [
    (p:PairingProof)=>({...p,issuer:'https://evil.example/'}),
    (p:PairingProof)=>({...p,rootIds:['private']}),
    (p:PairingProof)=>({...p,label:'Other NAS'}),
    (p:PairingProof)=>({...p,comparison:'999999'}),
    (p:PairingProof)=>({...p,browserKey:'other-browser'}),
    (p:PairingProof)=>({...p,publicKey:'other-key'})
  ])assert.throws(()=>pairing.approve(start.deviceCode,signature(start.deviceCode,change)),/invalid/);
  pairing.approve(start.deviceCode,signature(start.deviceCode));
});
test('a stolen user code cannot complete pairing or steal another browser session',()=>{
  const start=pairing.begin(publicKey,'Home NAS',['docs']),legitimate=browser(),attacker=browser();
  pairing.claim(start.userCode,legitimate);
  assert.throws(()=>pairing.claim(start.userCode,attacker));
  assert.throws(()=>pairing.completeBrowser(attacker));
  const other=generateKeyPairSync('ed25519');
  const status=pairing.poll(start.deviceCode);if(status.state!=='confirmation-required')throw new Error('Missing challenge');
  assert.throws(()=>pairing.approve(start.deviceCode,sign(null,pairingApprovalMessage(status),other.privateKey).toString('base64url')));
  pairing.approve(start.deviceCode,signature(start.deviceCode));assert.throws(()=>pairing.completeBrowser(attacker));
  pairing.completeBrowser(legitimate);
});
test('an existing device always returns its original account; another signed-in account cannot claim it',()=>{
  const first=complete();
  const start=pairing.begin(publicKey,'Home NAS',['docs']);assert.throws(()=>pairing.claim(start.userCode,browser(),'attacker'));
  const session=browser();pairing.claim(start.userCode,session);pairing.approve(start.deviceCode,signature(start.deviceCode));
  const again=pairing.completeBrowser(session);assert.equal(again.subject,first.subject);assert.equal(again.deviceId,first.deviceId);
  const another=complete(first.subject);assert.equal(another.subject,first.subject);
});
test('revoked device identity cannot connect; fresh NAS/admin confirmation restores only its own account',()=>{
  const first=complete('existing-owner');oauth.revokeDevice(first.deviceId,first.subject);assert.throws(()=>pairing.deviceIdentity(publicKey));
  const restored=complete();assert.equal(restored.subject,first.subject);assert.notEqual(restored.deviceId,first.deviceId);
  assert.equal(oauth.deviceIsActive(first.deviceId,first.subject),false);assert.equal(pairing.deviceIdentity(publicKey).deviceId,restored.deviceId);
});
test('pairing expiration, malformed input and code-role separation fail closed',()=>{
  assert.throws(()=>pairing.begin('invalid','Home NAS',['docs']));
  assert.throws(()=>pairing.begin(publicKey,'Home NAS',['../private']));
  const start=pairing.begin(publicKey,'Home NAS',['docs']);
  assert.throws(()=>pairing.claim(start.deviceCode,browser()));assert.throws(()=>pairing.poll(start.userCode));
  now+=601_000;assert.throws(()=>pairing.poll(start.deviceCode));assert.throws(()=>pairing.claim(start.userCode,browser()));
});
