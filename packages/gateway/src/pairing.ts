import { createPublicKey,createHash,randomBytes,randomUUID,verify } from 'node:crypto';
import { InvalidGrantError,InvalidRequestError } from '@modelcontextprotocol/sdk/server/auth/errors.js';
import { GatewayOAuthProvider } from './oauth.js';

type Pair={publicKey:string;label:string;rootIds:string[];challenge:string;userCodeKey:string;expires:number;
  browserKey?:string;comparison?:string;requestedSubject?:string;deviceId?:string;subject?:string;approved?:boolean;consumed?:boolean};
type Identity={subject:string;deviceId:string;publicKey:string};
const value=()=>randomBytes(32).toString('base64url');
/** Sign this exact byte sequence only after a DSM administrator compares both screens. */
export type PairingProof={issuer:string;publicKey:string;label:string;rootIds:string[];challenge:string;browserKey:string;comparison:string};
export function pairingApprovalMessage(proof:PairingProof) {
  return Buffer.from(JSON.stringify(['nas-pairing-v1',proof.issuer,proof.publicKey,proof.label,[...proof.rootIds].sort(),proof.challenge,proof.browserKey,proof.comparison]));
}
export class DevicePairing {
  constructor(private readonly oauth:GatewayOAuthProvider) {}
  private get store(){return this.oauth.store;}
  private key(encoded:string) {
    if(!/^[A-Za-z0-9_-]{59}$/.test(encoded))throw new InvalidRequestError('Invalid device public key');
    const key=createPublicKey({key:Buffer.from(encoded,'base64url'),format:'der',type:'spki'});
    if(key.asymmetricKeyType!=='ed25519'||key.export({type:'spki',format:'der'}).toString('base64url')!==encoded)
      throw new InvalidRequestError('Ed25519 device identity required');return key;
  }
  begin(publicKey:string,label:string,rootIds:string[]) {
    this.key(publicKey);
    if(!label||label.length>100||rootIds.length>20||new Set(rootIds).size!==rootIds.length||
      rootIds.some(id=>!/^[A-Za-z0-9_-]{1,40}$/.test(id)))throw new InvalidRequestError('Invalid NAS pairing request');
    this.store.prune();if(this.store.count('pair')>=1000)throw new InvalidRequestError('Pairing capacity reached');
    const deviceCode=value(),userCode=randomBytes(8).toString('hex').toUpperCase(),expires=this.store.now()+10*60_000;
    const userCodeKey=this.store.key('pair-user',userCode);
    this.store.transaction(()=>{
      this.store.put('pair',this.store.key('pair',deviceCode),{publicKey,label,rootIds,challenge:value(),userCodeKey,expires} satisfies Pair,expires);
      this.store.put('pair-user',userCodeKey,{deviceKey:this.store.key('pair',deviceCode)},expires);
    });
    return {deviceCode,userCode,expiresIn:600,verificationUri:new URL('connect/pair',this.oauth.issuer).href};
  }
  /** browserSessionId and subject must come from verified first-party server sessions. */
  claim(userCode:string,browserSessionId:string,subject?:string) {
    if(!/^[0-9A-F]{16}$/.test(userCode)||!/^[A-Za-z0-9_-]{43}$/.test(browserSessionId)||
      (subject!==undefined&&(!subject||subject.length>256)))throw new InvalidRequestError('Invalid pairing session');
    return this.store.transaction(()=>{
      const lookup=this.store.get<{deviceKey:string}>('pair-user',this.store.key('pair-user',userCode));
      const pair=lookup?this.store.get<Pair>('pair',lookup.deviceKey):undefined;
      if(!pair||pair.approved||pair.browserKey)throw new InvalidGrantError('Pairing code unavailable');
      const identity=this.store.get<Identity>('device-identity',this.identityKey(pair.publicKey));
      if(subject&&identity&&subject!==identity.subject)throw new InvalidGrantError('NAS belongs to another account');
      const comparison=String(randomBytes(4).readUInt32BE()%1_000_000).padStart(6,'0');
      const browserKey=this.store.key('pair-browser',browserSessionId);
      if(this.store.get('pair-browser',browserKey))throw new InvalidGrantError('A pairing is already pending in this browser');
      const next={...pair,browserKey,comparison,...(subject?{requestedSubject:subject}:{})};
      this.store.put('pair',lookup!.deviceKey,next,pair.expires);
      this.store.put('pair-browser',browserKey,{deviceKey:lookup!.deviceKey},pair.expires);
      return {label:pair.label,comparison,expiresIn:Math.max(0,Math.floor((pair.expires-this.store.now())/1000))};
    });
  }
  browserStatus(browserSessionId:string) {
    const browserKey=this.store.key('pair-browser',browserSessionId),lookup=this.store.get<{deviceKey:string}>('pair-browser',browserKey);
    const pair=lookup?this.store.get<Pair>('pair',lookup.deviceKey):undefined;
    if(!pair||pair.browserKey!==browserKey||pair.consumed)throw new InvalidGrantError('Pairing expired');
    return {label:pair.label,comparison:pair.comparison!,approved:Boolean(pair.approved),expiresIn:Math.max(0,Math.floor((pair.expires-this.store.now())/1000))};
  }
  cancelBrowser(browserSessionId:string) {
    this.store.transaction(()=>{
      const browserKey=this.store.key('pair-browser',browserSessionId),lookup=this.store.get<{deviceKey:string}>('pair-browser',browserKey);
      const pair=lookup?this.store.get<Pair>('pair',lookup.deviceKey):undefined;
      if(pair&&pair.browserKey===browserKey&&!pair.consumed){
        this.store.delete('pair-user',pair.userCodeKey);this.store.delete('pair',lookup!.deviceKey);
      }
      this.store.delete('pair-browser',browserKey);
    });
  }
  private identityKey(publicKey:string){return createHash('sha256').update(Buffer.from(publicKey,'base64url')).digest('hex');}
  /** Agent keeps deviceCode private; the browser never receives this credential. */
  poll(deviceCode:string) {
    const pair=this.store.get<Pair>('pair',this.store.key('pair',deviceCode));
    if(!pair)throw new InvalidGrantError('Pairing expired');
    return pair.approved?{state:'approved' as const,deviceId:pair.deviceId!}:
      pair.browserKey?{state:'confirmation-required' as const,issuer:this.oauth.issuer,publicKey:pair.publicKey,label:pair.label,rootIds:pair.rootIds,challenge:pair.challenge,browserKey:pair.browserKey,comparison:pair.comparison!}:
      {state:'waiting-for-browser' as const};
  }
  /** A signed NAS approval is issued only after its authenticated administrator confirms. */
  approve(deviceCode:string,signature:string) {
    return this.store.transaction(()=>{
      const deviceKey=this.store.key('pair',deviceCode),pair=this.store.get<Pair>('pair',deviceKey);
      if(!pair||pair.approved||!pair.browserKey||!pair.comparison||!/^[A-Za-z0-9_-]{86}$/.test(signature))throw new InvalidGrantError('Pairing cannot be confirmed');
      if(!verify(null,pairingApprovalMessage({...pair,issuer:this.oauth.issuer,browserKey:pair.browserKey,comparison:pair.comparison}),this.key(pair.publicKey),Buffer.from(signature,'base64url')))
        throw new InvalidGrantError('NAS proof is invalid');
      const identityKey=this.identityKey(pair.publicKey),known=this.store.get<Identity>('device-identity',identityKey);
      const subject=known?.subject??pair.requestedSubject??randomUUID();
      if(pair.requestedSubject&&pair.requestedSubject!==subject)throw new InvalidGrantError('Account mismatch');
      let deviceId=known?.deviceId;
      if(!deviceId||!this.oauth.deviceIsActive(deviceId,subject))deviceId=this.oauth.registerDevice(subject,pair.label,pair.rootIds);
      else this.oauth.setDeviceRoots(deviceId,subject,pair.rootIds);
      this.store.put('device-identity',identityKey,{subject,deviceId,publicKey:pair.publicKey} satisfies Identity,this.store.now()+3650*86400_000);
      this.store.put('pair',deviceKey,{...pair,approved:true,subject,deviceId},pair.expires);
      this.store.delete('pair-user',pair.userCodeKey);
      return {deviceId};
    });
  }
  /** Returns a verified first-party subject once, after both ends confirmed ownership. */
  completeBrowser(browserSessionId:string) {
    return this.store.transaction(()=>{
      const browserKey=this.store.key('pair-browser',browserSessionId),lookup=this.store.get<{deviceKey:string}>('pair-browser',browserKey);
      const pair=lookup?this.store.get<Pair>('pair',lookup.deviceKey):undefined;
      if(!pair||pair.browserKey!==browserKey||!pair.approved||pair.consumed||!pair.subject||!pair.deviceId)throw new InvalidGrantError('NAS confirmation required');
      this.store.put('pair',lookup!.deviceKey,{...pair,consumed:true},pair.expires);this.store.delete('pair-browser',browserKey);
      return {subject:pair.subject,deviceId:pair.deviceId};
    });
  }
  /** Relays must challenge the private key and bind every channel to this identity. */
  deviceIdentity(publicKey:string) {
    const identity=this.store.get<Identity>('device-identity',this.identityKey(publicKey));
    if(!identity||!this.oauth.deviceIsActive(identity.deviceId,identity.subject))throw new InvalidGrantError('Device is not paired');
    return {...identity};
  }
}
