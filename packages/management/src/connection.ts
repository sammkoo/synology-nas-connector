import { createHash,randomBytes,randomUUID,sign } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat,mkdir,open,rename,unlink } from 'node:fs/promises';
import path from 'node:path';
import { z } from 'zod';
import type { FileOperations } from '../../core/src/index.js';
import { GatewayAgentClient,GatewayClientError,NasRelayAgent,loadOrCreateRelayIdentity,canonicalGatewayIssuer,
  pairingApprovalMessage,deviceRevocationMessage,type PairingProof,type GatewayClientTrust } from '../../relay/src/index.js';
import { ManagementError } from './bridge-auth.js';

const recordSchema=z.object({version:z.literal(1),issuer:z.string().url().refine(v=>canonicalGatewayIssuer(v)===v),
  label:z.string().min(1).max(100),deviceId:z.string().uuid(),publicKey:z.string().regex(/^[A-Za-z0-9_-]{59}$/),
  enabled:z.boolean(),revocationPending:z.boolean()}).strict().refine(v=>!v.enabled||!v.revocationPending);
type Record=z.infer<typeof recordSchema>;
type Pending={id:string;user:string;files:FileOperations;client:GatewayAgentClient;identity:Awaited<ReturnType<typeof loadOrCreateRelayIdentity>>;
  label:string;rootIds:string[];deviceCode:string;userCode:string;verificationUri:string;expiresAt:number;proof?:PairingProof;confirmed?:boolean};
const proofHash=(proof:PairingProof)=>createHash('sha256').update(pairingApprovalMessage(proof)).digest('hex');

/** NAS-owned pairing; browser gets public codes, never private polling credentials or keys. */
export class NasConnectionController {
  private record?:Record;private pending?:Pending;private agent?:NasRelayAgent;private error?:string;
  private tail:Promise<void>=Promise.resolve();private queued=0;private stopping=false;
  constructor(private readonly directory:string,private readonly source:()=>FileOperations,private readonly trust:GatewayClientTrust={}) {}
  private get filename(){return path.join(this.directory,'connection.json');}
  private serial<T>(operation:()=>Promise<T>) {
    if(this.stopping)return Promise.reject(new ManagementError('CONNECTION_STOPPED',503));
    if(this.queued>=4)return Promise.reject(new ManagementError('CONNECTION_BUSY',409));this.queued++;
    const result=this.tail.then(operation);this.tail=result.then(()=>{},()=>{});
    return result.finally(()=>{this.queued--;});
  }
  private async privateDirectory() {
    await mkdir(this.directory,{recursive:true,mode:0o700});const s=await lstat(this.directory);
    if(!s.isDirectory()||s.isSymbolicLink()||s.uid!==process.getuid?.()||(s.mode&0o077))throw new ManagementError('CONNECTION_STORAGE_UNSAFE',503);
  }
  private async syncDirectory(){const h=await open(this.directory,constants.O_RDONLY|constants.O_NOFOLLOW);try{await h.sync();}finally{await h.close();}}
  private async persist(record:Record) {
    await this.privateDirectory();
    try{const s=await lstat(this.filename);if(!s.isFile()||s.isSymbolicLink()||s.uid!==process.getuid?.()||(s.mode&0o077))throw new ManagementError('CONNECTION_STORAGE_UNSAFE',503);}
    catch(e){if((e as NodeJS.ErrnoException).code!=='ENOENT')throw e;}
    const tmp=path.join(this.directory,`.connection-${randomUUID()}.tmp`);
    try{
      const h=await open(tmp,constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW,0o600);
      try{await h.writeFile(JSON.stringify(record)+'\n');await h.sync();}finally{await h.close();}
      await rename(tmp,this.filename);await this.syncDirectory();
    }finally{await unlink(tmp).catch(()=>{});}
  }
  private safeError(e:unknown){return e instanceof GatewayClientError||e instanceof ManagementError?e.code:'CONNECTION_FAILED';}
  private currentPending(user:string,id?:string) {
    if(this.stopping)throw new ManagementError('CONNECTION_STOPPED',503);
    const p=this.pending;
    if(!p||p.expiresAt<=Date.now()){this.pending=undefined;throw new ManagementError('PAIRING_EXPIRED',409);}
    if(p.user!==user)throw new ManagementError('PAIRING_OTHER_ADMIN',403);
    if(id!==undefined&&id!==p.id)throw new ManagementError('PAIRING_CHANGED',409);
    if(p.files!==this.source()){this.pending=undefined;throw new ManagementError('CONFIGURATION_CHANGED',409);}
    return p;
  }
  status(user:string) {
    if(this.pending&&(this.pending.expiresAt<=Date.now()||this.pending.files!==this.source()))this.pending=undefined;
    const p=this.pending;
    if(p)return p.user!==user?{state:'busy'}:{state:p.proof?'confirmation-required':'pairing',issuer:p.client.issuer,label:p.label,
      pairId:p.id,userCode:p.userCode,verificationUri:p.verificationUri,expiresAt:p.expiresAt,
      ...(p.proof?{comparison:p.proof.comparison,proofHash:proofHash(p.proof)}:{})};
    const r=this.record;
    if(!r)return {state:this.error?'error':'not-configured',...(this.error?{error:this.error}:{})};
    return {state:r.enabled?(this.agent?.state??'error'):'disconnected',issuer:r.issuer,label:r.label,
      mcpUrl:new URL('mcp',r.issuer).href,revocationPending:r.revocationPending,...(this.error?{error:this.error}:{})};
  }
  async restore() {
    try{
      // No identity or directory is created just by opening the application.
      const directory=await lstat(this.directory);
      if(!directory.isDirectory()||directory.isSymbolicLink()||directory.uid!==process.getuid?.()||(directory.mode&0o077))throw new Error('Unsafe connection directory');
      const h=await open(this.filename,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
      let record:Record;
      try{const s=await h.stat();if(!s.isFile()||s.size>4096||s.uid!==process.getuid?.()||(s.mode&0o077))throw new Error('Unsafe connection record');
        record=recordSchema.parse(JSON.parse(await h.readFile('utf8')));}finally{await h.close();}
      this.record=record;
      const identity=await loadOrCreateRelayIdentity(this.directory,false);if(identity.publicKey!==record.publicKey)throw new Error('Identity changed');
      // Refuse automatic reconnection when durable local revocation cannot be written.
      await this.persist(record);
      if(record.enabled)this.start(record,identity.privateKey);
      else if(record.revocationPending)await this.revoke(record,identity.privateKey);
    }catch(e){if((e as NodeJS.ErrnoException).code!=='ENOENT'||this.record){this.error='CONNECTION_RESTORE_FAILED';}}
  }
  private start(record:Record,privateKey:Awaited<ReturnType<typeof loadOrCreateRelayIdentity>>['privateKey']) {
    const client=new GatewayAgentClient(record.issuer,this.trust);
    this.agent=new NasRelayAgent({issuer:client.issuer,privateKey,expectedDeviceId:record.deviceId,source:this.source,
      trust:{...this.trust,lookup:client.lookup}});this.agent.start();
  }
  begin(user:string,issuer:string,label:string,expectedFiles:FileOperations) {
    return this.serial(async()=>{
      if(expectedFiles!==this.source())throw new ManagementError('CONFIGURATION_CHANGED',409);
      if(this.error==='CONNECTION_RESTORE_FAILED')throw new ManagementError(this.error,503);
      if(this.record?.enabled||this.record?.revocationPending)throw new ManagementError('DISCONNECT_FIRST',409);
      if(this.pending&&this.pending.expiresAt>Date.now())throw new ManagementError('CONNECTION_BUSY',409);
      const rootIds=expectedFiles.listRoots().map(r=>r.id);if(!rootIds.length)throw new ManagementError('SELECT_FOLDERS_FIRST',409);
      const client=new GatewayAgentClient(issuer,this.trust),identity=await loadOrCreateRelayIdentity(this.directory,!this.record);
      if(this.record&&identity.publicKey!==this.record.publicKey)throw new ManagementError('CONNECTION_RESTORE_FAILED',503);
      const reply=await client.begin(identity.publicKey,label,rootIds);
      if(this.stopping)throw new ManagementError('CONNECTION_STOPPED',503);
      if(expectedFiles!==this.source())throw new ManagementError('CONFIGURATION_CHANGED',409);
      this.pending={id:randomUUID(),user,files:expectedFiles,client,identity,label,rootIds,...reply,expiresAt:Date.now()+reply.expiresIn*1000};
      this.error=undefined;return this.status(user);
    });
  }
  private async pollPending(p:Pending) {
    const reply=await p.client.poll(p.deviceCode);this.currentPending(p.user,p.id);
    if(reply.state==='confirmation-required') {
      if(reply.issuer!==p.client.issuer||reply.publicKey!==p.identity.publicKey||reply.label!==p.label||
        JSON.stringify([...reply.rootIds].sort())!==JSON.stringify([...p.rootIds].sort()))throw new ManagementError('PAIRING_PROOF_INVALID',409);
      p.proof=reply;
    }else if(reply.state==='approved'&&!p.confirmed)throw new ManagementError('PAIRING_PROOF_INVALID',409);
    else if(reply.state==='waiting-for-browser'&&p.proof)throw new ManagementError('PAIRING_CHANGED',409);
    return reply;
  }
  poll(user:string) {
    return this.serial(async()=>{
      this.status(user);
      if(this.pending){const p=this.currentPending(user),reply=await this.pollPending(p);
        if(reply.state==='approved'&&p.confirmed)return this.finishPairing(p,reply.deviceId);}
      return this.status(user);
    });
  }
  confirm(user:string,id:string,hash:string,comparison:string) {
    return this.serial(async()=>{
      const p=this.currentPending(user,id),before=p.proof;
      if(!before||hash!==proofHash(before)||comparison!==before.comparison)throw new ManagementError('PAIRING_CHANGED',409);
      const reply=await this.pollPending(p);
      if(reply.state!=='confirmation-required'||hash!==proofHash(reply))throw new ManagementError('PAIRING_CHANGED',409);
      p.confirmed=true;
      let deviceId:string;
      try{deviceId=(await p.client.approve(p.deviceCode,sign(null,pairingApprovalMessage(reply),p.identity.privateKey).toString('base64url'))).deviceId;}
      catch(e){
        // An approval may have reached the gateway despite a lost response. It is
        // recoverable only within this explicitly confirmed, still-live pairing.
        const recovery=await p.client.poll(p.deviceCode);if(recovery.state!=='approved')throw e;deviceId=recovery.deviceId;
      }
      return this.finishPairing(p,deviceId);
    });
  }
  private async finishPairing(p:Pending,deviceId:string) {
      const {user,id}=p,record:Record={version:1,issuer:p.client.issuer,label:p.label,deviceId,publicKey:p.identity.publicKey,enabled:false,revocationPending:true};
      try{
        this.currentPending(user,id);await this.persist(record);this.record=record;
        this.currentPending(user,id);await this.persist({...record,enabled:true,revocationPending:false});
        this.currentPending(user,id);
        this.record={...record,enabled:true,revocationPending:false};this.start(this.record,p.identity.privateKey);this.pending=undefined;this.error=undefined;
        return this.status(user);
      }catch(e){
        this.pending=undefined;this.record=record;
        let persistenceError:unknown;
        try{await this.disableDurably(record);}catch(error){persistenceError=error;}
        await this.revoke(record,p.identity.privateKey).catch(()=>{});
        if(persistenceError)throw persistenceError;
        throw e instanceof ManagementError?e:new ManagementError('CONNECTION_NOT_SAVED',503);
      }
  }
  cancel(user:string,id:string){return this.serial(async()=>{this.currentPending(user,id);this.pending=undefined;return this.status(user);});}
  private async revoke(record:Record,privateKey:Awaited<ReturnType<typeof loadOrCreateRelayIdentity>>['privateKey']) {
    const client=new GatewayAgentClient(record.issuer,this.trust),request={publicKey:record.publicKey,deviceId:record.deviceId,timestamp:Date.now(),nonce:randomBytes(32).toString('base64url')};
    try{await client.revoke({...request,signature:sign(null,deviceRevocationMessage(record.issuer,request),privateKey).toString('base64url')});}
    catch(e){this.error=this.safeError(e);return;}
    const revoked={...record,enabled:false,revocationPending:false};await this.persist(revoked);this.record=revoked;this.error=undefined;
  }
  private async disableDurably(disabled:Record) {
    try{await this.persist(disabled);}catch{
      // Removal is a fallback when atomic replacement fails. If neither works,
      // report explicitly that a restart could revive the previous record.
      try{await unlink(this.filename).catch(e=>{if(e.code!=='ENOENT')throw e;});await this.syncDirectory();}
      catch{this.error='DISCONNECT_NOT_PERSISTED';throw new ManagementError(this.error,503);}
      this.error='CONNECTION_NOT_SAVED';throw new ManagementError(this.error,503);
    }
  }
  disconnect(user:string) {
    return this.serial(async()=>{
      this.pending=undefined;await this.agent?.stop();this.agent=undefined;
      const r=this.record;if(!r)return this.status(user);
      const disabled={...r,enabled:false,revocationPending:true};this.record=disabled;
      await this.disableDurably(disabled);
      const identity=await loadOrCreateRelayIdentity(this.directory,false);
      if(identity.publicKey!==r.publicKey)throw new ManagementError('CONNECTION_RESTORE_FAILED',503);
      await this.revoke(disabled,identity.privateKey);return this.status(user);
    });
  }
  async stop(){this.stopping=true;await this.agent?.stop();this.agent=undefined;await this.tail;this.pending=undefined;}
}
