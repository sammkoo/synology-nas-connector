import WebSocket,{WebSocketServer} from 'ws';
import type { Server } from 'node:http';
import { randomBytes,randomUUID,verify,createPublicKey } from 'node:crypto';
import { NAS_READ_SCOPE,NAS_CREATE_SCOPE,NAS_SHARE_SCOPE,type Principal } from '../../auth/src/index.js';
import { NasError,type FileOperations,type FileOperation } from '../../core/src/index.js';
import { RELAY_PROTOCOL,MAX_RELAY_BYTES,agentMessageSchema,relayProofMessage,encodeRelay,validateRelayResult,type RelayRoots,type RelayChallenge } from '../../relay/src/protocol.js';
import { DevicePairing } from './pairing.js';
import { GatewayOAuthProvider } from './oauth.js';
import { GatewayEdgeGuard } from './edge.js';

type Pending={operation:FileOperation;rootIds:readonly string[];resolve:(value:unknown)=>void;reject:(error:NasError)=>void;cleanup:()=>void;authorize?:()=>Promise<void>;commitRequested?:boolean;committed?:boolean};
type Channel={ws:WebSocket;publicKey:string;subject:string;deviceId:string;roots:RelayRoots;pending:Map<string,Pending>;recent:Set<string>};
export class GatewayRelay {
  private readonly wss=new WebSocketServer({noServer:true,perMessageDeflate:false,maxPayload:MAX_RELAY_BYTES,maxFragments:64,maxBufferedChunks:32});
  private readonly pairing:DevicePairing;private readonly channels=new Map<string,Channel>();private pendingCount=0;private handshakes=0;
  private attached?:Server;
  private closed=false;
  constructor(readonly oauth:GatewayOAuthProvider,private readonly edge:GatewayEdgeGuard,private readonly timeoutMs=15000) {
    if(!Number.isInteger(timeoutMs)||timeoutMs<1000||timeoutMs>35000)throw new Error('Invalid relay deadline');
    this.pairing=new DevicePairing(oauth);this.wss.on('error',()=>{});
  }
  get attachedToListener(){return Boolean(this.attached);}
  get edgeGuard(){return this.edge;}
  get onlineCount(){return this.channels.size;}
  isOnline(deviceId:string,subject:string){const c=this.channels.get(deviceId);return Boolean(c&&c.subject===subject&&this.active(c));}
  private active(c:Channel) {
    try{const identity=this.pairing.deviceIdentity(c.publicKey);return c.ws.readyState===WebSocket.OPEN&&this.channels.get(c.deviceId)===c&&identity.deviceId===c.deviceId&&identity.subject===c.subject;}catch{return false;}
  }
  attach(server:Server) {
    if(this.closed||this.attached)throw new Error('Relay is closed or already attached');this.attached=server;
    server.on('upgrade',this.upgrade);server.once('close',()=>this.close());
  }
  private readonly upgrade=(req:import('node:http').IncomingMessage,socket:import('node:stream').Duplex,head:Buffer)=>{
    const guard=this.edge.check(req),deny=(status:number)=>{socket.end(`HTTP/1.1 ${status} Rejected\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`);};
    if(guard){deny(guard.status);return;}
    if(req.url!=='/agent/relay'||req.headers.origin!==undefined||req.headers.cookie!==undefined||req.headers.authorization!==undefined||req.headers['sec-websocket-protocol']!==RELAY_PROTOCOL){deny(403);return;}
    if(this.handshakes>=16||this.channels.size>=256){deny(503);return;}
    this.handshakes++;let reserved=true;
    const release=()=>{if(reserved){reserved=false;this.handshakes--;socket.removeListener('close',release);}};
    socket.once('close',release);
    try{this.wss.handleUpgrade(req,socket,head,ws=>this.accept(ws,release));}catch{release();socket.destroy();}
  };
  private accept(ws:WebSocket,release:()=>void) {
    let channel:Channel|undefined,publicKey:string|undefined,challenge:RelayChallenge|undefined;
    let alive=true,window=Date.now(),messages=0;
    const timer=setTimeout(()=>ws.terminate(),10000);timer.unref();
    const heartbeat=setInterval(()=>{
      if(!channel||!this.active(channel)||!alive){ws.terminate();return;}alive=false;ws.ping();
    },20000);heartbeat.unref();
    ws.on('pong',()=>{alive=true;});ws.on('error',()=>{});
    const send=(value:unknown)=>{if(ws.readyState!==WebSocket.OPEN||ws.bufferedAmount>MAX_RELAY_BYTES)throw new Error('Backpressure');ws.send(encodeRelay(value));};
    ws.on('message',(raw,binary)=>{
      try{
        if(Date.now()-window>=60000){window=Date.now();messages=0;}
        const bytes=Array.isArray(raw)?Buffer.concat(raw):Buffer.isBuffer(raw)?raw:Buffer.from(raw);
        if(++messages>600||binary||(!channel&&bytes.byteLength>16384))throw new Error('Invalid relay frame');
        const message=agentMessageSchema.parse(JSON.parse(bytes.toString()));
        if(!channel){
          if(message.type==='hello'&&!publicKey){
            this.pairing.deviceIdentity(message.publicKey);publicKey=message.publicKey;
            challenge={type:'challenge',issuer:this.oauth.issuer,id:randomUUID(),nonce:randomBytes(32).toString('base64url')};send(challenge);
          }else if(message.type==='proof'&&publicKey&&challenge){
            const key=createPublicKey({key:Buffer.from(publicKey,'base64url'),format:'der',type:'spki'});
            if(!verify(null,relayProofMessage(challenge,publicKey,message.roots),key,Buffer.from(message.signature,'base64url')))throw new Error('NAS proof failed');
            const identity=this.pairing.deviceIdentity(publicKey);if(this.channels.has(identity.deviceId)||this.channels.size>=256)throw new Error('Duplicate/full device channel');
            this.oauth.setDeviceManifest(identity.deviceId,identity.subject,message.roots);
            channel={ws,publicKey,subject:identity.subject,deviceId:identity.deviceId,roots:message.roots,pending:new Map(),recent:new Set()};
            this.channels.set(channel.deviceId,channel);release();clearTimeout(timer);send({type:'ready',id:challenge.id,deviceId:channel.deviceId});
          }else throw new Error('Unexpected NAS handshake');return;
        }
        if(!this.active(channel))throw new Error('Device revoked');
        if(message.type==='policy'){this.oauth.setDeviceManifest(channel.deviceId,channel.subject,message.roots);channel.roots=message.roots;return;}
        if(message.type==='commit'){
          const pending=channel.pending.get(message.id);
          if(!pending||pending.operation.name==='list_roots'||!['create_file','create_drive_link'].includes(pending.operation.name)||pending.commitRequested)throw new Error('Unexpected commit request');
          pending.commitRequested=true;
          const currentChannel=channel;
          void (async()=>{
            let allowed=false;
            try {
              if(!pending.authorize)throw new Error('Missing commit authorization');
              await pending.authorize();
              if(!this.active(currentChannel)||!currentChannel.pending.has(message.id))return;
              const rootId=pending.operation.name==='list_roots'?'':pending.operation.args.rootId;
              const root=currentChannel.roots.find(r=>r.id===rootId);
              allowed=pending.rootIds.includes(rootId)&&!!root&&(pending.operation.name==='create_file'?!!root.allowCreate:!!root.allowShare);
            } catch { /* Revocation prevents the NAS from committing. */ }
            if(!currentChannel.pending.has(message.id))return;
            pending.committed=allowed;
            try{send({type:'commit',id:message.id,allowed});}catch{ws.terminate();}
          })();return;
        }
        if(message.type!=='result'&&message.type!=='error')throw new Error('Unexpected NAS message');
        const pending=channel.pending.get(message.id);
        if(!pending){if(channel.recent.has(message.id))return;throw new Error('Unsolicited NAS response');}
        pending.cleanup();
        if(message.type==='error')pending.reject(new NasError(message.code));
        else{try{
          if(['create_file','create_drive_link'].includes(pending.operation.name)&&!pending.committed)throw new Error('Missing commit approval');
          pending.resolve(validateRelayResult(pending.operation,message.value,pending.rootIds));
        }catch{pending.reject(new NasError(['create_file','create_drive_link'].includes(pending.operation.name)?'WRITE_RESULT_UNKNOWN':'INVALID_RELAY_RESPONSE'));ws.terminate();}}
      }catch{ws.terminate();}
    });
    ws.once('close',()=>{
      clearTimeout(timer);clearInterval(heartbeat);release();
      if(channel){if(this.channels.get(channel.deviceId)===channel)this.channels.delete(channel.deviceId);
        for(const pending of [...channel.pending.values()]){pending.cleanup();pending.reject(new NasError((pending.operation.name==='create_file'||pending.operation.name==='create_drive_link')?'WRITE_RESULT_UNKNOWN':'DEVICE_OFFLINE'));}}
    });
  }
  private call(channel:Channel,operation:FileOperation,rootIds:readonly string[],signal?:AbortSignal,allowCreate=false,allowShare=false,authorize?:()=>Promise<void>):Promise<unknown> {
    if(!this.active(channel))return Promise.reject(new NasError('DEVICE_OFFLINE'));
    if(signal?.aborted)return Promise.reject(new NasError('CANCELLED'));
    if(this.pendingCount>=32||channel.pending.size>=4)return Promise.reject(new NasError('BUSY'));
    const id=randomUUID();this.pendingCount++;
    return new Promise((resolve,reject)=>{
      let done=false;
      const cleanup=()=>{if(done)return;done=true;clearTimeout(timer);signal?.removeEventListener('abort',cancel);channel.pending.delete(id);this.pendingCount--;
        channel.recent.add(id);if(channel.recent.size>128)channel.recent.delete(channel.recent.values().next().value!);};
      const cancel=()=>{cleanup();reject(new NasError((operation.name==='create_file'||operation.name==='create_drive_link')?'WRITE_RESULT_UNKNOWN':'CANCELLED'));try{channel.ws.send(encodeRelay({type:'cancel',id}));}catch{channel.ws.terminate();}};
      const timer=setTimeout(()=>{cleanup();reject(new NasError((operation.name==='create_file'||operation.name==='create_drive_link')?'WRITE_RESULT_UNKNOWN':'RELAY_TIMEOUT'));try{channel.ws.send(encodeRelay({type:'cancel',id}));}catch{channel.ws.terminate();}},this.timeoutMs);timer.unref();
      channel.pending.set(id,{operation,rootIds,resolve,reject,cleanup,authorize});signal?.addEventListener('abort',cancel,{once:true});
      try{if(channel.ws.bufferedAmount>MAX_RELAY_BYTES)throw new Error('Backpressure');channel.ws.send(encodeRelay({type:'call',id,rootIds,operation,...(allowCreate?{allowCreate:true}:{}),...(allowShare?{allowShare:true}:{})}));}
      catch{cleanup();reject(new NasError((operation.name==='create_file'||operation.name==='create_drive_link')?'WRITE_RESULT_UNKNOWN':'DEVICE_OFFLINE'));channel.ws.terminate();}
    });
  }
  filesFor(principal:Principal):FileOperations {
    if(!principal.scopes.includes(NAS_READ_SCOPE))throw new NasError('SCOPE_DENIED');
    const channel=principal.deviceId?this.channels.get(principal.deviceId):undefined;
    if(!channel||channel.subject!==principal.subject||!this.active(channel)||!principal.rootIds)throw new NasError('DEVICE_OFFLINE');
    const roots=principal.rootIds;
    const call=<T>(operation:FileOperation,signal?:AbortSignal,authorize?:()=>Promise<void>)=>this.call(channel,operation,roots,signal,principal.scopes.includes(NAS_CREATE_SCOPE),principal.scopes.includes(NAS_SHARE_SCOPE),authorize) as Promise<T>;
    return {
      createDriveLink:(rootId,path,signal,beforeCommit)=>{
        if(!principal.scopes.includes(NAS_SHARE_SCOPE))return Promise.reject(new NasError('SCOPE_DENIED'));
        if(!roots.includes(rootId)||!channel.roots.some(r=>r.id===rootId&&r.allowShare))return Promise.reject(new NasError('SHARE_DENIED'));
        return call<Awaited<ReturnType<NonNullable<FileOperations['createDriveLink']>>>>({name:'create_drive_link',args:{rootId,path}},signal,beforeCommit);
      },
      createFile:(rootId,path,content,signal,beforeCommit)=>{
        if(!principal.scopes.includes(NAS_CREATE_SCOPE))return Promise.reject(new NasError('SCOPE_DENIED'));
        if(!roots.includes(rootId)||!channel.roots.some(r=>r.id===rootId&&r.allowCreate))return Promise.reject(new NasError('CREATE_DENIED'));
        return call<Awaited<ReturnType<NonNullable<FileOperations['createFile']>>>>({name:'create_file',args:{rootId,path,content}},signal,beforeCommit);
      },
      listRoots:()=>{if(!this.active(channel))throw new NasError('DEVICE_OFFLINE');return channel.roots.filter(r=>roots.includes(r.id)).map(r=>({...r}));},
      listDirectory:(rootId,path='',limit=100,signal,offset=0)=>call({name:'list_directory',args:{rootId,path,limit,offset}},signal),
      searchFiles:(rootId,query,limit=100,signal)=>call({name:'search_files',args:{rootId,query,limit}},signal),
      metadata:(rootId,path,signal)=>call({name:'get_metadata',args:{rootId,path}},signal),
      readText:(rootId,path,startLine=1,maxLines=200,signal)=>call({name:'read_text',args:{rootId,path,startLine,maxLines}},signal)
    };
  }
  close(){if(this.closed)return;this.closed=true;if(this.attached){this.attached.removeListener('upgrade',this.upgrade);this.attached=undefined;}for(const ws of this.wss.clients)ws.terminate();this.wss.close();}
}
