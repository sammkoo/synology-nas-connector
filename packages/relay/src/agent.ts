import WebSocket from 'ws';
import { createPublicKey,sign,type KeyObject } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import type { LookupFunction } from 'node:net';
import { NasError,executeReadOnly,type ReadOnlyFileProvider } from '../../core/src/index.js';
import { MAX_RELAY_BYTES,RELAY_PROTOCOL,rootsSchema,relayProofMessage,encodeRelay,gatewayMessageSchema,agentMessageSchema,type RelayChallenge } from './protocol.js';

export type AgentState='stopped'|'connecting'|'online'|'offline';
export type NasRelayOptions={issuer:string;privateKey:KeyObject;source:ReadOnlyFileProvider;
  trust?:{ca?:WebSocket.ClientOptions['ca'];lookup?:LookupFunction};onState?:(state:AgentState)=>void;maxConcurrent?:number};
export class NasRelayAgent {
  readonly publicKey:string;state:AgentState='stopped';deviceId?:string;
  private socket?:WebSocket;private shutdown?:AbortController;private loop?:Promise<void>;
  private stopping=false;
  // Retain slots until OS I/O actually finishes, even across cancellation/reconnect.
  private readonly calls=new Map<string,AbortController>();
  private readonly issuer:string;private readonly maxConcurrent:number;
  constructor(private readonly options:NasRelayOptions) {
    const url=new URL(options.issuer);
    if(url.protocol!=='https:'||url.pathname!=='/'||url.href!==options.issuer||url.search||url.hash||url.username||url.password||options.privateKey.type!=='private'||options.privateKey.asymmetricKeyType!=='ed25519')throw new Error('Canonical HTTPS gateway and private NAS key required');
    this.issuer=url.href;this.publicKey=createPublicKey(options.privateKey).export({type:'spki',format:'der'}).toString('base64url');
    this.maxConcurrent=options.maxConcurrent??4;
    if(!Number.isInteger(this.maxConcurrent)||this.maxConcurrent<1||this.maxConcurrent>32)throw new Error('Invalid relay concurrency');
  }
  private current(){return typeof this.options.source==='function'?this.options.source():this.options.source;}
  private status(state:AgentState){this.state=state;try{this.options.onState?.(state);}catch{ /* State observers cannot bypass protocol. */ }}
  async connect():Promise<void> {
    if(this.socket)throw new Error('Relay is already connecting');this.stopping=false;this.status('connecting');
    const url=new URL('agent/relay',this.issuer);url.protocol='wss:';
    const ws=new WebSocket(url,RELAY_PROTOCOL,{...this.options.trust,rejectUnauthorized:true,followRedirects:false,perMessageDeflate:false,
      maxPayload:16384,maxFragments:64,maxBufferedChunks:32,handshakeTimeout:10000});
    this.socket=ws;let challenge:RelayChallenge|undefined,manifest='',ready=false,settled=false;
    const calls=this.calls;
    let policyTimer:NodeJS.Timeout|undefined;
    const handshake=setTimeout(()=>ws.terminate(),10000);handshake.unref();
    const send=(value:unknown)=>{if(ws.readyState!==WebSocket.OPEN||ws.bufferedAmount>MAX_RELAY_BYTES)throw new NasError('RELAY_TIMEOUT');ws.send(encodeRelay(value));};
    return new Promise<void>((resolve,reject)=>{
      ws.on('open',()=>{try{send({type:'hello',publicKey:this.publicKey});}catch{ws.terminate();}});
      ws.on('message',(raw,binary)=>{
        try{
          if(binary)throw new Error('Binary protocol frame');
          const message=gatewayMessageSchema.parse(JSON.parse(raw.toString()));
          if(!ready){
            if(message.type==='challenge'&&!challenge){
              if(message.issuer!==this.issuer)throw new Error('Gateway issuer mismatch');challenge=message;
              const roots=rootsSchema.parse(this.current().listRoots());manifest=JSON.stringify(roots);
              send({type:'proof',roots,signature:sign(null,relayProofMessage(challenge,this.publicKey,roots),this.options.privateKey).toString('base64url')});
            }else if(message.type==='ready'&&challenge&&message.id===challenge.id){
              ready=true;settled=true;clearTimeout(handshake);this.deviceId=message.deviceId;this.status('online');resolve();
              policyTimer=setInterval(()=>{
                try{const roots=rootsSchema.parse(this.current().listRoots()),next=JSON.stringify(roots);if(next!==manifest){send({type:'policy',roots});manifest=next;}}catch{ws.terminate();}
              },1000);policyTimer.unref();
            }else throw new Error('Unexpected handshake frame');return;
          }
          if(message.type==='cancel'){calls.get(message.id)?.abort();return;}
          if(message.type!=='call')throw new Error('Unexpected gateway frame');
          if(calls.has(message.id))throw new Error('Duplicate relay request');
          if(calls.size>=this.maxConcurrent){send({type:'error',id:message.id,code:'BUSY'});return;}
          const abort=new AbortController();calls.set(message.id,abort);
          const timeout=setTimeout(()=>abort.abort(),15000);timeout.unref();
          void (async()=>{
            try{
              const files=this.current();
              const value=await executeReadOnly(files,message.operation,message.rootIds,abort.signal);
              if(this.current()!==files)throw new NasError('CONFIGURATION_CHANGED');
              if(abort.signal.aborted)throw new NasError('CANCELLED');
              send({type:'result',id:message.id,value});
            }catch(e){
              const safe=agentMessageSchema.safeParse({type:'error',id:message.id,code:e instanceof NasError?e.code:'OPERATION_FAILED'});
              try{send(safe.success?safe.data:{type:'error',id:message.id,code:'OPERATION_FAILED'});}catch{ws.terminate();}
            }finally{clearTimeout(timeout);calls.delete(message.id);}
          })();
        }catch{ws.terminate();}
      });
      ws.on('error',()=>{ /* Closing socket produces a sanitized failure. */ });
      ws.once('close',()=>{
        clearTimeout(handshake);if(policyTimer)clearInterval(policyTimer);for(const abort of calls.values())abort.abort();
        if(this.socket===ws)this.socket=undefined;this.deviceId=undefined;this.status(this.stopping||this.shutdown?.signal.aborted?'stopped':'offline');
        if(!settled){settled=true;reject(new NasError('RELAY_CONNECTION_FAILED'));}
      });
    });
  }
  start() {
    if(this.loop)return;if(this.socket)throw new Error('Stop the existing relay before enabling reconnection');this.shutdown=new AbortController();const signal=this.shutdown.signal;
    this.loop=(async()=>{
      let attempts=0;
      while(!signal.aborted){
        try{await this.connect();attempts=0;const ws=this.socket;if(ws)await new Promise<void>(resolve=>{if(ws.readyState===WebSocket.CLOSED)resolve();else ws.once('close',()=>resolve());});}
        catch{if(!signal.aborted)this.status('offline');}
        if(!signal.aborted)await delay(Math.min(30000,1000*2**Math.min(attempts++,5))+Math.floor(Math.random()*1000),undefined,{signal}).catch(()=>{});
      }
    })().finally(()=>{this.loop=undefined;this.status('stopped');});
  }
  async stop(){
    this.stopping=true;this.shutdown?.abort();const ws=this.socket;
    const closed=ws?new Promise<void>(resolve=>{if(ws.readyState===WebSocket.CLOSED)resolve();else ws.once('close',()=>resolve());}):Promise.resolve();
    ws?.terminate();await closed;await this.loop;this.status('stopped');
  }
}
