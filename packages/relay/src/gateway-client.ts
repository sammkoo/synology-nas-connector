import { lookup as dnsLookup } from 'node:dns';
import { request,Agent,type RequestOptions } from 'node:https';
import { isIP,type LookupFunction } from 'node:net';
import ipaddr from 'ipaddr.js';
import { z } from 'zod';
import { pairingBeginSchema,pairingPollSchema,deviceRevocationSchema,type DeviceRevocation } from './pairing-protocol.js';

export class GatewayClientError extends Error {constructor(readonly code:string){super(code);}}
export function isPublicGatewayAddress(address:string) {
  try{const parsed=ipaddr.process(address);return Boolean(isIP(address))&&parsed.range()==='unicast'&&
    (parsed.kind()==='ipv4'||parsed.match(ipaddr.parse('2000::'),3));}catch{return false;}
}
/** Validate all DNS answers and give the socket those exact addresses. */
export function publicGatewayLookup(resolve:typeof dnsLookup=dnsLookup):LookupFunction {
  return (hostname,options,callback)=>{
    resolve(hostname,{all:true,verbatim:true,family:options.family??0},(error,addresses)=>{
      if(error){callback(new GatewayClientError('GATEWAY_DNS_FAILED'),'',4);return;}
      if(!addresses.length||addresses.some(item=>!isPublicGatewayAddress(item.address))){callback(new GatewayClientError('GATEWAY_ADDRESS_DENIED'),'',4);return;}
      if(options.all)callback(null,addresses);else callback(null,addresses[0]!.address,addresses[0]!.family);
    });
  };
}
export function canonicalGatewayIssuer(value:string) {
  let url:URL;try{url=new URL(value.trim());}catch{throw new GatewayClientError('GATEWAY_URL_INVALID');}
  if(url.protocol!=='https:'||url.pathname!=='/'||url.search||url.hash||url.username||url.password||url.href.length>2048||/\s/.test(value.trim()))throw new GatewayClientError('GATEWAY_URL_INVALID');
  return url.href;
}
export type GatewayClientTrust={ca?:RequestOptions['ca'];lookup?:LookupFunction};
export class GatewayAgentClient {
  readonly issuer:string;readonly lookup:LookupFunction;
  constructor(issuer:string,readonly trust:GatewayClientTrust={}) {
    this.issuer=canonicalGatewayIssuer(issuer);this.lookup=trust.lookup??publicGatewayLookup();
    const hostname=new URL(this.issuer).hostname.replace(/^\[|\]$/g,'');
    if(!trust.lookup&&isIP(hostname)&&!isPublicGatewayAddress(hostname))throw new GatewayClientError('GATEWAY_ADDRESS_DENIED');
  }
  private async post(endpoint:'begin'|'poll'|'approve'|'revoke',body:unknown):Promise<unknown> {
    const data=Buffer.from(JSON.stringify(body));if(data.length>16384)throw new GatewayClientError('GATEWAY_REQUEST_INVALID');
    const agent=new Agent({keepAlive:false,maxSockets:1});
    try{return await new Promise((resolve,reject)=>{
      let settled=false;
      const finish=(error?:GatewayClientError,value?:unknown)=>{if(settled)return;settled=true;clearTimeout(deadline);if(error)reject(error);else resolve(value);};
      const req=request(new URL(`agent/pair/${endpoint}`,this.issuer),{agent,lookup:this.lookup,ca:this.trust.ca,rejectUnauthorized:true,minVersion:'TLSv1.2',method:'POST',
        headers:{'Content-Type':'application/json',Accept:'application/json','Content-Length':String(data.length)}},response=>{
        if(response.statusCode!==200||response.headers['content-type']?.split(';')[0]!=='application/json'){
          finish(new GatewayClientError('GATEWAY_REQUEST_DENIED'));req.destroy();return;
        }
        const chunks:Buffer[]=[];let bytes=0;
        response.on('data',chunk=>{bytes+=chunk.length;if(bytes>16384){finish(new GatewayClientError('GATEWAY_RESPONSE_INVALID'));req.destroy();}else chunks.push(Buffer.from(chunk));});
        response.on('error',()=>finish(new GatewayClientError('GATEWAY_UNAVAILABLE')));
        response.on('end',()=>{try{finish(undefined,JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(chunks))));}catch{finish(new GatewayClientError('GATEWAY_RESPONSE_INVALID'));}});
      });
      const deadline=setTimeout(()=>{finish(new GatewayClientError('GATEWAY_TIMEOUT'));req.destroy();},3000);
      req.on('error',(error:NodeJS.ErrnoException)=>{
        const tlsErrors=['DEPTH_ZERO_SELF_SIGNED_CERT','CERT_HAS_EXPIRED','ERR_TLS_CERT_ALTNAME_INVALID','UNABLE_TO_GET_ISSUER_CERT_LOCALLY','UNABLE_TO_VERIFY_LEAF_SIGNATURE','SELF_SIGNED_CERT_IN_CHAIN'];
        finish(error instanceof GatewayClientError?error:new GatewayClientError(tlsErrors.includes(error.code??'')?'GATEWAY_TLS_REQUIRED':'GATEWAY_UNAVAILABLE'));
      });req.end(data);
    });}finally{agent.destroy();}
  }
  async begin(publicKey:string,label:string,rootIds:string[]) {
    const result=pairingBeginSchema.safeParse(await this.post('begin',{publicKey,label,rootIds}));
    if(!result.success||result.data.verificationUri!==new URL('connect/pair',this.issuer).href)throw new GatewayClientError('GATEWAY_RESPONSE_INVALID');return result.data;
  }
  async poll(deviceCode:string) {
    const result=pairingPollSchema.safeParse(await this.post('poll',{deviceCode}));if(!result.success)throw new GatewayClientError('GATEWAY_RESPONSE_INVALID');return result.data;
  }
  async approve(deviceCode:string,signature:string) {
    const result=z.object({deviceId:z.string().uuid()}).strict().safeParse(await this.post('approve',{deviceCode,signature}));if(!result.success)throw new GatewayClientError('GATEWAY_RESPONSE_INVALID');return result.data;
  }
  async revoke(request:DeviceRevocation) {
    deviceRevocationSchema.parse(request);
    const result=z.object({revoked:z.literal(true)}).strict().safeParse(await this.post('revoke',request));if(!result.success)throw new GatewayClientError('GATEWAY_RESPONSE_INVALID');return result.data;
  }
}
