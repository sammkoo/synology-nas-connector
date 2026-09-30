import type { IncomingMessage } from 'node:http';
import { isIP } from 'node:net';
import { GatewayOAuthProvider } from './oauth.js';
export type GatewayEdgeOptions={trustedProxyAddresses?:readonly string[]};
/** One shared guard/rate budget for HTTP requests and WebSocket upgrades. */
export class GatewayEdgeGuard {
  private readonly trusted:readonly string[];private readonly host:string;
  private readonly windows=new Map<string,{at:number;count:number}>();private at:number;private total=0;
  constructor(private readonly oauth:GatewayOAuthProvider,options:GatewayEdgeOptions={}) {
    this.trusted=options.trustedProxyAddresses??[];this.host=new URL(oauth.issuer).host;this.at=oauth.store.now();
    if(this.trusted.some(ip=>!isIP(ip)))throw new Error('Proxy addresses must be exact IP addresses');
  }
  check(req:IncomingMessage):{status:number;error:string}|undefined {
    const peer=req.socket.remoteAddress??'',proxy=this.trusted.includes(peer),forwarded=req.headers['x-forwarded-for'];
    if(req.headers.host!==this.host||(!('encrypted' in req.socket&&req.socket.encrypted)&&!(proxy&&req.headers['x-forwarded-proto']==='https')))return {status:403,error:'secure_transport_required'};
    if(proxy&&(typeof forwarded!=='string'||!isIP(forwarded)))return {status:403,error:'invalid_proxy_provenance'};
    const ip=proxy?forwarded as string:peer,now=this.oauth.store.now();
    if(now-this.at>=60_000){this.at=now;this.total=0;for(const [key,e] of this.windows)if(now-e.at>=60_000)this.windows.delete(key);}
    let entry=this.windows.get(ip);
    if(!entry||now-entry.at>=60_000){if(!entry&&this.windows.size>=10000)return {status:429,error:'busy'};entry={at:now,count:0};this.windows.set(ip,entry);}
    if(++this.total>600||++entry.count>120)return {status:429,error:'rate_limited'};
  }
}
