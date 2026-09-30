import express from 'express';
import { isIP } from 'node:net';
import { z } from 'zod';
import { DevicePairing } from './pairing.js';
import { GatewayOAuthProvider } from './oauth.js';
import { gatewayOAuthRouter } from './router.js';
import { gatewayBrowserRouter } from './browser.js';

export type GatewayEdgeOptions={trustedProxyAddresses?:readonly string[]};
/** Gateway control-plane app. The MCP relay must be attached before deployment. */
export function createGatewayApp(oauth:GatewayOAuthProvider,edge:GatewayEdgeOptions={}) {
  const app=express(),pairing=new DevicePairing(oauth),issuer=new URL(oauth.issuer);
  const trusted=edge.trustedProxyAddresses??[];
  if(trusted.some(ip=>!isIP(ip)))throw new Error('Proxy addresses must be exact IP addresses');
  app.disable('x-powered-by');
  const windows=new Map<string,{at:number;count:number}>();let at=oauth.store.now(),total=0;
  app.use((req,res,next)=>{
    res.set({'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer','Strict-Transport-Security':'max-age=31536000'});
    const peer=req.socket.remoteAddress??'';
    const proxy=trusted.includes(peer);
    if(req.headers.host!==issuer.host||(!('encrypted' in req.socket&&req.socket.encrypted)&&!(proxy&&req.headers['x-forwarded-proto']==='https'))){res.status(403).json({error:'secure_transport_required'});return;}
    // A trusted proxy must overwrite (not append) both headers. Never trust a chain.
    const forwarded=req.headers['x-forwarded-for'];
    if(proxy&&(typeof forwarded!=='string'||!isIP(forwarded))){res.status(403).json({error:'invalid_proxy_provenance'});return;}
    const ip=proxy?forwarded as string:peer,now=oauth.store.now();
    if(now-at>=60_000){at=now;total=0;for(const [key,entry] of windows)if(now-entry.at>=60_000)windows.delete(key);}
    let entry=windows.get(ip);
    if(!entry||now-entry.at>=60_000){if(!entry&&windows.size>=10000){res.status(429).json({error:'busy'});return;}entry={at:now,count:0};windows.set(ip,entry);}
    if(++total>600||++entry.count>120){res.set('Retry-After','60').status(429).json({error:'rate_limited'});return;}next();
  });
  app.get('/health',(_req,res)=>{res.json({status:'control-plane-ready',relay:'not-attached'});});
  app.use('/connect',gatewayBrowserRouter(oauth,pairing));
  const agent=express.Router();
  agent.use((req,res,next)=>{
    if(req.headers.origin!==undefined){res.status(403).json({error:'agent_request_required'});return;}
    if(!req.is('application/json')){res.status(415).json({error:'json_required'});return;}next();
  },express.json({limit:'16kb',strict:true}));
  const code=z.object({deviceCode:z.string().regex(/^[A-Za-z0-9_-]{43}$/)}).strict();
  agent.post('/begin',(req,res)=>{
    const input=z.object({publicKey:z.string().max(100),label:z.string().max(100),rootIds:z.array(z.string().max(40)).max(20)}).strict().parse(req.body);
    res.json(pairing.begin(input.publicKey,input.label,input.rootIds));
  });
  agent.post('/poll',(req,res)=>{res.json(pairing.poll(code.parse(req.body).deviceCode));});
  agent.post('/approve',(req,res)=>{
    const input=code.extend({signature:z.string().regex(/^[A-Za-z0-9_-]{86}$/)}).parse(req.body);res.json(pairing.approve(input.deviceCode,input.signature));
  });
  agent.use((e:{status?:number},_req:express.Request,res:express.Response,_next:express.NextFunction)=>{res.status(e.status===413?413:400).json({error:'pairing_request_failed'});});
  app.use('/agent/pair',agent);
  app.use(gatewayOAuthRouter(oauth));
  app.use((_req,res)=>{res.status(404).json({error:'not_found'});});
  return app;
}
