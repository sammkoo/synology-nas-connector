import express from 'express';
import { z } from 'zod';
import { DevicePairing } from './pairing.js';
import { GatewayOAuthProvider } from './oauth.js';
import { gatewayOAuthRouter } from './router.js';
import { gatewayBrowserRouter } from './browser.js';
import { GatewayEdgeGuard,type GatewayEdgeOptions } from './edge.js';
import { GatewayRelay } from './relay.js';
import { gatewayMcpRouter } from './mcp.js';
export type { GatewayEdgeOptions } from './edge.js';

/** Gateway control-plane app. The MCP relay must be attached before deployment. */
export function createGatewayApp(oauth:GatewayOAuthProvider,edge:GatewayEdgeOptions={},relay?:GatewayRelay) {
  const app=express(),pairing=new DevicePairing(oauth),issuer=new URL(oauth.issuer);
  if(relay&&(relay.oauth!==oauth||new URL(oauth.resource).origin!==issuer.origin||new URL(oauth.resource).pathname!=='/mcp'))throw new Error('Relay requires the same provider and issuer /mcp resource');
  const guard=relay?.edgeGuard??new GatewayEdgeGuard(oauth,edge);
  app.disable('x-powered-by');
  app.use((req,res,next)=>{
    res.set({'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer','Strict-Transport-Security':'max-age=31536000'});
    const rejected=guard.check(req);if(rejected){if(rejected.status===429)res.set('Retry-After','60');res.status(rejected.status).json({error:rejected.error});return;}next();
  });
  app.get('/health',(_req,res)=>{res.json(relay?.attachedToListener?{status:'ready',relay:'attached'}:{status:'control-plane-ready',relay:'not-attached'});});
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
  if(relay)app.use(gatewayMcpRouter(oauth,relay));
  app.use(gatewayOAuthRouter(oauth));
  app.use((_req,res)=>{res.status(404).json({error:'not_found'});});
  return app;
}
export function createGatewayRuntime(oauth:GatewayOAuthProvider,edge:GatewayEdgeOptions={}) {
  const relay=new GatewayRelay(oauth,new GatewayEdgeGuard(oauth,edge));return {app:createGatewayApp(oauth,edge,relay),relay};
}
