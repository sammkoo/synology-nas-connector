import express from 'express';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { createMcpServer } from '../../../apps/server/src/mcp.js';
import { NasError,type FileOperations } from '../../core/src/index.js';
import { NAS_READ_SCOPE,type Principal } from '../../auth/src/index.js';
import { GatewayOAuthProvider } from './oauth.js';
import { GatewayRelay } from './relay.js';

export function gatewayMcpRouter(oauth:GatewayOAuthProvider,relay:GatewayRelay) {
  const router=express.Router(),auth=oauth.authenticator();let active=0;
  router.post('/mcp',(req,res,next)=>{
    if(active>=32){res.status(503).json({error:'busy'});return;}active++;let released=false;
    const release=()=>{if(!released){released=true;active--;}};res.once('close',release);res.once('finish',release);next();
  },express.json({limit:'128kb',strict:true}),async(req,res)=>{
    const header=req.headers.authorization;
    const match=/^Bearer ([A-Za-z0-9_-]{43})$/.exec(header??'');
    const token=match?.[1];
    let principal:Principal={subject:'anonymous',scopes:[],rootIds:[]};
    if(header!==undefined){
      const verified=token?await auth.authenticate(token):null;
      if(!verified){res.status(401).set('WWW-Authenticate',`${auth.challenge}, error="invalid_token"`).json({error:'unauthorized'});return;}
      principal=verified;
    }
    const controller=new AbortController();let files:FileOperations|undefined;
    const source=()=>files??=relay.filesFor(principal);
    const revalidate=async()=>{
      const current=token?await auth.authenticate(token):null;
      if(!current||current.subject!==principal.subject||current.deviceId!==principal.deviceId||!current.scopes.includes(NAS_READ_SCOPE)||JSON.stringify([...current.scopes].sort())!==JSON.stringify([...principal.scopes].sort())||
        JSON.stringify([...(current.rootIds??[])].sort())!==JSON.stringify([...(principal.rootIds??[])].sort()))throw new NasError('AUTHENTICATION_REQUIRED');
    };
    const server=createMcpServer(source,principal,{oauthChallenge:auth.challenge,revalidate,signal:controller.signal});
    const transport=new StreamableHTTPServerTransport({sessionIdGenerator:undefined,enableJsonResponse:true});
    const deadline=setTimeout(()=>{controller.abort();if(!res.headersSent)res.status(504).json({error:'request_timeout'});res.end();},40000);deadline.unref();
    res.once('close',()=>{clearTimeout(deadline);controller.abort();void transport.close();void server.close();});
    try{await server.connect(transport);await transport.handleRequest(req,res,req.body);}
    catch{if(!res.headersSent)res.status(500).json({error:'mcp_request_failed'});}
  });
  router.all('/mcp',(_req,res)=>{res.set('Allow','POST').status(405).json({error:'method_not_allowed'});});
  router.use((e:{status?:number},_req:express.Request,res:express.Response,_next:express.NextFunction)=>{res.status(e.status===413?413:400).json({error:'invalid_request'});});
  return router;
}
