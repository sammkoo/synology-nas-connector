import express from 'express';
import { z } from 'zod';
import { BridgeGuard, ManagementError, type ConfigurationStore,type NasConnectionController } from '../../../packages/management/src/index.js';
import { GatewayClientError } from '../../../packages/relay/src/gateway-client.js';

export function managementRouter(store: ConfigurationStore, guard: BridgeGuard,connection?:NasConnectionController) {
  const router = express.Router();
  router.use(express.raw({type:'application/json',limit:'16kb'}));
  router.use((req,res,next)=>{
    res.set({'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'});
    try {
      const header = (name: string) => typeof req.headers[name] === 'string' ? req.headers[name] as string : '';
      const body = Buffer.isBuffer(req.body) ? req.body : Buffer.alloc(0);
      const user = header('x-nas-user');
      const csrf = header('x-nas-csrf');
      guard.verify({method:req.method,path:req.originalUrl,user,timestamp:header('x-nas-timestamp'),nonce:header('x-nas-nonce'),csrf,body},
        header('x-nas-signature'),req.socket.remoteAddress);
      if (req.method !== 'GET') guard.checkCsrf(user,csrf);
      res.locals.user = user;
      next();
    } catch(e) {next(e);}
  });
  router.get('/bootstrap',async(req,res,next)=>{
    try {res.json({...(await store.status()),...(connection?{connection:connection.status(res.locals.user)}:{}),user:res.locals.user,csrf:guard.issueCsrf(res.locals.user)});} catch(e){next(e);}
  });
  router.post('/roots',async(req,res,next)=>{
    try {
      const body = z.object({ids:z.array(z.string().regex(/^share_[a-f0-9]{20}$/)).max(20),
        revision:z.string().regex(/^[a-f0-9]{64}$/)}).strict().parse(JSON.parse(req.body.toString('utf8')));
      res.json({...(await store.saveRoots(body.ids,body.revision)),...(connection?{connection:connection.status(res.locals.user)}:{})});
    } catch(e){next(e);}
  });
  router.post('/preview',async(req,res,next)=>{
    try {
      const {rootId} = z.object({rootId:z.string().min(1).max(40)}).strict().parse(JSON.parse(req.body.toString('utf8')));
      const files = store.getFiles();
      const preview = await files.listDirectory(rootId,'',10);
      if (files !== store.getFiles()) throw new ManagementError('CONFIGURATION_CHANGED',409);
      res.json(preview);
    } catch(e){next(e);}
  });
  const requireConnection=()=>{if(!connection)throw new ManagementError('CONNECTION_UNAVAILABLE',503);return connection;};
  const json=(req:express.Request)=>JSON.parse(req.body.toString('utf8'));
  router.post('/pair-begin',async(req,res,next)=>{try{
    const body=z.object({issuer:z.string().min(1).max(2048),label:z.string().trim().min(1).max(100),consent:z.literal(true),revision:z.string().regex(/^[a-f0-9]{64}$/)}).strict().parse(json(req));
    if(body.revision!==store.revision())throw new ManagementError('CONFIGURATION_CHANGED',409);
    res.json(await requireConnection().begin(res.locals.user,body.issuer,body.label,store.getFiles()));
  }catch(e){next(e);}});
  router.post('/pair-status',async(req,res,next)=>{try{z.object({}).strict().parse(json(req));res.json(await requireConnection().poll(res.locals.user));}catch(e){next(e);}});
  router.post('/pair-confirm',async(req,res,next)=>{try{
    const body=z.object({pairId:z.string().uuid(),proofHash:z.string().regex(/^[a-f0-9]{64}$/),comparison:z.string().regex(/^\d{6}$/)}).strict().parse(json(req));
    res.json(await requireConnection().confirm(res.locals.user,body.pairId,body.proofHash,body.comparison));
  }catch(e){next(e);}});
  router.post('/pair-cancel',async(req,res,next)=>{try{
    const body=z.object({pairId:z.string().uuid()}).strict().parse(json(req));res.json(await requireConnection().cancel(res.locals.user,body.pairId));
  }catch(e){next(e);}});
  router.post('/pair-disconnect',async(req,res,next)=>{try{z.object({}).strict().parse(json(req));res.json(await requireConnection().disconnect(res.locals.user));}catch(e){next(e);}});
  router.use((_req,res)=>{res.status(404).json({error:'UNKNOWN_MANAGEMENT_ACTION'});});
  router.use((e: unknown,_req:express.Request,res:express.Response,_next:express.NextFunction)=>{
    const status = e instanceof ManagementError ? e.status : 400;
    res.status(status).json({error:e instanceof ManagementError||e instanceof GatewayClientError ? e.code : 'MANAGEMENT_REQUEST_FAILED'});
  });
  return router;
}
