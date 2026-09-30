import { createServer as createHttpServer,request as httpRequest,type Server } from 'node:http';
import { createServer as createHttpsServer,request as httpsRequest } from 'node:https';
import type { Socket } from 'node:net';
import { isIP } from 'node:net';
import { checkServerIdentity } from 'node:tls';
import { GatewayStore } from './store.js';
import { GatewayOAuthProvider } from './oauth.js';
import { createGatewayRuntime } from './app.js';
import { gatewayDeploymentSchema,readGatewayKey,readDeploymentFile,type GatewayDeploymentConfig } from './deployment.js';

/** Single-instance listener. Configuration must have resolved absolute file paths. */
export async function startGateway(input:GatewayDeploymentConfig) {
  const config=gatewayDeploymentSchema.parse(input),key=await readGatewayKey(config);
  let store:GatewayStore|undefined,server:Server|undefined;
  let relay:ReturnType<typeof createGatewayRuntime>['relay']|undefined;
  try{
    store=await GatewayStore.open(config.dataDirectory,key,Date.now,{exclusive:true,maxDatabaseBytes:config.limits.databaseMaxBytes,create:false});
    key.fill(0);
    const binding=store.get<{version:number;issuer:string;keyCheck:string}>('installation','gateway');
    if(binding?.version!==1||binding.issuer!==config.issuer||binding.keyCheck!==store.key('installation','gateway-deployment-v1'))throw new Error('Gateway database/key backup mismatch');
    const oauth=new GatewayOAuthProvider(store,{issuer:config.issuer,resource:new URL('mcp',config.issuer).href,redirectUris:config.redirectUris});
    const runtime=createGatewayRuntime(oauth,config.transport.mode==='proxy'?{trustedProxyAddresses:config.transport.trustedProxyAddresses}:{});relay=runtime.relay;
    const options={maxHeaderSize:16384,headersTimeout:10000,requestTimeout:15000,connectionsCheckingInterval:1000,keepAliveTimeout:5000,requireHostHeader:true};
    if(config.transport.mode==='https'){
      const certificate=await readDeploymentFile(config.transport.certificateFile,1024*1024,false),tlsKey=await readDeploymentFile(config.transport.privateKeyFile,16384);
      try{server=createHttpsServer({...options,cert:certificate,key:tlsKey,minVersion:'TLSv1.2',handshakeTimeout:10000},runtime.app);}finally{tlsKey.fill(0);}
      server.on('tlsClientError',()=>{});
    }else server=createHttpServer(options,runtime.app);
    const listener=server,database=store;const sockets=new Set<Socket>();
    listener.maxConnections=config.limits.maxConnections;
    listener.setTimeout(45000,socket=>socket.destroy());
    listener.on('connection',socket=>{sockets.add(socket);socket.once('close',()=>sockets.delete(socket));});
    listener.on('clientError',(_error,socket)=>socket.destroy());
    relay.attach(listener);
    await new Promise<void>((resolve,reject)=>{
      const error=(e:Error)=>{listener.off('listening',ready);reject(e);},ready=()=>{listener.off('error',error);resolve();};
      listener.once('error',error);listener.once('listening',ready);listener.listen(config.transport.port,config.transport.host);
    });
    // No access logs, headers, request URLs, account identifiers or bodies.
    const prune=setInterval(()=>{try{database.prune();}catch{/* Full/broken storage fails requests closed; avoid raw error logs. */}},60000);prune.unref();
    let stopping:Promise<void>|undefined;
    const close=()=>stopping??=(async()=>{
      clearInterval(prune);relay!.close();
      await new Promise<void>(resolve=>{
        const deadline=setTimeout(()=>{for(const socket of sockets)socket.destroy();},5000);deadline.unref();
        listener.close(()=>{clearTimeout(deadline);resolve();});listener.closeIdleConnections();
      });
      database.close();
    })();
    return {server:listener,oauth,relay:runtime.relay,close};
  }catch(e){relay?.close();server?.close();store?.close();throw e;}finally{key.fill(0);}
}

/** Probe only the configured local listener, preserving TLS verification and Host. */
export async function checkGatewayHealth(config:GatewayDeploymentConfig) {
  const tls=config.transport.mode==='https',host=config.transport.host==='0.0.0.0'?'127.0.0.1':config.transport.host==='::'?'::1':config.transport.host;
  const issuer=new URL(config.issuer),tlsName=issuer.hostname.replace(/^\[|\]$/g,''),headers:Record<string,string>={Host:issuer.host};
  if(!tls){headers['X-Forwarded-Proto']='https';headers['X-Forwarded-For']=host;}
  return new Promise<void>((resolve,reject)=>{
    const request=(tls?httpsRequest:httpRequest)({hostname:host,port:config.transport.port,path:'/health',method:'GET',headers,...(tls?{servername:isIP(tlsName)?undefined:tlsName,checkServerIdentity:(_name:string,cert:import('node:tls').PeerCertificate)=>checkServerIdentity(tlsName,cert),rejectUnauthorized:true,minVersion:'TLSv1.2'}:{})},response=>{
      let body='';response.setEncoding('utf8');response.on('data',chunk=>{body+=chunk;if(body.length>256)request.destroy(new Error('Invalid health response'));});
      response.on('error',reject);response.on('end',()=>{
        try{const status=JSON.parse(body);if(response.statusCode!==200||status.status!=='ready'||status.relay!=='attached')throw new Error('Not ready');resolve();}catch{reject(new Error('Gateway is not ready'));}
      });
    });const deadline=setTimeout(()=>request.destroy(new Error('Gateway health timeout')),2000);request.once('close',()=>clearTimeout(deadline));request.on('error',reject);request.end();
  });
}
