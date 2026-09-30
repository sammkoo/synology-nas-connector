import express from 'express';
import { mcpAuthRouter,createOAuthMetadata } from '@modelcontextprotocol/sdk/server/auth/router.js';
import { NAS_READ_SCOPE } from '../../auth/src/index.js';
import { GatewayOAuthProvider } from './oauth.js';

/** OAuth protocol endpoints; account login and consent UI must be mounted by the gateway. */
export function gatewayOAuthRouter(provider:GatewayOAuthProvider) {
  const router=express.Router();
  const options={provider,issuerUrl:new URL(provider.issuer),resourceServerUrl:new URL(provider.resource),scopesSupported:[NAS_READ_SCOPE]};
  const metadata={...createOAuthMetadata(options),authorization_response_iss_parameter_supported:true,
    token_endpoint_auth_methods_supported:['none'],revocation_endpoint_auth_methods_supported:['none']};
  router.use((req,res,next)=>{
    res.set({'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'});
    // SDK-generated authorization error redirects need the same RFC 9207 issuer
    // parameter as our success/denial responses before advertising support.
    if(req.path==='/authorize') {
      const original=res.setHeader.bind(res);
      res.setHeader=((name:string,value: string|number|readonly string[])=>{
        if(name.toLowerCase()==='location'&&typeof value==='string') {
          const url=new URL(value,provider.issuer);
          if(url.searchParams.has('error')||url.searchParams.has('code')) {
            url.searchParams.set('iss',provider.issuer);
            if(!url.searchParams.has('state')&&typeof req.query.state==='string'&&req.query.state.length<=1024)url.searchParams.set('state',req.query.state);
            value=url.href;
          }
        }
        return original(name,value);
      }) as typeof res.setHeader;
    }
    next();
  });
  router.use(['/token','/revoke','/authorize'],express.urlencoded({extended:false,limit:'16kb',parameterLimit:20}));
  router.use('/register',express.json({limit:'16kb',strict:true}));
  router.get('/.well-known/oauth-authorization-server',(_req,res)=>{res.set('Access-Control-Allow-Origin','*').json(metadata);});
  const resource=new URL(provider.resource);
  const prmPath=`/.well-known/oauth-protected-resource${resource.pathname==='/'?'':resource.pathname}`;
  router.get(prmPath,(_req,res)=>{res.set('Access-Control-Allow-Origin','*').json(provider.authenticator().resourceMetadata);});
  router.use(mcpAuthRouter(options));
  router.use((e:{status?:number},_req:express.Request,res:express.Response,_next:express.NextFunction)=>{
    res.status(e.status===413?413:400).json({error:'invalid_request',error_description:'The request could not be processed.'});
  });
  return router;
}
