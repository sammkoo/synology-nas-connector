import { randomBytes,randomUUID,createHash,timingSafeEqual } from 'node:crypto';
import type { Response } from 'express';
import type { OAuthServerProvider,AuthorizationParams } from '@modelcontextprotocol/sdk/server/auth/provider.js';
import type { OAuthRegisteredClientsStore } from '@modelcontextprotocol/sdk/server/auth/clients.js';
import type { OAuthClientInformationFull,OAuthTokens,OAuthTokenRevocationRequest } from '@modelcontextprotocol/sdk/shared/auth.js';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import { InvalidClientMetadataError,InvalidGrantError,InvalidTokenError,InvalidScopeError,InvalidTargetError,InvalidRequestError } from '@modelcontextprotocol/sdk/server/auth/errors.js';
import { NAS_READ_SCOPE,type Authenticator } from '../../auth/src/index.js';
import { GatewayStore } from './store.js';

const fresh=()=>randomBytes(32).toString('base64url');
const DAY=86400_000;
type Device={subject:string;label:string;rootIds:string[];rootVersions:Record<string,number>;revision:number;revoked:boolean};
type Pending={issuer:string;clientId:string;redirectUri:string;resource:string;challenge:string;state?:string;scopes:string[]};
type Grant={issuer:string;subject:string;deviceId:string;rootIds:string[];rootVersions:Record<string,number>;clientId:string;resource:string;scopes:string[];expires:number;revoked:boolean};
type Code=Pending&{grantId:string};
type Token={grantId:string;clientId:string;resource:string;expires:number};
type Refresh=Token&{used:boolean};
export type GatewayOAuthOptions={issuer:string;resource:string;redirectUris:readonly string[];accessSeconds?:number;grantDays?:number};

/** Durable opaque tokens. No OpenAI identity token is accepted as a NAS credential. */
export class GatewayOAuthProvider implements OAuthServerProvider {
  readonly clientsStore:OAuthRegisteredClientsStore;
  readonly issuer:string;
  readonly resource:string;
  private readonly accessSeconds:number;
  private readonly grantDays:number;
  constructor(readonly store:GatewayStore,private readonly options:GatewayOAuthOptions) {
    const issuer=new URL(options.issuer),resource=new URL(options.resource);
    for(const url of [issuer,resource])if(url.protocol!=='https:'||url.username||url.password||url.search||url.hash)
      throw new Error('Canonical HTTPS issuer and resource are required');
    if(issuer.pathname!=='/'||issuer.href!==options.issuer||resource.href!==options.resource)
      throw new Error('Issuer must be an origin ending in /; URLs must be canonical');
    if(!options.redirectUris.length||options.redirectUris.length>20)throw new Error('Explicit client callback allowlist required');
    for(const value of options.redirectUris){const url=new URL(value);
      if(url.protocol!=='https:'||url.username||url.password||url.hash||url.href!==value)throw new Error('Exact HTTPS callbacks required');}
    this.issuer=issuer.href;this.resource=resource.href;
    this.accessSeconds=options.accessSeconds??300;this.grantDays=options.grantDays??30;
    if(!Number.isInteger(this.accessSeconds)||this.accessSeconds<30||this.accessSeconds>900||
      !Number.isInteger(this.grantDays)||this.grantDays<1||this.grantDays>90)throw new Error('Invalid token lifetime');
    this.clientsStore={getClient:id=>store.get<OAuthClientInformationFull>('client',id),registerClient:client=>this.register(client)};
  }
  private register(client:Omit<OAuthClientInformationFull,'client_id'|'client_id_issued_at'>) {
    if(client.token_endpoint_auth_method!=='none'||client.client_secret||!client.redirect_uris.length||client.redirect_uris.length>5||
      client.redirect_uris.some(uri=>!this.options.redirectUris.includes(uri))||
      client.grant_types?.some(type=>!['authorization_code','refresh_token'].includes(type))||
      client.response_types?.some(type=>type!=='code')||
      (client.scope&&client.scope!==NAS_READ_SCOPE))throw new InvalidClientMetadataError('Only approved public MCP clients and NAS read scope are supported');
    this.store.prune();if(this.store.count('client')>=1000)throw new InvalidClientMetadataError('Client registration capacity reached');
    if(client.client_name&&client.client_name.length>100)throw new InvalidClientMetadataError('Client name is too long');
    const record:OAuthClientInformationFull={redirect_uris:client.redirect_uris,...(client.client_name?{client_name:client.client_name}:{}),client_id:randomUUID(),client_id_issued_at:Math.floor(this.store.now()/1000),
      token_endpoint_auth_method:'none',grant_types:['authorization_code','refresh_token'],response_types:['code'],scope:NAS_READ_SCOPE};
    this.store.put('client',record.client_id,record,this.store.now()+90*DAY);return record;
  }
  private requireClient(client:OAuthClientInformationFull){
    const registered=this.store.get<OAuthClientInformationFull>('client',client.client_id);
    if(!registered||registered.token_endpoint_auth_method!=='none'||registered.redirect_uris.some(uri=>!this.options.redirectUris.includes(uri)))throw new InvalidGrantError('Unknown client');
    return registered;
  }
  /** Called after verified account/device pairing, never with an unverified browser subject. */
  registerDevice(subject:string,label:string,rootIds:string[]) {
    if(!subject||subject.length>256||!label||label.length>100||!this.validRoots(rootIds))throw new InvalidRequestError('Invalid paired device');
    if(this.store.count('device')>=10000)throw new InvalidRequestError('Device capacity reached');
    const id=randomUUID();this.store.put('device',id,{subject,label,rootIds,rootVersions:Object.fromEntries(rootIds.map(id=>[id,1])),revision:1,revoked:false} satisfies Device,this.store.now()+3650*DAY);return id;
  }
  private validRoots(ids:string[]){return ids.length<=20&&new Set(ids).size===ids.length&&ids.every(id=>/^[a-zA-Z0-9_-]{1,40}$/.test(id));}
  deviceIsActive(deviceId:string,subject:string) {
    const device=this.store.get<Device>('device',deviceId);return Boolean(device&&!device.revoked&&device.subject===subject);
  }
  setDeviceRoots(deviceId:string,subject:string,rootIds:string[]) {
    const device=this.store.get<Device>('device',deviceId);
    if(!device||device.subject!==subject||device.revoked||!this.validRoots(rootIds))throw new InvalidGrantError('Device unavailable');
    const revision=device.revision+1;
    const rootVersions=Object.fromEntries(rootIds.map(id=>[id,device.rootVersions[id]??revision]));
    this.store.put('device',deviceId,{...device,rootIds,rootVersions,revision},this.store.now()+3650*DAY);
  }
  revokeDevice(deviceId:string,subject:string) {
    const device=this.store.get<Device>('device',deviceId);
    if(!device||device.subject!==subject)throw new InvalidGrantError('Device unavailable');
    this.store.put('device',deviceId,{...device,revoked:true},this.store.now()+3650*DAY);
  }
  private pending(client:OAuthClientInformationFull,params:AuthorizationParams):Pending {
    const registered=this.requireClient(client);
    if(!registered.redirect_uris.includes(params.redirectUri))throw new InvalidRequestError('Unregistered callback');
    if(params.resource?.href!==this.resource)throw new InvalidTargetError('NAS resource must match exactly');
    const scopes=params.scopes?.length?params.scopes:[NAS_READ_SCOPE];
    if(scopes.length!==1||scopes[0]!==NAS_READ_SCOPE)throw new InvalidScopeError('Only NAS read access is supported');
    if(!/^[A-Za-z0-9_-]{43}$/.test(params.codeChallenge)||!params.state||params.state.length>1024)
      throw new InvalidRequestError('S256 PKCE and state are required');
    return {issuer:this.issuer,clientId:client.client_id,redirectUri:params.redirectUri,resource:this.resource,challenge:params.codeChallenge,state:params.state,scopes};
  }
  beginAuthorization(client:OAuthClientInformationFull,params:AuthorizationParams) {
    const request=this.pending(client,params);this.store.prune();
    if(this.store.count('pending')>=1000)throw new InvalidRequestError('Authorization capacity reached');
    const handle=fresh();this.store.put('pending',this.store.key('pending',handle),request,this.store.now()+10*60_000);return handle;
  }
  async authorize(client:OAuthClientInformationFull,params:AuthorizationParams,res:Response) {
    const handle=this.beginAuthorization(client,params);
    res.redirect(302,new URL(`connect/authorize?request=${encodeURIComponent(handle)}`,this.issuer).href);
  }
  inspectAuthorization(handle:string) {
    const pending=this.store.get<Pending>('pending',this.store.key('pending',handle));
    if(!pending||pending.issuer!==this.issuer||pending.resource!==this.resource)throw new InvalidGrantError('Authorization request expired');
    const client=this.store.get<OAuthClientInformationFull>('client',pending.clientId);
    if(!client)throw new InvalidGrantError('Client expired');
    return {clientName:client.client_name??'MCP client',scope:NAS_READ_SCOPE,resource:this.resource};
  }
  /** Gateway route must validate its own account session, origin and CSRF before calling. */
  approveAuthorization(handle:string,subject:string,deviceId:string,rootIds:string[]) {
    return this.store.transaction(()=>{
      const key=this.store.key('pending',handle),request=this.store.get<Pending>('pending',key);
      const device=this.store.get<Device>('device',deviceId);
      if(!request||request.issuer!==this.issuer||request.resource!==this.resource||!device||device.revoked||device.subject!==subject||!this.validRoots(rootIds)||!rootIds.length||
        rootIds.some(id=>!device.rootIds.includes(id)))throw new InvalidGrantError('Device and selected folders must belong to the signed-in account');
      const expires=this.store.now()+this.grantDays*DAY;
      const grantId=randomUUID();
      this.store.put('grant',grantId,{issuer:this.issuer,subject,deviceId,rootIds,rootVersions:Object.fromEntries(rootIds.map(id=>[id,device.rootVersions[id]!])),clientId:request.clientId,resource:request.resource,scopes:request.scopes,expires,revoked:false} satisfies Grant,expires);
      this.store.delete('pending',key);
      const code=fresh();this.store.put('code',this.store.key('code',code),{...request,grantId} satisfies Code,this.store.now()+60_000);
      const callback=new URL(request.redirectUri);callback.searchParams.set('code',code);callback.searchParams.set('state',request.state!);callback.searchParams.set('iss',this.issuer);
      return callback.href;
    });
  }
  denyAuthorization(handle:string) {
    return this.store.transaction(()=>{
      const key=this.store.key('pending',handle),request=this.store.get<Pending>('pending',key);
      if(!request||request.issuer!==this.issuer||request.resource!==this.resource)throw new InvalidGrantError('Authorization request expired');
      this.store.delete('pending',key);
      const callback=new URL(request.redirectUri);callback.searchParams.set('error','access_denied');callback.searchParams.set('state',request.state!);callback.searchParams.set('iss',this.issuer);return callback.href;
    });
  }
  private code(client:OAuthClientInformationFull,code:string){
    this.requireClient(client);
    const record=this.store.get<Code>('code',this.store.key('code',code));
    if(!record||record.clientId!==client.client_id||record.issuer!==this.issuer||record.resource!==this.resource)throw new InvalidGrantError('Invalid authorization code');return record;
  }
  async challengeForAuthorizationCode(client:OAuthClientInformationFull,code:string){return this.code(client,code).challenge;}
  // We validate PKCE in the same atomic transaction as consuming the code.
  readonly skipLocalPkceValidation=true;
  async exchangeAuthorizationCode(client:OAuthClientInformationFull,code:string,verifier?:string,redirectUri?:string,resource?:URL):Promise<OAuthTokens> {
    return this.store.transaction(()=>{
      const record=this.code(client,code);
      if(!verifier||!/^[A-Za-z0-9._~-]{43,128}$/.test(verifier)||redirectUri!==record.redirectUri||resource?.href!==record.resource)
        throw new InvalidGrantError('Callback, PKCE verifier and resource must match the authorization');
      const actual=createHash('sha256').update(verifier).digest('base64url');
      if(!timingSafeEqual(Buffer.from(actual),Buffer.from(record.challenge)))throw new InvalidGrantError('PKCE verification failed');
      const grant=this.requireGrant(record.grantId);
      this.store.delete('code',this.store.key('code',code));return this.issueTokens(record.grantId,grant);
    });
  }
  private requireGrant(id:string) {
    const grant=this.store.get<Grant>('grant',id),device=grant?this.store.get<Device>('device',grant.deviceId):undefined;
    if(!grant||grant.issuer!==this.issuer||grant.resource!==this.resource||grant.revoked||grant.expires<=this.store.now()||
      !this.store.get('client',grant.clientId)||!device||device.revoked||device.subject!==grant.subject||
      !grant.rootIds.some(id=>device.rootIds.includes(id)&&device.rootVersions[id]===grant.rootVersions[id]))
      throw new InvalidGrantError('Access grant is no longer active');return grant;
  }
  private issueTokens(grantId:string,grant:Grant):OAuthTokens {
    const access=fresh(),refresh=fresh(),expires=Math.min(this.store.now()+this.accessSeconds*1000,grant.expires);
    this.store.put('access',this.store.key('access',access),{grantId,clientId:grant.clientId,resource:grant.resource,expires} satisfies Token,expires);
    this.store.put('refresh',this.store.key('refresh',refresh),{grantId,clientId:grant.clientId,resource:grant.resource,expires:grant.expires,used:false} satisfies Refresh,grant.expires);
    return {access_token:access,token_type:'Bearer',expires_in:Math.floor((expires-this.store.now())/1000),refresh_token:refresh,scope:NAS_READ_SCOPE};
  }
  async exchangeRefreshToken(client:OAuthClientInformationFull,token:string,scopes?:string[],resource?:URL):Promise<OAuthTokens> {
    // Reuse detection must commit revocation even though the request returns an error.
    const result=this.store.transaction(()=>{
      this.requireClient(client);
      const key=this.store.key('refresh',token),record=this.store.get<Refresh>('refresh',key);
      if(!record||record.clientId!==client.client_id||resource?.href!==record.resource||
        (scopes&&(scopes.length!==1||scopes[0]!==NAS_READ_SCOPE)))throw new InvalidGrantError('Invalid refresh request');
      const grant=this.requireGrant(record.grantId);
      if(record.used){this.store.put('grant',record.grantId,{...grant,revoked:true},grant.expires);return null;}
      this.store.put('refresh',key,{...record,used:true},record.expires);
      return this.issueTokens(record.grantId,grant);
    });
    if(!result)throw new InvalidGrantError('Refresh token reuse detected; reconnect your account');return result;
  }
  async verifyAccessToken(token:string):Promise<AuthInfo> {
    if(!/^[A-Za-z0-9_-]{43}$/.test(token))throw new InvalidTokenError('Invalid access token');
    const record=this.store.get<Token>('access',this.store.key('access',token));
    if(!record||record.resource!==this.resource)throw new InvalidTokenError('Invalid access token');
    let grant:Grant;
    try{grant=this.requireGrant(record.grantId);}catch{throw new InvalidTokenError('Access has been revoked');}
    const device=this.store.get<Device>('device',grant.deviceId)!;
    const roots=grant.rootIds.filter(id=>device.rootIds.includes(id)&&device.rootVersions[id]===grant.rootVersions[id]);
    if(!roots.length)throw new InvalidTokenError('Folder access has been removed');
    return {token,clientId:record.clientId,scopes:grant.scopes,expiresAt:Math.floor(record.expires/1000),resource:new URL(record.resource),
      extra:{subject:grant.subject,deviceId:grant.deviceId,rootIds:roots,grantId:record.grantId}};
  }
  async revokeToken(client:OAuthClientInformationFull,request:OAuthTokenRevocationRequest) {
    this.requireClient(client);
    this.store.transaction(()=>{
      for(const kind of ['access','refresh']){
        const record=this.store.get<Token>(kind,this.store.key(kind,request.token));
        if(!record||record.clientId!==client.client_id)continue;
        const grant=this.store.get<Grant>('grant',record.grantId);
        if(grant)this.store.put('grant',record.grantId,{...grant,revoked:true},grant.expires);
      }
    });
  }
  authenticator():Authenticator {
    const resource=new URL(this.resource);
    const metadata=new URL(`/.well-known/oauth-protected-resource${resource.pathname==='/'?'':resource.pathname}`,resource).href;
    return {mode:'oauth',challenge:`Bearer resource_metadata="${metadata}", scope="${NAS_READ_SCOPE}"`,
      resourceMetadata:{resource:this.resource,authorization_servers:[this.issuer],scopes_supported:[NAS_READ_SCOPE]},
      authenticate:async token=>{
        try{const auth=await this.verifyAccessToken(token);return {subject:String(auth.extra!.subject),scopes:auth.scopes,rootIds:auth.extra!.rootIds as string[],deviceId:String(auth.extra!.deviceId)};}
        catch{return null;}
      }};
  }
}
