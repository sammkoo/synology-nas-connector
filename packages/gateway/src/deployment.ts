import { z } from 'zod';
import { constants } from 'node:fs';
import { lstat,mkdir,open,realpath } from 'node:fs/promises';
import path from 'node:path';
import { randomBytes,createHash,timingSafeEqual } from 'node:crypto';
import { isIP } from 'node:net';
import { GatewayStore } from './store.js';

const httpsOrigin=z.string().max(2048).refine(value=>{
  try{const u=new URL(value);return u.protocol==='https:'&&u.href===value&&u.pathname==='/'&&!u.username&&!u.password&&!u.search&&!u.hash;}catch{return false;}
},'A canonical HTTPS origin ending in / is required');
const callback=z.string().max(2048).refine(value=>{
  try{const u=new URL(value);return u.protocol==='https:'&&u.href===value&&!u.username&&!u.password&&!u.hash;}catch{return false;}
},'An exact HTTPS callback is required');
const filename=z.string().min(1).max(4096);
const listen={host:z.string().refine(v=>Boolean(isIP(v))).default('127.0.0.1'),port:z.number().int().min(1024).max(65535).default(8788)};
const transport=z.discriminatedUnion('mode',[
  z.object({mode:z.literal('https'),...listen,certificateFile:filename,privateKeyFile:filename}).strict(),
  z.object({mode:z.literal('proxy'),...listen,trustedProxyAddresses:z.array(z.string().refine(v=>['127.0.0.1','::1','::ffff:127.0.0.1'].includes(v))).min(1).max(3)}).strict()
]);
export const gatewayDeploymentSchema=z.object({
  issuer:httpsOrigin,redirectUris:z.array(callback).min(1).max(20),dataDirectory:filename,transport,
  limits:z.object({maxConnections:z.number().int().min(2).max(512).default(128),databaseMaxBytes:z.number().int().min(16*1024*1024).max(1024*1024*1024).default(256*1024*1024)}).strict().default({}),
}).strict().superRefine((v,ctx)=>{
  if(new Set(v.redirectUris).size!==v.redirectUris.length)ctx.addIssue({code:z.ZodIssueCode.custom,message:'Duplicate callbacks'});
  if(v.transport.mode==='proxy'&&(!['127.0.0.1','::1'].includes(v.transport.host)||!v.transport.trustedProxyAddresses.includes(v.transport.host)))
    ctx.addIssue({code:z.ZodIssueCode.custom,message:'A proxy listener must bind and trust its exact loopback address'});
});
export type GatewayDeploymentConfig=z.infer<typeof gatewayDeploymentSchema>;

export async function readDeploymentFile(file:string,maxBytes:number,privateFile=true) {
  const handle=await open(file,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
  try{
    const stat=await handle.stat();
    if(!stat.isFile()||stat.size>maxBytes||(privateFile&&(stat.uid!==process.getuid?.()||(stat.mode&0o077))))throw new Error('Unsafe gateway configuration or key');
    const buffer=Buffer.alloc(maxBytes+1);let size=0;
    while(size<buffer.length){const {bytesRead}=await handle.read(buffer,size,buffer.length-size,size);if(!bytesRead)break;size+=bytesRead;}
    if(size>maxBytes)throw new Error('Gateway file exceeds its size bound');return buffer.subarray(0,size);
  }finally{await handle.close();}
}
export async function privateGatewayDirectory(directory:string) {
  await mkdir(directory,{recursive:true,mode:0o700});const stat=await lstat(directory);
  if(!stat.isDirectory()||stat.isSymbolicLink()||stat.uid!==process.getuid?.()||(stat.mode&0o077))throw new Error('Unsafe gateway directory');
  return realpath(directory);
}
async function writeNewPrivate(file:string,value:Buffer|string) {
  const handle=await open(file,constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW,0o600);
  try{await handle.writeFile(value);await handle.sync();}finally{await handle.close();}
}
const keyDigest=(key:Buffer)=>createHash('sha256').update('nas-gateway-key-v1\0').update(key).digest('hex');
const identitySchema=z.object({version:z.literal(1),issuer:httpsOrigin,keyDigest:z.string().regex(/^[a-f0-9]{64}$/)}).strict();

/** Explicit first-install operation. Never recreate a missing key during startup. */
export async function initializeGateway(configPath:string,issuer:string,redirectUris:string[]) {
  const config=gatewayDeploymentSchema.parse({issuer,redirectUris,dataDirectory:'state',transport:{mode:'https',certificateFile:'tls/cert.pem',privateKeyFile:'tls/key.pem'}});
  const directory=await privateGatewayDirectory(path.dirname(path.resolve(configPath))),state=path.join(directory,'state');
  for(const file of [configPath,state]){
    const exists=await lstat(file).then(()=>true,e=>{if(e.code==='ENOENT')return false;throw e;});if(exists)throw new Error('Existing gateway installation; refusing to overwrite');
  }
  await privateGatewayDirectory(state);await privateGatewayDirectory(path.join(directory,'tls'));
  const key=randomBytes(32);
  try{
    await writeNewPrivate(path.join(state,'auth.key'),key);
    await writeNewPrivate(path.join(state,'installation.json'),JSON.stringify({version:1,issuer,keyDigest:keyDigest(key)})+'\n');
    const database=await GatewayStore.open(state,key,Date.now,{exclusive:true,maxDatabaseBytes:config.limits.databaseMaxBytes});
    try{database.put('installation','gateway',{version:1,issuer,keyCheck:database.key('installation','gateway-deployment-v1')},Number.MAX_SAFE_INTEGER);}finally{database.close();}
    await writeNewPrivate(path.resolve(configPath),JSON.stringify(config,null,2)+'\n');
    for(const dir of [state,directory]){const handle=await open(dir,constants.O_RDONLY);try{await handle.sync();}finally{await handle.close();}}
  }finally{key.fill(0);}
}
export async function loadGatewayDeployment(configPath:string) {
  const absolute=path.resolve(configPath),config=gatewayDeploymentSchema.parse(JSON.parse((await readDeploymentFile(absolute,16384)).toString('utf8')));
  const base=path.dirname(absolute);config.dataDirectory=path.resolve(base,config.dataDirectory);
  if(config.transport.mode==='https'){
    config.transport.certificateFile=path.resolve(base,config.transport.certificateFile);
    config.transport.privateKeyFile=path.resolve(base,config.transport.privateKeyFile);
  }
  return config;
}
export async function readGatewayKey(config:GatewayDeploymentConfig) {
  const directory=await privateGatewayDirectory(config.dataDirectory);
  const identity=identitySchema.parse(JSON.parse((await readDeploymentFile(path.join(directory,'installation.json'),4096)).toString('utf8')));
  const key=await readDeploymentFile(path.join(directory,'auth.key'),32);
  if(key.length!==32||identity.issuer!==config.issuer||!timingSafeEqual(Buffer.from(identity.keyDigest,'hex'),Buffer.from(keyDigest(key),'hex'))){key.fill(0);throw new Error('Gateway issuer or key changed; restore consistent installation state');}
  return key;
}
