import { constants } from 'node:fs';
import { open } from 'node:fs/promises';
import { z } from 'zod';
import { NasError } from './errors.js';

export const driveConfigSchema=z.object({baseUrl:z.string().url(),sessionFile:z.string().min(1),linkOrigins:z.array(z.string().url()).min(1).max(5)}).strict();
export type DriveConfig=z.infer<typeof driveConfigSchema>;
const metadataSchema=z.object({file_id:z.string().regex(/^\d{1,30}$/),dsm_path:z.string(),display_path:z.string(),type:z.string(),removed:z.boolean(),capabilities:z.object({can_share:z.boolean()}).passthrough()}).passthrough();

/** Independently implemented REST client. No vendor SDK or copied documentation is bundled. */
export class SynologyDrive {
  private readonly origin:string;
  constructor(private readonly config:DriveConfig) {
    const base=new URL(config.baseUrl);
    if(base.protocol!=='https:'||base.username||base.password||base.search||base.hash||base.pathname!=='/')throw new NasError('DRIVE_CONFIGURATION_INVALID');
    this.origin=base.origin;
    for(const value of config.linkOrigins){const url=new URL(value);if(url.protocol!=='https:'||url.origin!==value)throw new NasError('DRIVE_CONFIGURATION_INVALID');}
  }
  static async login(baseUrl:string,account:string,passwd:string):Promise<string> {
    // Validate the destination before sending credentials. Passwords are never persisted.
    const config={baseUrl,sessionFile:'unused',linkOrigins:[new URL(baseUrl).origin]};
    new SynologyDrive(config);
    if(!account||account.length>128||!passwd||passwd.length>1024)throw new NasError('DRIVE_LOGIN_FAILED');
    try {
      const response=await fetch(new URL('/api/SynologyDrive/default/v1/login',baseUrl),{method:'POST',redirect:'error',signal:AbortSignal.timeout(5000),
        headers:{Accept:'application/json','Content-Type':'application/json'},body:JSON.stringify({format:'sid',account,passwd})});
      if(!response.ok)throw new Error();
      const reader=response.body?.getReader();if(!reader)throw new Error();
      const chunks:Uint8Array[]=[];let size=0;
      try {while(true){const value=await reader.read();if(value.done)break;size+=value.value.byteLength;if(size>4096){await reader.cancel();throw new Error();}chunks.push(value.value);}}
      finally {reader.releaseLock();}
      const parsed=z.object({success:z.literal(true),data:z.object({sid:z.string().regex(/^[A-Za-z0-9._~+\/=-]{1,2048}$/)}).passthrough()}).passthrough().parse(JSON.parse(Buffer.concat(chunks).toString('utf8')));
      return parsed.data.sid;
    } catch {throw new NasError('DRIVE_LOGIN_FAILED');}
  }
  async checkFolder(drivePath:string,physicalPath:string) {
    const sid=await this.session();
    const parsed=metadataSchema.safeParse(await this.request('files','GET',sid,undefined,undefined,drivePath));
    if(!parsed.success)throw new NasError('DRIVE_RESPONSE_INVALID');
    if(parsed.data.removed||parsed.data.type!=='dir'||!parsed.data.capabilities.can_share||parsed.data.dsm_path!==physicalPath||parsed.data.display_path!==drivePath)throw new NasError('DRIVE_PATH_MISMATCH');
  }
  private async session() {
    let handle;
    try {
      handle=await open(this.config.sessionFile,constants.O_RDONLY|constants.O_NOFOLLOW);
      const stat=await handle.stat();
      if(!stat.isFile()||stat.size>4096||stat.mode&0o077||stat.uid!==process.getuid?.())throw new Error();
      const sid=(await handle.readFile('utf8')).trim();
      if(!/^[A-Za-z0-9._~+\/=-]{1,2048}$/.test(sid))throw new Error();
      return sid;
    } catch {throw new NasError('DRIVE_SESSION_REQUIRED');} finally {await handle?.close();}
  }
  private async request(endpoint:string,method:'GET'|'POST',sid:string,signal?:AbortSignal,body?:unknown,query?:string) {
    const url=new URL(`/api/SynologyDrive/default/v1/${endpoint}`,this.origin);
    if(query!==undefined)url.searchParams.set('path',query);
    let response:Response;
    try {response=await fetch(url,{method,redirect:'error',signal:signal?AbortSignal.any([signal,AbortSignal.timeout(5000)]):AbortSignal.timeout(5000),
      headers:{Accept:'application/json',Cookie:`id=${sid}`,...(body?{'Content-Type':'application/json'}:{})},...(body?{body:JSON.stringify(body)}:{})});}
    catch {throw new NasError(method==='POST'?'WRITE_RESULT_UNKNOWN':'DRIVE_UNAVAILABLE');}
    if(!response.ok){await response.body?.cancel();throw new NasError(response.status===401||response.status===403?'DRIVE_SESSION_REQUIRED':method==='POST'?'WRITE_RESULT_UNKNOWN':'DRIVE_UNAVAILABLE');}
    // The response is bounded before parsing; never return cookies, paths or raw API errors.
    const reader=response.body?.getReader();if(!reader)throw new NasError(method==='POST'?'WRITE_RESULT_UNKNOWN':'DRIVE_RESPONSE_INVALID');
    const chunks:Uint8Array[]=[];let size=0;
    try {while(true){const result=await reader.read();if(result.done)break;size+=result.value.byteLength;
      if(size>65536){await reader.cancel();throw new Error();}chunks.push(result.value);}
      const data=JSON.parse(Buffer.concat(chunks).toString('utf8')) as {success?:unknown;data?:unknown};
      if(data.success!==true)throw new NasError('DRIVE_REQUEST_DENIED');return data.data;
    } catch(error){if(error instanceof NasError)throw error;throw new NasError(method==='POST'?'WRITE_RESULT_UNKNOWN':'DRIVE_RESPONSE_INVALID');}
    finally {reader.releaseLock();}
  }
  async createLink(drivePath:string,physicalPath:string,signal?:AbortSignal,beforeCommit?:()=>Promise<void>) {
    const sid=await this.session();
    const parsed=metadataSchema.safeParse(await this.request('files','GET',sid,signal,undefined,drivePath));
    if(!parsed.success)throw new NasError('DRIVE_RESPONSE_INVALID');
    const file=parsed.data;
    if(file.removed||file.type!=='file'||!file.capabilities.can_share||file.dsm_path!==physicalPath||file.display_path!==drivePath)throw new NasError('DRIVE_PATH_MISMATCH');
    await beforeCommit?.();if(signal?.aborted)throw new NasError('CANCELLED');
    const value=await this.request('sharing/create-link','POST',sid,signal,{path:`id:${file.file_id}`});
    const result=z.object({url:z.string().url()}).passthrough().safeParse(value);
    if(!result.success)throw new NasError('WRITE_RESULT_UNKNOWN');
    const url=new URL(result.data.url);
    if(url.protocol!=='https:'||url.username||url.password||url.hash||url.search||!/^\/d\/f\/[A-Za-z0-9_-]{16,128}$/.test(url.pathname)||!this.config.linkOrigins.includes(url.origin))throw new NasError('DRIVE_LINK_URL_DENIED');
    return {url:url.href,provider:'synology-drive' as const,access:'existing-permissions' as const};
  }
}
