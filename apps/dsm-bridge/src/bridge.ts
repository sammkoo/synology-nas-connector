import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { randomBytes } from 'node:crypto';
import { loadConfig } from '../../../packages/core/src/index.js';
import { ManagementError, readManagementSecret, signBridgeRequest } from '../../../packages/management/src/index.js';
import path from 'node:path';

const execute = promisify(execFile);
type DsmExecutor = (filename:string,args:string[],options:{env?:NodeJS.ProcessEnv;timeout:number;maxBuffer:number}) => Promise<{stdout:string}>;
async function stage<T>(code:string,operation:()=>Promise<T>):Promise<T> {
  try {return await operation();} catch (error) {
    if (error instanceof ManagementError) throw error;
    // Child errors can include the inherited DSM cookie and stdout/stderr.
    // Return only a fixed stage code, never the raw error or its cause.
    throw new ManagementError(code,503);
  }
}
export function requireAdministrator(username: string, groups: string) {
  if (!/^[A-Za-z0-9_.@\\-]{1,128}$/.test(username) || username.startsWith('-') ||
      !groups.trim().split(/\s+/).includes('administrators')) throw new ManagementError('DSM_ADMIN_REQUIRED',403);
  return username;
}
export function bridgeAction(env: NodeJS.ProcessEnv) {
  const query = new URLSearchParams(env.QUERY_STRING ?? '');
  const action = query.get('action');
  if ([...query.keys()].length !== 1 || !['bootstrap','roots','preview','pair-begin','pair-status','pair-confirm','pair-cancel','pair-disconnect'].includes(action ?? ''))
    throw new ManagementError('UNKNOWN_ACTION',404);
  const method = action === 'bootstrap' ? 'GET' : 'POST';
  if (env.REQUEST_METHOD !== method) throw new ManagementError('METHOD_NOT_ALLOWED',405);
  if (method === 'POST') {
    // Own CSRF enforcement does not depend on optional DSM security settings.
    const host = env.HTTP_HOST ?? '';
    if (!host || /[\s/@\\]/.test(host) || env.HTTP_ORIGIN !== `https://${host}`)
      throw new ManagementError('ORIGIN_REQUIRED',403);
    if (env.CONTENT_TYPE?.split(';')[0] !== 'application/json') throw new ManagementError('JSON_REQUIRED',415);
  }
  return {method,endpoint:`/manage/${action}`};
}
export async function forwardManagement(env: NodeJS.ProcessEnv, body: Buffer, configPath: string,run:DsmExecutor=execute) {
  const {method,endpoint} = bridgeAction(env);
  if (body.length > 16384) throw new ManagementError('REQUEST_TOO_LARGE',413);
  if (!env.HTTP_COOKIE || !env.REMOTE_ADDR) throw new ManagementError('DSM_LOGIN_REQUIRED',401);
  // Official DSM authentication executable reads the existing CGI session cookie.
  // No passwords, cookies or DSM tokens are sent to the Node management service.
  const auth = await stage('DSM_AUTH_EXECUTION_FAILED',()=>run('/usr/syno/synoman/webman/modules/authenticate.cgi',[],{env,timeout:3000,maxBuffer:2048}));
  const user = auth.stdout.trim();
  if (!/^[A-Za-z0-9_.@\\-]{1,128}$/.test(user) || user.startsWith('-')) throw new ManagementError('DSM_LOGIN_REQUIRED',401);
  const groups = await stage('DSM_GROUP_LOOKUP_FAILED',()=>run('/usr/bin/id',['-Gn',user],{timeout:3000,maxBuffer:4096}));
  requireAdministrator(user,groups.stdout);
  const config = await stage('DSM_CONFIG_READ_FAILED',()=>loadConfig(configPath));
  if (!config.management || config.http.host !== '127.0.0.1') throw new ManagementError('MANAGEMENT_UNAVAILABLE',503);
  const secretPath = path.resolve(path.dirname(configPath),config.management.secretFile);
  const secret = await stage('DSM_SIGNING_KEY_READ_FAILED',()=>readManagementSecret(secretPath));
  const signed = {method,path:endpoint,user,timestamp:String(Date.now()),nonce:randomBytes(32).toString('hex'),
    csrf:env.HTTP_X_NAS_CSRF ?? '',body};
  const response = await stage('DSM_LOCAL_SERVICE_UNAVAILABLE',()=>fetch(`http://127.0.0.1:${config.http.port}${endpoint}`,{method,
    signal:AbortSignal.timeout(7000),redirect:'error',headers:{'Content-Type':'application/json',
      'x-nas-user':user,'x-nas-timestamp':signed.timestamp,'x-nas-nonce':signed.nonce,'x-nas-csrf':signed.csrf,
      'x-nas-signature':signBridgeRequest(secret,signed)},...(method==='POST'?{body:new Uint8Array(body)}: {})}));
  const reader = response.body?.getReader();
  if (!reader) throw new ManagementError('SERVICE_UNAVAILABLE',503);
  const chunks: Uint8Array[] = []; let size = 0;
  try {for (;;) {
    const next = await reader.read(); if (next.done) break;
    size += next.value.length;
    if (size > 262144) throw new ManagementError('RESPONSE_TOO_LARGE',503);
    chunks.push(next.value);
  }} finally {await reader.cancel();}
  const result = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  return {status:response.status,body:result};
}
