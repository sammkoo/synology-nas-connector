import { z } from 'zod';
import { operationSchema,type ReadOnlyOperation,NasError } from '../../core/src/index.js';
export const RELAY_PROTOCOL='nas-relay.v1',MAX_RELAY_BYTES=4*1024*1024;
export const rootsSchema=z.array(z.object({id:z.string().regex(/^[A-Za-z0-9_-]{1,40}$/),label:z.string().min(1).max(100)}).strict()).max(20)
  .refine(roots=>new Set(roots.map(r=>r.id)).size===roots.length);
export type RelayRoots=z.infer<typeof rootsSchema>;
const id=z.string().uuid(),secret=z.string().regex(/^[A-Za-z0-9_-]{43}$/);
export const challengeSchema=z.object({type:z.literal('challenge'),issuer:z.string().url(),id,nonce:secret}).strict();
export type RelayChallenge=z.infer<typeof challengeSchema>;
export function relayProofMessage(challenge:RelayChallenge,publicKey:string,roots:RelayRoots) {
  const canonical=[...roots].sort((a,b)=>a.id<b.id?-1:a.id>b.id?1:0).map(r=>[r.id,r.label]);
  return Buffer.from(JSON.stringify(['nas-relay-v1',challenge.issuer,challenge.id,challenge.nonce,publicKey,canonical]));
}
export const agentMessageSchema=z.discriminatedUnion('type',[
  z.object({type:z.literal('hello'),publicKey:z.string().regex(/^[A-Za-z0-9_-]{59}$/)}).strict(),
  z.object({type:z.literal('proof'),roots:rootsSchema,signature:z.string().regex(/^[A-Za-z0-9_-]{86}$/)}).strict(),
  z.object({type:z.literal('policy'),roots:rootsSchema}).strict(),
  z.object({type:z.literal('result'),id,value:z.unknown()}).strict(),
  z.object({type:z.literal('error'),id,code:z.enum(['ROOT_DENIED','PATH_DENIED','NOT_FOUND_OR_DENIED','UNSUPPORTED_FILE','UNSUPPORTED_TEXT_FORMAT','FILE_TOO_LARGE','INVALID_UTF8','BINARY_CONTENT','INVALID_RANGE','INVALID_LIMIT','INVALID_OFFSET','INVALID_QUERY','CONFIGURATION_CHANGED','CANCELLED','BUSY','RESULT_TOO_LARGE','OPERATION_FAILED','RELAY_TIMEOUT'])}).strict()
]);
export const gatewayMessageSchema=z.discriminatedUnion('type',[
  challengeSchema,
  z.object({type:z.literal('ready'),id,deviceId:id}).strict(),
  z.object({type:z.literal('call'),id,rootIds:z.array(z.string().regex(/^[A-Za-z0-9_-]{1,40}$/)).max(20),operation:operationSchema}).strict(),
  z.object({type:z.literal('cancel'),id}).strict()
]);
export function encodeRelay(value:unknown) {
  const encoded=JSON.stringify(value);if(Buffer.byteLength(encoded)>MAX_RELAY_BYTES)throw new NasError('RESULT_TOO_LARGE');return encoded;
}
const relative=z.string().max(32768).refine(v=>!v.startsWith('/')&&!v.includes('\\')&&!/[\x00-\x1f\x7f]/.test(v)&&v.split('/').every(s=>s!=='.'&&s!=='..'));
const metadata=z.object({rootId:z.string(),path:relative,type:z.enum(['file','directory']),size:z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),modifiedAt:z.string().datetime(),readableText:z.boolean()}).strict();
const entry=metadata.extend({name:z.string().min(1).max(1024)}).strict();
const results={
  list_roots:rootsSchema,
  list_directory:z.object({entries:z.array(entry).max(200),offset:z.number().int().nonnegative(),nextOffset:z.number().int().nonnegative().nullable(),scanTruncated:z.boolean(),truncated:z.boolean()}).strict(),
  search_files:z.object({entries:z.array(entry).max(200),truncated:z.boolean(),skippedDirectories:z.number().int().nonnegative()}).strict(),
  get_metadata:metadata,
  read_text:z.object({rootId:z.string(),path:relative,text:z.string().refine(v=>Buffer.byteLength(v)<=2_000_000),startLine:z.number().int().positive(),totalLines:z.number().int().nonnegative(),truncated:z.boolean(),trust:z.literal('untrusted-document-content')}).strict()
};
export function validateRelayResult(operation:ReadOnlyOperation,value:unknown,rootIds:readonly string[]) {
  const parsed=results[operation.name].safeParse(value);if(!parsed.success)throw new NasError('INVALID_RELAY_RESPONSE');
  const data=parsed.data;
  const entries=Array.isArray(data)?data:'entries' in data?data.entries:[data];
  for(const item of entries){
    const root='id' in item?item.id:item.rootId;
    if(!rootIds.includes(root)||(operation.name!=='list_roots'&&root!==operation.args.rootId))throw new NasError('INVALID_RELAY_RESPONSE');
  }
  if((operation.name==='get_metadata'||operation.name==='read_text')&&'path' in data&&data.path!==operation.args.path)throw new NasError('INVALID_RELAY_RESPONSE');
  return data;
}
