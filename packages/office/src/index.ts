import {constants} from 'node:fs';
import {open} from 'node:fs/promises';
import {z} from 'zod';

export class OfficeError extends Error {
  constructor(public readonly code:string){super(code);}
}
const httpsOrigin=z.string().url().refine(value=>{
  try {const url=new URL(value);return url.protocol==='https:'&&!url.username&&!url.password&&!url.search&&!url.hash&&url.pathname==='/';}catch{return false;}
},'A canonical HTTPS origin is required');
const alias=z.string().regex(/^[A-Za-z0-9_-]{1,40}$/);
export const officeConfigSchema=z.object({
  apiOrigin:httpsOrigin,
  tokenFile:z.string().min(1),
  spreadsheets:z.array(z.object({
    alias,label:z.string().min(1).max(100),
    spreadsheetId:z.string().regex(/^[A-Za-z0-9]{16,128}$/),
    allowEdit:z.boolean().default(false)
  }).strict()).max(20).default([])
}).strict().superRefine((value,ctx)=>{
  if(new Set(value.spreadsheets.map(s=>s.alias)).size!==value.spreadsheets.length||new Set(value.spreadsheets.map(s=>s.spreadsheetId)).size!==value.spreadsheets.length)
    ctx.addIssue({code:'custom',message:'Spreadsheet bindings must be unique'});
});
export type OfficeConfig=z.infer<typeof officeConfigSchema>;
export type Cell=string|number|boolean;
export type CellRange={sheet:string;firstRow:number;firstColumn:number;rows:number;columns:number};

/** An explicit bounded rectangle, never an entire sheet, named range or expression. */
export function parseCellRange(input:string):CellRange {
  if(input.length>200)throw new OfficeError('OFFICE_RANGE_INVALID');
  const match=/^(?:'((?:[^'\x00-\x1f]|'')+)'|([A-Za-z_][A-Za-z0-9_ ]{0,99}))!([A-Z]{1,3})([1-9]\d{0,5})(?::([A-Z]{1,3})([1-9]\d{0,5}))?$/.exec(input);
  if(!match)throw new OfficeError('OFFICE_RANGE_INVALID');
  const column=(letters:string)=>[...letters].reduce((value,char)=>value*26+char.charCodeAt(0)-64,0);
  const firstColumn=column(match[3]!),lastColumn=column(match[5]??match[3]!);
  const firstRow=Number(match[4]),lastRow=Number(match[6]??match[4]);
  const rows=lastRow-firstRow+1,columns=lastColumn-firstColumn+1;
  const sheet=(match[1]?.replace(/''/g,"'")??match[2])!;
  if(rows<1||columns<1||rows*columns>1000||lastColumn>16384||lastRow>100000||sheet.length>100||/[\x00-\x1f\x7f\[\]\\/:*?]/.test(sheet))throw new OfficeError('OFFICE_RANGE_INVALID');
  return {sheet,firstRow,firstColumn,rows,columns};
}
const primitive=z.union([z.string().max(16384),z.number().finite(),z.boolean()]);
const richText=z.object({t:z.literal('r'),v:z.array(z.object({tx:z.string().max(16384)}).passthrough()).max(100)}).passthrough();
const valuesSchema=z.object({range:z.string().max(200),majorDimension:z.enum(['ROWS','COLUMNS']),values:z.array(z.array(z.union([primitive,richText])).max(1000)).max(1000)}).strict();
const metadataSchema=z.object({id:z.string(),properties:z.object({title:z.string().max(1000),locale:z.string().max(100)}).passthrough(),
  sheets:z.array(z.object({properties:z.object({title:z.string().max(100),sheetId:z.string().max(100),index:z.number().finite(),hidden:z.boolean()}).passthrough(),
    rowCount:z.number().int().nonnegative(),colCount:z.number().int().nonnegative()}).passthrough()).max(200)}).passthrough();

/** Independently implemented documented Spreadsheet 3.4.1 client. No vendor code is bundled. */
export class SynologySpreadsheet {
  private readonly config:OfficeConfig;
  constructor(input:OfficeConfig){
    const parsed=officeConfigSchema.safeParse(input);
    if(!parsed.success)throw new OfficeError('OFFICE_CONFIGURATION_INVALID');
    this.config=parsed.data;
  }
  /** NAS credentials go to this explicitly trusted API proxy; never expose this as an MCP tool. */
  static async authorize(apiOrigin:string,nasOrigin:string,username:string,password:string):Promise<string>{
    if(!httpsOrigin.safeParse(apiOrigin).success||!httpsOrigin.safeParse(nasOrigin).success||!username||username.length>128||!password||password.length>1024)
      throw new OfficeError('OFFICE_LOGIN_FAILED');
    try {
      const response=await fetch(new URL('/spreadsheets/authorize',apiOrigin),{method:'POST',redirect:'error',signal:AbortSignal.timeout(5000),
        headers:{Accept:'application/json','Content-Type':'application/json'},body:JSON.stringify({username,password,host:new URL(nasOrigin).host,protocol:'https'})});
      if(!response.ok){await response.body?.cancel();throw new Error();}
      const reader=response.body?.getReader();if(!reader)throw new Error();
      const chunks:Uint8Array[]=[];let size=0;
      try{while(true){const chunk=await reader.read();if(chunk.done)break;size+=chunk.value.byteLength;if(size>8192){await reader.cancel();throw new Error();}chunks.push(chunk.value);}}
      finally{reader.releaseLock();}
      return z.object({token:z.string().regex(/^[A-Za-z0-9._~-]{1,4096}$/)}).strict().parse(JSON.parse(Buffer.concat(chunks).toString('utf8'))).token;
    }catch{throw new OfficeError('OFFICE_LOGIN_FAILED');}
  }
  list(){return this.config.spreadsheets.map(({alias,label,allowEdit})=>({alias,label,allowEdit}));}
  private binding(name:string){
    const binding=this.config.spreadsheets.find(item=>item.alias===name);
    if(!binding)throw new OfficeError('OFFICE_DOCUMENT_DENIED');return binding;
  }
  private async token(){
    let handle;
    try {
      handle=await open(this.config.tokenFile,constants.O_RDONLY|constants.O_NOFOLLOW);
      const stat=await handle.stat();
      if(!stat.isFile()||stat.uid!==process.getuid?.()||stat.mode&0o077||stat.size>4096)throw new Error();
      const value=(await handle.readFile('utf8')).trim();
      if(!/^[A-Za-z0-9._~-]{1,4096}$/.test(value))throw new Error();return value;
    }catch{throw new OfficeError('OFFICE_SESSION_REQUIRED');}finally{await handle?.close();}
  }
  private async request(route:string,method:'GET'|'PUT',signal?:AbortSignal,body?:unknown){
    const token=await this.token();
    let response;
    try {response=await fetch(new URL(route,this.config.apiOrigin),{method,redirect:'error',signal:signal?AbortSignal.any([signal,AbortSignal.timeout(5000)]):AbortSignal.timeout(5000),
      headers:{Accept:'application/json',Authorization:`Bearer ${token}`,...(body?{'Content-Type':'application/json'}:{})},...(body?{body:JSON.stringify(body)}:{})});}
    catch{throw new OfficeError(method==='PUT'?'WRITE_RESULT_UNKNOWN':'OFFICE_UNAVAILABLE');}
    if(!response.ok){await response.body?.cancel();throw new OfficeError(response.status===401||response.status===403?'OFFICE_SESSION_REQUIRED':method==='PUT'?'WRITE_RESULT_UNKNOWN':'OFFICE_UNAVAILABLE');}
    const reader=response.body?.getReader();if(!reader)throw new OfficeError(method==='PUT'?'WRITE_RESULT_UNKNOWN':'OFFICE_RESPONSE_INVALID');
    const chunks:Uint8Array[]=[];let size=0;
    try {while(true){const chunk=await reader.read();if(chunk.done)break;size+=chunk.value.byteLength;if(size>262144){await reader.cancel();throw new Error();}chunks.push(chunk.value);}
      return JSON.parse(Buffer.concat(chunks).toString('utf8')) as unknown;
    }catch{throw new OfficeError(method==='PUT'?'WRITE_RESULT_UNKNOWN':'OFFICE_RESPONSE_INVALID');}finally{reader.releaseLock();}
  }
  async metadata(name:string,signal?:AbortSignal){
    const binding=this.binding(name);
    const result=metadataSchema.safeParse(await this.request(`/spreadsheets/${binding.spreadsheetId}`,'GET',signal));
    if(!result.success||result.data.id!==binding.spreadsheetId)throw new OfficeError('OFFICE_RESPONSE_INVALID');
    return {alias:name,title:result.data.properties.title,locale:result.data.properties.locale,sheets:result.data.sheets.map(sheet=>({title:sheet.properties.title,index:sheet.properties.index,hidden:sheet.properties.hidden,rows:sheet.rowCount,columns:sheet.colCount})),trust:'untrusted-document-data' as const};
  }
  private parseValues(value:unknown,range:string){
    const expected=parseCellRange(range),result=valuesSchema.safeParse(value);
    if(!result.success)throw new OfficeError('OFFICE_RESPONSE_INVALID');
    // Never accept a response for another sheet or outside the requested rectangle.
    let returned:CellRange;
    try{returned=parseCellRange(result.data.range);}catch{throw new OfficeError('OFFICE_RESPONSE_INVALID');}
    if(JSON.stringify(returned)!==JSON.stringify(expected))throw new OfficeError('OFFICE_RESPONSE_INVALID');
    const outer=result.data.majorDimension==='ROWS'?expected.rows:expected.columns;
    const inner=result.data.majorDimension==='ROWS'?expected.columns:expected.rows;
    if(result.data.values.length>outer||result.data.values.some(row=>row.length>inner))throw new OfficeError('OFFICE_RESPONSE_INVALID');
    return {range,majorDimension:result.data.majorDimension,values:result.data.values.map(row=>row.map(cell=>typeof cell==='object'?cell.v.map(segment=>segment.tx).join(''):cell)),trust:'untrusted-document-data' as const};
  }
  async readCells(name:string,range:string,signal?:AbortSignal){
    const binding=this.binding(name);parseCellRange(range);
    return {alias:name,...this.parseValues(await this.request(`/spreadsheets/${binding.spreadsheetId}/values/${encodeURIComponent(range)}`,'GET',signal),range)};
  }
  async writeCells(name:string,range:string,values:Cell[][],beforeCommit:()=>Promise<void>,signal?:AbortSignal){
    const binding=this.binding(name);if(!binding.allowEdit)throw new OfficeError('OFFICE_EDIT_DENIED');
    const rectangle=parseCellRange(range);
    const parsed=z.array(z.array(primitive).min(1).max(1000)).min(1).max(1000).safeParse(values);
    if(!parsed.success||parsed.data.length!==rectangle.rows||parsed.data.some(row=>row.length!==rectangle.columns)||Buffer.byteLength(JSON.stringify(values),'utf8')>32768)
      throw new OfficeError('OFFICE_VALUES_INVALID');
    // Formula semantics/escaping are unverified; do not execute caller-supplied expressions.
    if(parsed.data.some(row=>row.some(cell=>typeof cell==='string'&&(/^\s*[=+@]/.test(cell)||/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(cell)))))throw new OfficeError('OFFICE_FORMULA_UNSUPPORTED');
    if(typeof beforeCommit!=='function')throw new OfficeError('OFFICE_COMMIT_REQUIRED');
    await beforeCommit();if(signal?.aborted)throw new OfficeError('CANCELLED');
    const result=await this.request(`/spreadsheets/${binding.spreadsheetId}/values/${encodeURIComponent(range)}`,'PUT',signal,{values:parsed.data});
    try{
      this.parseValues(result,range);
      const readback=await this.readCells(name,range,signal);
      const rows=readback.majorDimension==='ROWS'?readback.values:Array.from({length:rectangle.rows},(_,row)=>Array.from({length:rectangle.columns},(_,column)=>readback.values[column]?.[row]));
      if(JSON.stringify(rows)!==JSON.stringify(parsed.data))throw new Error();
      return {...readback,updated:true as const,verification:'readback-matched' as const,concurrency:'no-atomic-revision-check' as const};
    }
    catch{throw new OfficeError('WRITE_RESULT_UNKNOWN');}
  }
}
