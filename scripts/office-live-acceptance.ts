/** Manual acceptance against ONE disposable native spreadsheet; never use production documents. */
import {mkdtemp,writeFile,rm} from 'node:fs/promises';
import path from 'node:path';
import {tmpdir} from 'node:os';
import {emitKeypressEvents} from 'node:readline';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StdioClientTransport} from '@modelcontextprotocol/sdk/client/stdio.js';
import {OfficeError,SynologySpreadsheet,officeConfigSchema} from '../packages/office/src/index.js';

export function hiddenPassword():Promise<string>{
  if(!process.stdin.isTTY||!process.stdout.isTTY)throw new Error('INTERACTIVE_TERMINAL_REQUIRED');
  return new Promise((resolve,reject)=>{
    let value='';const raw=process.stdin.isRaw;
    // DSM reverse proxies may close an idle WebSocket while the user enters a hidden password.
    const heartbeat=setInterval(()=>process.stdout.write('\nWaiting for test account password (hidden): '),20000);
    const timeout=setTimeout(()=>{cleanup();value='';reject(new Error('PASSWORD_ENTRY_TIMEOUT'));},120000);
    const ended=()=>{cleanup();value='';reject(new Error('TERMINAL_DISCONNECTED'));};
    const cleanup=()=>{clearTimeout(timeout);clearInterval(heartbeat);process.stdin.off('keypress',input);process.stdin.off('end',ended);
      try{process.stdin.setRawMode(raw);}catch{/* A disconnected terminal cannot restore its mode. */}
      process.stdin.pause();process.stdout.write('\n');};
    const input=(text:string,key:{name?:string,ctrl?:boolean})=>{
      if(key?.ctrl&&key.name==='c'){cleanup();value='';reject(new Error('CANCELLED'));}
      else if(key?.name==='return'||key?.name==='enter'){cleanup();resolve(value);value='';}
      else if(key?.name==='backspace'){value=Array.from(value).slice(0,-1).join('');}
      else if(text&&!key?.ctrl&&!/[\x00-\x1f\x7f]/.test(text)){
        if(value.length+text.length>1024){cleanup();value='';reject(new Error('PASSWORD_TOO_LONG'));}
        else value+=text;
      }
    };
    emitKeypressEvents(process.stdin);process.stdin.setRawMode(true);process.stdin.on('keypress',input);process.stdin.once('end',ended);process.stdin.resume();
    process.stdout.write('Restricted NAS test account password (hidden): ');
  });
}

type AcceptanceOptions={bundle:string,apiOrigin:string,nasOrigin:string,username:string,spreadsheetId:string,
  passwordPrompt:()=>Promise<string>,report:(value:string)=>void};

export async function officeAcceptance(options:AcceptanceOptions){
  // Configuration validation occurs before credentials or any network request.
  const config=officeConfigSchema.parse({apiOrigin:options.apiOrigin,allowLoopbackHttp:true,tokenFile:'token',
    spreadsheets:[{alias:'disposable-test',label:'Disposable Office acceptance test',spreadsheetId:options.spreadsheetId,allowEdit:true}]});
  const unauth=await fetch(new URL(`/spreadsheets/${options.spreadsheetId}`,options.apiOrigin),{redirect:'error',signal:AbortSignal.timeout(5000)});
  await unauth.body?.cancel();
  if(unauth.status!==401)throw new Error('UNAUTHENTICATED_ACCESS_NOT_DENIED');
  options.report('UNAUTHENTICATED_ACCESS_DENIED');
  let password=await options.passwordPrompt();let token:string;
  try{token=await SynologySpreadsheet.authorize(options.apiOrigin,options.nasOrigin,options.username,password,{allowLoopbackHttp:true});}
  finally{password='';}
  options.report('RESTRICTED_ACCOUNT_AUTHORIZED');
  const directory=await mkdtemp(path.join(tmpdir(),'office-acceptance-'));
  const configPath=path.join(directory,'config.json');
  const client=new Client({name:'manual-disposable-office-test',version:'1'});
  try{
    await writeFile(path.join(directory,'token'),token,{mode:0o600});token='';
    await writeFile(configPath,JSON.stringify(config),{mode:0o600});
    await client.connect(new StdioClientTransport({command:process.execPath,args:[path.resolve(options.bundle),'--config',configPath],stderr:'pipe'}));
    const tools=await client.listTools();if(tools.tools.length!==4)throw new Error('MCP_TOOL_COUNT_MISMATCH');
    const call=async(name:string,args:Record<string,unknown>)=>{
      const result=await client.callTool({name,arguments:args});
      const content=result.content as Array<{type:string,text?:string}>;
      if(result.isError){const code=content[0]?.text;throw new Error(typeof code==='string'&&/^[A-Z_]+$/.test(code)?code:'MCP_OPERATION_FAILED');}
      if(content[0]?.type!=='text'||typeof content[0].text!=='string')throw new Error('MCP_RESPONSE_INVALID');
      return JSON.parse(content[0].text);
    };
    const denied=await client.callTool({name:'get_spreadsheet',arguments:{alias:'unconfigured'}});
    if(!denied.isError||!JSON.stringify(denied).includes('OFFICE_DOCUMENT_DENIED'))throw new Error('UNCONFIGURED_ALIAS_NOT_DENIED');
    options.report('UNCONFIGURED_ALIAS_DENIED');
    const metadata=await call('get_spreadsheet',{alias:'disposable-test'});
    // Do not derive mutation scope from arbitrary document contents.
    if(!Array.isArray(metadata.sheets)||!metadata.sheets.some((sheet:{title?:unknown})=>sheet.title==='Sheet1'))throw new Error('EXPECTED_TEST_SHEET_MISSING');
    options.report('NATIVE_METADATA_VERIFIED');
    await call('read_spreadsheet_cells',{alias:'disposable-test',range:'Sheet1!A1:B2'});
    options.report('BOUNDED_READ_VERIFIED');
    const values=[['NAS-CONNECTOR-OFFICE-TEST',7],['synthetic test only',true]];
    const receipt=await call('write_spreadsheet_cells',{alias:'disposable-test',range:'Sheet1!A1:B2',values});
    if(receipt.verification!=='readback-matched'||!receipt.updated)throw new Error('EDIT_NOT_VERIFIED');
    options.report('BOUNDED_EDIT_READBACK_VERIFIED');
    // Revocation is a local configuration change, never a destructive vendor operation.
    await writeFile(configPath,JSON.stringify({...config,spreadsheets:[]}),{mode:0o600});
    const revoked=await client.callTool({name:'read_spreadsheet_cells',arguments:{alias:'disposable-test',range:'Sheet1!A1:B2'}});
    if(!revoked.isError||!JSON.stringify(revoked).includes('OFFICE_CONFIGURATION_CHANGED'))throw new Error('REVOCATION_NOT_ENFORCED');
    options.report('DEVELOPMENT_CONFIGURATION_REVOCATION_VERIFIED');
  }finally{token='';await client.close();await rm(directory,{recursive:true,force:true});}
}

async function main(){
  const [bundle,nasOrigin,username,spreadsheetId,ack]=process.argv.slice(2);
  if(!bundle||!nasOrigin||!username||!spreadsheetId||ack!=='--replace-disposable-A1-B2')throw new Error('DISPOSABLE_TEST_ARGUMENTS_REQUIRED');
  await officeAcceptance({bundle,nasOrigin,username,spreadsheetId,apiOrigin:'http://127.0.0.1:3000/',passwordPrompt:hiddenPassword,report:message=>console.log(message)});
}
if(/office-live-acceptance\.(?:ts|cjs)$/.test(process.argv[1]??''))main().catch(error=>{
  const code=error instanceof OfficeError||error instanceof Error?error.message:'';
  console.error(/^[A-Z_]+$/.test(code)?code:'OFFICE_ACCEPTANCE_FAILED');process.exitCode=1;
});
