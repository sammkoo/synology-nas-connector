import {constants} from 'node:fs';
import {open} from 'node:fs/promises';
import path from 'node:path';
import {StdioServerTransport} from '@modelcontextprotocol/sdk/server/stdio.js';
import {officeConfigSchema,SynologySpreadsheet,OfficeError} from '../../../packages/office/src/index.js';
import {createOfficeDevMcp} from './mcp.js';

async function main(){
  const args=process.argv.slice(2);
  if(args.length!==2||args[0]!=='--config')throw new OfficeError('OFFICE_CONFIGURATION_REQUIRED');
  const configPath=path.resolve(args[1]!);let handle;
  try {
    handle=await open(configPath,constants.O_RDONLY|constants.O_NOFOLLOW);
    const stat=await handle.stat();
    if(!stat.isFile()||stat.uid!==process.getuid?.()||stat.mode&0o077||stat.size>32768)throw new OfficeError('OFFICE_CONFIGURATION_INVALID');
    const snapshot=await handle.readFile('utf8');
    const config=officeConfigSchema.parse(JSON.parse(snapshot));
    config.tokenFile=path.resolve(path.dirname(configPath),config.tokenFile);
    const office=new SynologySpreadsheet(config);
    // Revocation/editing the private configuration takes effect before the next mutation.
    const beforeCommit=async()=>{
      let current;
      try {current=await open(configPath,constants.O_RDONLY|constants.O_NOFOLLOW);const state=await current.stat();
        if(!state.isFile()||state.uid!==process.getuid?.()||state.mode&0o077||state.size>32768||(await current.readFile('utf8'))!==snapshot)throw new Error();}
      catch{throw new OfficeError('OFFICE_CONFIGURATION_CHANGED');}finally{await current?.close();}
    };
    await createOfficeDevMcp(office,{revalidate:beforeCommit}).connect(new StdioServerTransport());
  }finally{await handle?.close();}
}
main().catch(error=>{console.error(error instanceof OfficeError?error.code:'OFFICE_START_FAILED');process.exitCode=1;});
