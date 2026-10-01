import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createContext, runInContext } from 'node:vm';
import { forwardManagement } from '../apps/dsm-bridge/src/bridge.js';
import { cgiResponse } from '../apps/dsm-bridge/src/response.js';
import { ManagementError } from '../packages/management/src/index.js';

const env = {REQUEST_METHOD:'GET',QUERY_STRING:'action=bootstrap',REMOTE_ADDR:'127.0.0.1',
  HTTP_COOKIE:'invented-test-cookie'};
const absentConfig = '/nonexistent-nas-test-config/config.json';
function hasError(code:string,status:number) {
  return (error:unknown) => {
    assert.ok(error instanceof ManagementError);
    assert.equal(error.code,code);assert.equal(error.status,status);
    assert.equal(error.message,code);
    assert.equal('cause' in error,false);
    assert.ok(!JSON.stringify(error).includes('invented-test-cookie'));
    return true;
  };
}
test('CGI stage errors never disclose failed child output, cookies or raw exception details',async()=>{
  await assert.rejects(forwardManagement(env,Buffer.alloc(0),absentConfig,async()=>{
    throw Object.assign(new Error('private exception invented-test-cookie'),
      {stdout:'private auth output',stderr:'private diagnostic'});
  }),hasError('DSM_AUTH_EXECUTION_FAILED',503));
  await assert.rejects(forwardManagement(env,Buffer.alloc(0),absentConfig,async filename=>{
    if(filename.endsWith('authenticate.cgi'))return {stdout:'admin\n'};
    throw new Error('private lookup details');
  }),hasError('DSM_GROUP_LOOKUP_FAILED',503));
});
test('CGI distinguishes authentication rejection from launch failure without trusting partial stdout',async()=>{
  const scenarios:[Record<string,unknown>,string,number][]=[
    [{code:5},'DSM_AUTH_SESSION_REJECTED',401],
    [{code:1},'DSM_AUTH_SESSION_REJECTED',401],
    [{code:255},'DSM_AUTH_SESSION_REJECTED',401],
    [{code:'ENOENT'},'DSM_AUTH_HELPER_MISSING',503],
    [{code:'EACCES'},'DSM_AUTH_HELPER_DENIED',503],
    [{code:'EPERM'},'DSM_AUTH_HELPER_DENIED',503],
    [{code:'ERR_CHILD_PROCESS_STDIO_MAXBUFFER',killed:true},'DSM_AUTH_HELPER_OUTPUT_LIMIT',503],
    [{code:null,killed:true,signal:'SIGTERM'},'DSM_AUTH_HELPER_INTERRUPTED',503],
    [{code:5,signal:'SIGSEGV'},'DSM_AUTH_EXECUTION_FAILED',503],
    [{code:256},'DSM_AUTH_EXECUTION_FAILED',503],
    [{code:'5'},'DSM_AUTH_EXECUTION_FAILED',503],
    [{code:'private invented-test-cookie'},'DSM_AUTH_EXECUTION_FAILED',503],
  ];
  for(const [failure,code,status] of scenarios) {
    let calls=0;
    await assert.rejects(forwardManagement({...env,HTTP_X_SYNO_TOKEN:'fixture-token'},Buffer.alloc(0),absentConfig,async(filename,args,options)=>{
      calls++;
      assert.equal(filename,'/usr/syno/synoman/webman/modules/authenticate.cgi');
      assert.deepEqual(args,[]);assert.equal(options.env?.HTTP_X_SYNO_TOKEN,'fixture-token');
      throw Object.assign(new Error('private invented-test-cookie'),failure,{stdout:'admin\n',stderr:'private auth output'});
    }),hasError(code,status));
    assert.equal(calls,1,'Failed authentication must not reach account lookup or configuration');
  }
});
test('CGI rejects missing login and non-administrators before opening package configuration',async()=>{
  await assert.rejects(forwardManagement({...env,HTTP_COOKIE:undefined},Buffer.alloc(0),absentConfig,
    async()=>{assert.fail('Authentication must not execute without a session cookie');}),
    hasError('DSM_LOGIN_REQUIRED',401));
  await assert.rejects(forwardManagement(env,Buffer.alloc(0),absentConfig,async(filename,args)=>{
    if(filename.endsWith('authenticate.cgi'))return {stdout:'member\n'};
    assert.equal(filename,'/usr/bin/id');assert.deepEqual(args,['-Gn','member']);
    return {stdout:'users fake-administrators\n'};
  }),hasError('DSM_ADMIN_REQUIRED',403));
  await assert.rejects(forwardManagement(env,Buffer.alloc(0),absentConfig,async filename=>
    ({stdout:filename.endsWith('authenticate.cgi')?'admin\n':'users administrators\n'})),
    hasError('DSM_CONFIG_READ_FAILED',503));
});
test('only CGI server errors use a bounded error envelope; rejection and success statuses are retained',()=>{
  assert.deepEqual(cgiResponse({status:503,body:{error:'DSM_AUTH_EXECUTION_FAILED',private:'must not escape'}}),
    {status:200,body:{error:'DSM_AUTH_EXECUTION_FAILED',httpStatus:503}});
  assert.deepEqual(cgiResponse({status:500,body:{error:'private exception /volume1/config'}}),
    {status:200,body:{error:'DSM_BRIDGE_UNAVAILABLE',httpStatus:500}});
  assert.deepEqual(cgiResponse({status:503,body:['private upstream result']}),
    {status:200,body:{error:'DSM_BRIDGE_UNAVAILABLE',httpStatus:503}});
  for(const status of [200,401,403,413,419]) {
    const value={status,body:{error:'FIXED_TEST_ERROR'}};
    assert.deepEqual(cgiResponse(value),value);
  }
});
test('actual DSM dashboard rejects HTTP 200 error envelopes without enabling setup or accepting writes',async()=>{
  const nodes = new Map<string,{disabled:boolean;textContent:string;options:unknown[];addEventListener:()=>void}>();
  const context=createContext({document:{getElementById:(id:string)=>{
    if(!nodes.has(id))nodes.set(id,{disabled:true,textContent:'',options:[],addEventListener:()=>{}});
    return nodes.get(id);
  }},setInterval:()=>{},AbortSignal,fetch:async(url:string)=>new Response(JSON.stringify(url==='/webman/login.cgi'
    ?{success:true,SynoToken:'fixture-token'}:{error:'DSM_AUTH_EXECUTION_FAILED',httpStatus:503}),
    {status:200,headers:{'Content-Type':'application/json'}})});
  runInContext(await readFile('packaging/synology/dashboard.js','utf8'),context);
  await new Promise<void>(resolve=>setImmediate(resolve));
  assert.equal(runInContext('sessionReady',context),false);
  assert.equal(nodes.get('save')!.disabled,true);
  assert.equal(nodes.get('preview')!.disabled,true);
  assert.match(nodes.get('notice')!.textContent,/DSM_AUTH_EXECUTION_FAILED/);
  await assert.rejects(runInContext('api("roots", {ids:[],revision:"fixture"})',context),/DSM_AUTH_EXECUTION_FAILED/);
  assert.equal(runInContext('sessionReady',context),false);
});
async function dashboard(fetcher:(url:string,options:RequestInit)=>Promise<Response>) {
  const nodes=new Map<string,{disabled:boolean;textContent:string;options:unknown[];addEventListener:()=>void}>();
  const context=createContext({document:{getElementById:(id:string)=>{
    if(!nodes.has(id))nodes.set(id,{disabled:true,textContent:'',options:[],addEventListener:()=>{}});
    return nodes.get(id);
  }},setInterval:()=>{},AbortSignal,fetch:fetcher});
  runInContext(await readFile('packaging/synology/dashboard.js','utf8'),context);
  await new Promise<void>(resolve=>setImmediate(resolve));
  return {nodes,context};
}
test('DSM token stays in memory and is sent only in a same-origin CGI header with the separate management CSRF',async()=>{
  const requests:{url:string;options:RequestInit}[]=[];
  const fixture='fixture-token+/=';
  const {nodes,context}=await dashboard(async(url,options)=>{
    requests.push({url,options});
    return new Response(JSON.stringify(url==='/webman/login.cgi'?{success:true,SynoToken:fixture}:
      {error:'DSM_CONFIG_READ_FAILED',httpStatus:503}),{status:200});
  });
  assert.equal(requests.length,2);assert.equal(requests[0]!.url,'/webman/login.cgi');
  assert.equal(requests[1]!.url,'api.cgi?action=bootstrap');
  for(const request of requests) {
    assert.equal(request.options.credentials,'same-origin');assert.equal(request.options.redirect,'error');
    assert.equal(request.options.cache,'no-store');assert.ok(!request.url.includes(fixture));
  }
  assert.ok(requests[0]!.options.signal);
  assert.deepEqual(JSON.parse(JSON.stringify(requests[1]!.options.headers)),{'X-SYNO-TOKEN':fixture});
  runInContext('csrf="fixture-management-csrf"',context);
  await assert.rejects(runInContext('api("roots", {ids:[],revision:"fixture"})',context),/DSM_CONFIG_READ_FAILED/);
  const write=requests[2]!;
  assert.equal(write.options.method,'POST');
  assert.deepEqual(JSON.parse(JSON.stringify(write.options.headers)),{
    'X-SYNO-TOKEN':fixture,'Content-Type':'application/json','X-NAS-CSRF':'fixture-management-csrf'});
  assert.ok(!String(write.options.body).includes(fixture));
  for(const node of nodes.values())assert.ok(!node.textContent.includes(fixture));
  assert.equal(runInContext('sessionReady',context),false);
});
test('DSM token acquisition fails closed on unsafe, unsuccessful, non-JSON or unavailable responses',async()=>{
  const badResponses=[
    ()=>new Response(JSON.stringify({success:false,SynoToken:'fixture-secret'})),
    ()=>new Response(JSON.stringify({success:true,error:'private error',SynoToken:'fixture-secret'})),
    ()=>new Response(JSON.stringify({success:true,SynoToken:''})),
    ()=>new Response(JSON.stringify({success:true,SynoToken:'header\r\ninjection'})),
    ()=>new Response(JSON.stringify({success:true,SynoToken:'x'.repeat(513)})),
    ()=>new Response(JSON.stringify({success:true,SynoToken:123})),
    ()=>new Response('private HTML fixture-secret'),
    ()=>new Response(JSON.stringify({success:true,SynoToken:'fixture-secret'}),{status:403}),
    ()=>{throw new Error('private network fixture-secret');},
  ];
  for(const response of badResponses) {
    let calls=0;
    const {nodes,context}=await dashboard(async url=>{
      calls++;assert.equal(url,'/webman/login.cgi');return response();
    });
    assert.equal(calls,1);assert.equal(runInContext('dsmToken',context),'');
    assert.equal(runInContext('sessionReady',context),false);
    assert.equal(nodes.get('save')!.disabled,true);assert.equal(nodes.get('preview')!.disabled,true);
    assert.match(nodes.get('notice')!.textContent,/DSM_SESSION_TOKEN_UNAVAILABLE/);
    assert.ok(!nodes.get('notice')!.textContent.includes('fixture-secret'));
    await assert.rejects(runInContext('api("roots", {})',context),/DSM_SESSION_TOKEN_UNAVAILABLE/);
    assert.equal(calls,1);
  }
});
test('DSM session rejection clears tokens and disables all management actions before another request',async()=>{
  let calls=0;
  const {nodes,context}=await dashboard(async url=>{
    calls++;return new Response(JSON.stringify(url==='/webman/login.cgi'?{success:true,SynoToken:'fixture-token'}:
      {error:'DSM_CONFIG_READ_FAILED',httpStatus:503}));
  });
  runInContext('sessionReady=true;csrf="fixture-csrf";root.options=[{}]',context);
  for(const node of nodes.values())node.disabled=false;
  // Simulate a later authenticated call losing the DSM session.
  context.fetch=async()=>{calls++;return new Response(JSON.stringify({error:'DSM_AUTH_SESSION_REJECTED'}),{status:401});};
  await assert.rejects(runInContext('api("roots", {})',context),/DSM did not confirm this session/);
  assert.equal(runInContext('sessionReady',context),false);
  assert.equal(runInContext('csrf',context),'');assert.equal(runInContext('dsmToken',context),'');
  for(const id of ['save','preview','root','pair-begin','pair-confirm','pair-cancel','pair-disconnect'])
    assert.equal(nodes.get(id)!.disabled,true,id);
  const before=calls;
  await assert.rejects(runInContext('api("pair-confirm", {})',context),/DSM_SESSION_TOKEN_UNAVAILABLE/);
  assert.equal(calls,before);
  for(const status of [401,403,419]) {
    runInContext('sessionReady=true;csrf="fixture-csrf";dsmToken="fixture-token"',context);
    context.fetch=async()=>new Response('private HTML fixture-secret',{status});
    await assert.rejects(runInContext('api("roots", {})',context),new RegExp(`HTTP ${status}`));
    assert.equal(runInContext('sessionReady',context),false);
    assert.equal(runInContext('dsmToken',context),'');
    assert.equal(nodes.get('save')!.disabled,true);
  }
});
