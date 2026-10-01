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
  }},setInterval:()=>{},fetch:async()=>new Response(JSON.stringify({error:'DSM_AUTH_EXECUTION_FAILED',httpStatus:503}),
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
