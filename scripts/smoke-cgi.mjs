import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { once } from 'node:events';
import path from 'node:path';

// Exercise the packaged CGI entry point, without DSM credentials or NAS files.
// An absent configuration must not be read before authentication succeeds.
const cases = [
  { length: '0', input: '', status: '401 Unauthorized', error: 'DSM_LOGIN_REQUIRED' },
  { length: '16385', input: '', status: '413 Payload Too Large', error: 'REQUEST_TOO_LARGE' },
  { length: '1', input: '', status: '400 Bad Request', error: 'INVALID_BODY' },
  // An invented fixture value, never an actual DSM session. The helper is
  // absent on CI/macOS, so this exercises a real failed child-process launch.
  { length: '0', input: '', status: '200 OK', error: 'DSM_AUTH_HELPER_MISSING',
    env: {HTTP_COOKIE:'fixture-only-invalid-cookie'},httpStatus:503 }
];
for (const scenario of cases) {
  const processResult = spawnSync(process.execPath,
    [path.resolve('dist/dsm-bridge.cjs'), path.resolve('dist/absent-smoke-config.json')], {
      env: { PATH: '/usr/bin:/bin', REQUEST_METHOD: 'GET', QUERY_STRING: 'action=bootstrap',
        REMOTE_ADDR: '127.0.0.1', CONTENT_LENGTH: scenario.length,...scenario.env },
      input: scenario.input, encoding: 'utf8', timeout: 10000, maxBuffer: 65536
    });
  assert.ifError(processResult.error);
  assert.equal(processResult.status, 0);
  assert.equal(processResult.stderr, '');
  const separator = processResult.stdout.indexOf('\r\n\r\n');
  assert.ok(separator > 0, 'CGI must separate headers and body with CRLF');
  const headers = processResult.stdout.slice(0, separator).split('\r\n');
  assert.equal(headers[0], `Status: ${scenario.status}`);
  assert.ok(headers.includes('Content-Type: application/json; charset=utf-8'));
  assert.ok(headers.includes('Cache-Control: no-store'));
  assert.ok(headers.includes('X-Content-Type-Options: nosniff'));
  assert.deepEqual(JSON.parse(processResult.stdout.slice(separator + 4)),
    { error: scenario.error,...(scenario.httpStatus ? {httpStatus:scenario.httpStatus} : {}) });
}
// A CGI server need not close stdin after delivering CONTENT_LENGTH bytes.
// Keep this real child process's input open: authentication must still start.
const pending = spawn(process.execPath,
  [path.resolve('dist/dsm-bridge.cjs'), path.resolve('dist/absent-smoke-config.json')], {
    env: {PATH:'/usr/bin:/bin',REQUEST_METHOD:'POST',QUERY_STRING:'action=roots',
      REMOTE_ADDR:'127.0.0.1',CONTENT_LENGTH:'2',CONTENT_TYPE:'application/json',
      HTTP_HOST:'fixture.invalid',HTTP_ORIGIN:'https://fixture.invalid',
      HTTP_COOKIE:'fixture-only-invalid-cookie'},stdio:['pipe','pipe','pipe']
  });
let output='',stderr='';
pending.stdout.setEncoding('utf8');pending.stderr.setEncoding('utf8');
pending.stdout.on('data',chunk=>{output+=chunk;});
pending.stderr.on('data',chunk=>{stderr+=chunk;});
pending.stdin.on('error',()=>{});
const deadline=setTimeout(()=>pending.kill(),10000);
try {
  pending.stdin.write('{}'); // Deliberately never end stdin before the response.
  const [code,signal]=await once(pending,'close');
  assert.equal(signal,null);assert.equal(code,0);assert.equal(stderr,'');
  const separator=output.indexOf('\r\n\r\n');
  assert.ok(separator>0);
  assert.equal(output.slice(0,separator).split('\r\n')[0],'Status: 200 OK');
  assert.deepEqual(JSON.parse(output.slice(separator+4)),
    {error:'DSM_AUTH_HELPER_MISSING',httpStatus:503});
} finally {clearTimeout(deadline);pending.stdin.destroy();}
console.log('Bundled CGI passed 5 scenarios, including a complete POST body with stdin kept open');
