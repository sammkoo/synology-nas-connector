import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import path from 'node:path';

// Exercise the packaged CGI entry point, without DSM credentials or NAS files.
// An absent configuration must not be read before authentication succeeds.
const cases = [
  { length: '0', input: '', status: '401 Unauthorized', error: 'DSM_LOGIN_REQUIRED' },
  { length: '16385', input: '', status: '413 Payload Too Large', error: 'REQUEST_TOO_LARGE' },
  { length: '1', input: '', status: '400 Bad Request', error: 'INVALID_BODY' }
];
for (const scenario of cases) {
  const processResult = spawnSync(process.execPath,
    [path.resolve('dist/dsm-bridge.cjs'), path.resolve('dist/absent-smoke-config.json')], {
      env: { PATH: '/usr/bin:/bin', REQUEST_METHOD: 'GET', QUERY_STRING: 'action=bootstrap',
        REMOTE_ADDR: '127.0.0.1', CONTENT_LENGTH: scenario.length },
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
  assert.deepEqual(JSON.parse(processResult.stdout.slice(separator + 4)), { error: scenario.error });
}
console.log('Bundled CGI emitted valid status/JSON headers for unauthenticated, oversized and truncated requests');
