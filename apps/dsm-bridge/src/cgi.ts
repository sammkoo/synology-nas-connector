import { ManagementError } from '../../../packages/management/src/index.js';
import { STATUS_CODES } from 'node:http';
import { forwardManagement } from './bridge.js';

async function main() {
  let result: {status:number;body:unknown};
  try {
    const length = Number(process.env.CONTENT_LENGTH ?? '0');
    if (!Number.isInteger(length) || length < 0 || length > 16384) throw new ManagementError('REQUEST_TOO_LARGE',413);
    const chunks: Buffer[] = []; let size = 0;
    if (length) {
      const timeout = setTimeout(()=>process.stdin.destroy(new Error('BODY_TIMEOUT')),3000);
      try {for await (const chunk of process.stdin) {
        size += chunk.length;
        if (size > length) throw new ManagementError('INVALID_BODY');
        chunks.push(Buffer.from(chunk));
      }} finally {clearTimeout(timeout);}
      if (size !== length) throw new ManagementError('INVALID_BODY');
    }
    result = await forwardManagement(process.env,Buffer.concat(chunks),process.argv[2]!);
  } catch (e) {
    result = {status:e instanceof ManagementError ? e.status : 503,
      body:{error:e instanceof ManagementError ? e.code : 'DSM_BRIDGE_UNAVAILABLE'}};
  }
  process.stdout.write(`Status: ${result.status} ${STATUS_CODES[result.status] ?? 'Unknown Status'}\r\nContent-Type: application/json; charset=utf-8\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n\r\n${JSON.stringify(result.body)}`);
}
void main();
