import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { constants } from 'node:fs';
import { open } from 'node:fs/promises';

export class ManagementError extends Error {
  constructor(public readonly code: string, public readonly status = 400) { super(code); }
}
export type BridgeRequest = {method: string; path: string; user: string; timestamp: string; nonce: string; csrf: string; body: Buffer};
const digest = (body: Buffer) => createHash('sha256').update(body).digest('hex');
const message = (r: BridgeRequest) => JSON.stringify([r.method,r.path,r.user,r.timestamp,r.nonce,r.csrf,digest(r.body)]);
export function signBridgeRequest(secret: Buffer, request: BridgeRequest) {
  return createHmac('sha256',secret).update(message(request)).digest('hex');
}
export async function readManagementSecret(filename: string) {
  const file = await open(filename,constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const s = await file.stat();
    if (!s.isFile() || s.size > 256 || (s.mode & 0o077) ||
      (s.uid !== process.getuid?.() && process.getuid?.() !== 0))
      throw new ManagementError('PRIVATE_SECRET_REQUIRED',503);
    const value = (await file.readFile('utf8')).trim();
    if (!/^[a-f0-9]{64}$/.test(value)) throw new ManagementError('INVALID_MANAGEMENT_SECRET',503);
    return Buffer.from(value,'hex');
  } finally {await file.close();}
}
export class BridgeGuard {
  private readonly used = new Map<string,number>();
  private readonly sessions = new Map<string,{hash: Buffer; expires: number}>();
  constructor(private readonly secret: Buffer, private readonly now: () => number = Date.now) {
    if (secret.length !== 32) throw new ManagementError('INVALID_MANAGEMENT_SECRET',503);
  }
  verify(r: BridgeRequest, signature: string, address: string | undefined) {
    const now = this.now();
    if (address !== '127.0.0.1' && address !== '::1' && address !== '::ffff:127.0.0.1')
      throw new ManagementError('LOCAL_BRIDGE_REQUIRED',403);
    if (!/^[A-Za-z0-9_.@\\-]{1,128}$/.test(r.user) || r.user.startsWith('-') ||
      !/^\d{13}$/.test(r.timestamp) || !/^[a-f0-9]{64}$/.test(r.nonce) || !/^[a-f0-9]{64}$/.test(signature) ||
      Math.abs(now - Number(r.timestamp)) > 15000)
      throw new ManagementError('BRIDGE_AUTH_REQUIRED',401);
    const expected = Buffer.from(signBridgeRequest(this.secret,r),'hex');
    if (!timingSafeEqual(expected,Buffer.from(signature,'hex'))) throw new ManagementError('BRIDGE_AUTH_REQUIRED',401);
    for (const [nonce,time] of this.used) if (now - time > 30000) this.used.delete(nonce);
    if (this.used.has(r.nonce)) throw new ManagementError('BRIDGE_REPLAY_DENIED',401);
    if (this.used.size >= 2048) throw new ManagementError('BRIDGE_BUSY',503);
    this.used.set(r.nonce,now);
  }
  issueCsrf(user: string) {
    const now = this.now();
    for (const [name,session] of this.sessions) if (session.expires < now) this.sessions.delete(name);
    if (!this.sessions.has(user) && this.sessions.size >= 100) throw new ManagementError('BRIDGE_BUSY',503);
    const token = randomBytes(32).toString('hex');
    this.sessions.set(user,{hash: createHash('sha256').update(token).digest(),expires:now+15*60_000});
    return token;
  }
  checkCsrf(user: string, token: string) {
    const session = this.sessions.get(user);
    if (!session || session.expires <= this.now() || !/^[a-f0-9]{64}$/.test(token) ||
      !timingSafeEqual(session.hash,createHash('sha256').update(token).digest()))
      throw new ManagementError('SESSION_EXPIRED',419);
  }
}
