import { createHash, timingSafeEqual } from 'node:crypto';
import { constants } from 'node:fs';
import { open } from 'node:fs/promises';

export const NAS_READ_SCOPE = 'nas:read';
export const NAS_CREATE_SCOPE = 'nas:create';
export const NAS_SHARE_SCOPE = 'nas:share';
export const NAS_SCOPES = [NAS_READ_SCOPE,NAS_CREATE_SCOPE,NAS_SHARE_SCOPE];
export type Principal = {subject: string; scopes: readonly string[]; rootIds?: readonly string[]; deviceId?: string};
/** A future OAuth adapter must verify signature/introspection, issuer, audience, expiry, scopes and revocation. */
export interface Authenticator {
  readonly mode: 'local-token' | 'oauth';
  authenticate(token: string): Promise<Principal | null>;
  challenge: string;
  resourceMetadata?: Record<string, unknown>;
}
export async function localTokenAuthenticator(tokenFile: string,allowCreate=false): Promise<Authenticator> {
  const handle = await open(tokenFile, constants.O_RDONLY | constants.O_NOFOLLOW);
  let token: string;
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || stat.size > 4096 || (stat.mode & 0o077) !== 0 || stat.uid !== process.getuid?.())
      throw new Error('Token file must be owned by the service user with mode 0600');
    token = (await handle.readFile('utf8')).trim();
  } finally { await handle.close(); }
  if (!/^[A-Za-z0-9_-]{32,256}$/.test(token)) throw new Error('Token must contain 32–256 base64url characters');
  const expected = createHash('sha256').update(token).digest();
  return {
    mode: 'local-token', challenge: 'Bearer realm="nas-connector-local"',
    async authenticate(candidate) {
      if (candidate.length > 256) return null;
      const supplied = createHash('sha256').update(candidate).digest();
      return timingSafeEqual(expected, supplied) ? {subject: 'local-owner', scopes: allowCreate?NAS_SCOPES:[NAS_READ_SCOPE]} : null;
    }
  };
}
/** Configuration contract only; v0.1 does not expose an authorization server or OpenAI login flow. */
export function oauthResourceMetadata(resource: string, issuer: string) {
  for (const value of [resource, issuer]) {
    const url = new URL(value);
    if (url.protocol !== 'https:' || url.username || url.password || url.hash || url.search)
      throw new Error('OAuth resource and issuer must be canonical HTTPS URLs');
  }
  return {resource, authorization_servers: [issuer], scopes_supported: [NAS_READ_SCOPE]};
}
