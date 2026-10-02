import { constants } from 'node:fs';
import { access, opendir, realpath } from 'node:fs/promises';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { ManagementError } from './bridge-auth.js';

export type Share = {id: string; label: string; path: string; readable: boolean; writable:boolean};
/** Bases come from trusted deployment configuration; browser input never supplies a filesystem path. */
export class ShareCatalog {
  constructor(private readonly bases: readonly string[]) {
    if (bases.length > 32 || bases.some(p => !path.isAbsolute(p))) throw new ManagementError('INVALID_CATALOG');
  }
  static dsm() {return new ShareCatalog(Array.from({length:16},(_,i)=>`/volume${i+1}`));}
  async list(): Promise<Share[]> {
    const shares: Share[] = [];
    for (const base of this.bases) {
      let canonical: string;
      try {canonical = await realpath(base);} catch {continue;}
      const directory = await opendir(canonical).catch(()=>null);
      if (!directory) continue;
      for await (const d of directory) {
        if (shares.length >= 500) break;
        if (!d.isDirectory() || /^[.@#]/.test(d.name) || /[\x00-\x1f\x7f]/.test(d.name)) continue;
        const full = path.join(canonical,d.name);
        const resolved = await realpath(full).catch(()=>null);
        if (!resolved || resolved !== full) continue;
        const readable = await access(full,constants.R_OK | constants.X_OK).then(()=>true,()=>false);
        const writable = await access(full,constants.W_OK | constants.X_OK).then(()=>true,()=>false);
        shares.push({id:'share_'+createHash('sha256').update(full).digest('hex').slice(0,20),label:d.name,path:full,readable,writable});
      }
    }
    return shares.sort((a,b)=>a.label.localeCompare(b.label));
  }
}
