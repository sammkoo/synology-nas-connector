import { createHash, randomUUID } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, open, rename, unlink } from 'node:fs/promises';
import path from 'node:path';
import { configSchema, NasFiles, type Config } from '../../core/src/index.js';
import { ShareCatalog } from './catalog.js';
import { ManagementError } from './bridge-auth.js';

export class ConfigurationStore {
  private tail: Promise<void> = Promise.resolve();
  private constructor(private readonly filename: string, private config: Config, private files: NasFiles, readonly catalog: ShareCatalog) {}
  static async create(filename: string, config: Config, catalog: ShareCatalog) {
    return new ConfigurationStore(filename,structuredClone(config),await NasFiles.create(config),catalog);
  }
  getFiles() {return this.files;}
  revision() {return createHash('sha256').update(JSON.stringify(this.config)).digest('hex');}
  async status() {
    const files = this.files;
    const selected = new Set(this.config.roots.map(r=>r.path));
    const shares = (await this.catalog.list()).map(({id,label,path:full,readable})=>({id,label,readable,selected:selected.has(full)}));
    if (files !== this.files) throw new ManagementError('CONFIGURATION_CHANGED',409);
    return {readOnly:true,revision:this.revision(),roots:this.files.listRoots(),shares,
      connection:{state:'not-configured'},configured:this.config.roots.length>0};
  }
  async saveRoots(ids: string[], expectedRevision: string) {
    const operation = this.tail.then(async()=>{
      if (this.revision() !== expectedRevision) throw new ManagementError('CONFIGURATION_CHANGED',409);
      if (ids.length > 20 || new Set(ids).size !== ids.length) throw new ManagementError('INVALID_SELECTION');
      const catalog = await this.catalog.list();
      const roots: Config['roots'] = [];
      for (const id of ids) {
        const share = catalog.find(s=>s.id===id);
        if (!share) throw new ManagementError('FOLDER_UNAVAILABLE',404);
        if (!share.readable) throw new ManagementError('FOLDER_PERMISSION_REQUIRED',403);
        roots.push({id:share.id,label:share.label,path:share.path});
      }
      const next = configSchema.parse({...this.config,roots});
      const files = await NasFiles.create(next);
      const existing = await lstat(this.filename);
      if (!existing.isFile() || existing.isSymbolicLink() || existing.uid !== process.getuid?.() || existing.mode & 0o077)
        throw new ManagementError('PRIVATE_CONFIGURATION_REQUIRED',503);
      const temporary = path.join(path.dirname(this.filename),`.nas-config-${randomUUID()}.tmp`);
      try {
        const handle = await open(temporary,constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,0o600);
        try {await handle.writeFile(JSON.stringify(next,null,2)+'\n');await handle.sync();} finally {await handle.close();}
        await rename(temporary,this.filename);
      } finally {await unlink(temporary).catch(()=>{});}
      // Publish policy only after the durable file write succeeds.
      this.config = next;
      this.files = files;
      return this.status();
    });
    this.tail = operation.then(()=>{},()=>{});
    return operation;
  }
}
