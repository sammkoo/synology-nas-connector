import { createHash, randomUUID } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, open, rename, unlink,mkdir,realpath } from 'node:fs/promises';
import path from 'node:path';
import { configSchema, NasFiles,SynologyDrive, type Config } from '../../core/src/index.js';
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
    const shares = (await this.catalog.list()).map(({id,label,path:full,readable,writable})=>({id,label,readable,writable,selected:selected.has(full),allowCreate:!!this.config.roots.find(r=>r.path===full)?.allowCreate,allowShare:!!this.config.roots.find(r=>r.path===full)?.allowShare}));
    if (files !== this.files) throw new ManagementError('CONFIGURATION_CHANGED',409);
    return {readOnly:!this.config.roots.some(r=>r.allowCreate||r.allowShare),createSupported:process.platform==='linux',driveConfigured:!!this.config.drive,revision:this.revision(),roots:this.files.listRoots(),shares,
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
        const previous=this.config.roots.find(r=>r.id===id&&r.path===share.path);
        roots.push({id:share.id,label:share.label,path:share.path,...(previous?.allowCreate?{allowCreate:true}:{}),...(previous?.allowShare?{allowShare:true}:{})});
      }
      const next = configSchema.parse({...this.config,roots});
      return this.publish(next);
    });
    this.tail = operation.then(()=>{},()=>{});
    return operation;
  }
  async connectDrive(baseUrl:string,account:string,passwd:string,expectedRevision:string) {
    const operation=this.tail.then(async()=>{
      if(this.revision()!==expectedRevision)throw new ManagementError('CONFIGURATION_CHANGED',409);
      const sid=await SynologyDrive.login(baseUrl,account,passwd);
      // Disable existing sharing before replacing a credential, including if the later save fails.
      await this.publish(configSchema.parse({...this.config,roots:this.config.roots.map(r=>({...r,allowShare:false}))}));
      const directory=path.join(path.dirname(this.filename),'drive');
      await mkdir(directory,{mode:0o700}).catch(e=>{if(e.code!=='EEXIST')throw e;});
      const stat=await lstat(directory);
      if(!stat.isDirectory()||stat.isSymbolicLink()||stat.uid!==process.getuid?.()||stat.mode&0o077)throw new ManagementError('PRIVATE_CONFIGURATION_REQUIRED',503);
      const temporary=path.join(directory,`.session-${randomUUID()}.tmp`),sessionFile=path.join(directory,'session');
      try {
        const handle=await open(temporary,constants.O_CREAT|constants.O_EXCL|constants.O_WRONLY|constants.O_NOFOLLOW,0o600);
        try{await handle.writeFile(sid+'\n');await handle.sync();}finally{await handle.close();}
        await rename(temporary,sessionFile);
      } finally {await unlink(temporary).catch(()=>{});}
      return this.publish(configSchema.parse({...this.config,drive:{baseUrl,sessionFile,linkOrigins:[new URL(baseUrl).origin]},roots:this.config.roots.map(r=>({...r,allowShare:false}))}));
    });
    this.tail=operation.then(()=>{},()=>{});return operation;
  }
  async saveSharing(rootId:string,allowShare:boolean,expectedRevision:string) {
    const operation=this.tail.then(async()=>{
      if(this.revision()!==expectedRevision)throw new ManagementError('CONFIGURATION_CHANGED',409);
      const root=this.config.roots.find(r=>r.id===rootId);
      if(!root)throw new ManagementError('FOLDER_UNAVAILABLE',404);
      if(allowShare){
        if(!this.config.drive)throw new ManagementError('DRIVE_SESSION_REQUIRED',400);
        const canonical=await realpath(root.path);
        if(!/^\/volume[1-9]\d*\/[^/]+$/.test(canonical))throw new ManagementError('DRIVE_PATH_MISMATCH',400);
        await new SynologyDrive(this.config.drive).checkFolder(`/team-folders/${path.basename(canonical)}`,canonical);
      }
      return this.publish(configSchema.parse({...this.config,roots:this.config.roots.map(r=>r.id===rootId?{...r,allowShare}:r)}));
    });
    this.tail=operation.then(()=>{},()=>{});return operation;
  }
  async saveCreation(rootId:string,allowCreate:boolean,expectedRevision:string) {
    const operation=this.tail.then(async()=>{
      if(this.revision()!==expectedRevision)throw new ManagementError('CONFIGURATION_CHANGED',409);
      const root=this.config.roots.find(r=>r.id===rootId);
      if(!root)throw new ManagementError('FOLDER_UNAVAILABLE',404);
      if(allowCreate){
        if(process.platform!=='linux')throw new ManagementError('CREATE_REQUIRES_LINUX',400);
        const share=(await this.catalog.list()).find(s=>s.id===rootId&&s.path===root.path);
        if(!share?.readable||!share.writable)throw new ManagementError('FOLDER_WRITE_PERMISSION_REQUIRED',403);
      }
      return this.publish(configSchema.parse({...this.config,roots:this.config.roots.map(r=>r.id===rootId?{...r,allowCreate}:r)}));
    });
    this.tail=operation.then(()=>{},()=>{});
    return operation;
  }
  private async publish(next:Config) {
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
  }
}
