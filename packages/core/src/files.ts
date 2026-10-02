import { constants } from 'node:fs';
import { open, lstat, realpath, opendir, link, unlink } from 'node:fs/promises';
import { randomUUID, createHash } from 'node:crypto';
import type { FileHandle } from 'node:fs/promises';
import path from 'node:path';
import type { Config } from './config.js';
import { SynologyDrive } from './drive.js';
import { NasError } from './errors.js';
export { NasError } from './errors.js';
const textExtensions = new Set(['.txt', '.md', '.csv', '.tsv', '.json', '.xml', '.yaml', '.yml', '.log', '.rst']);
const sensitiveExtensions = new Set(['.pem', '.key', '.p12', '.pfx', '.kdbx', '.db', '.sqlite', '.sqlite3']);
const privateNames = new Set(['#recycle', '#snapshot', 'node_modules', 'id_rsa', 'id_ed25519', 'credentials', 'secrets', 'token']);
type Root = Config['roots'][number] & { canonical: string };
export type Entry = {rootId: string; path: string; name: string; type: 'directory' | 'file'; size: number; modifiedAt: string; readableText: boolean};

/** No DSM credentials or web API needed: DSM ACLs govern the package user's mounted shares. */
export class NasFiles {
  private readonly drive?:SynologyDrive;
  private constructor(private readonly config: Config, private readonly roots: Root[]) {if(config.drive)this.drive=new SynologyDrive(config.drive);}
  static async create(config: Config): Promise<NasFiles> {
    const roots: Root[] = [];
    for (const r of config.roots) {
      if (!path.isAbsolute(r.path)) throw new NasError('ROOT_MUST_BE_ABSOLUTE');
      const canonical = await realpath(r.path);
      if (canonical === path.parse(canonical).root) throw new NasError('FILESYSTEM_ROOT_FORBIDDEN');
      if (!(await lstat(canonical)).isDirectory()) throw new NasError('ROOT_NOT_DIRECTORY');
      roots.push({...r, canonical});
    }
    return new NasFiles(config, roots);
  }
  listRoots() { return this.roots.map(({id, label, allowCreate,allowShare}) => ({id, label,...(allowCreate?{allowCreate:true as const}:{}),...(allowShare&&this.drive?{allowShare:true as const}:{})})); }
  async createDriveLink(rootId:string,relative:string,signal?:AbortSignal,beforeCommit?:()=>Promise<void>) {
    const root=this.roots.find(r=>r.id===rootId);
    if(!root?.allowShare||!this.drive)throw new NasError('SHARE_DENIED');
    this.segments(relative);if(!relative)throw new NasError('PATH_DENIED');
    // Share mapping is limited to top-level DSM shared folders, never arbitrary Drive IDs from clients.
    if(!/^\/volume[1-9]\d*\/[^/]+$/.test(root.canonical))throw new NasError('DRIVE_PATH_MISMATCH');
    return this.withHandle(rootId,relative,false,async(_handle,ref)=>{
      const physicalPath=await realpath(ref);
      if(physicalPath!==path.join(root.canonical,relative))throw new NasError('PATH_DENIED');
      const value=await this.drive!.createLink(`/team-folders/${path.basename(root.canonical)}/${relative}`,physicalPath,signal,beforeCommit);
      return {rootId,path:relative,...value};
    });
  }
  /** Linux directory descriptors pin the destination. Publishing uses link(), never rename/overwrite. */
  async createFile(rootId:string,relative:string,content:string,signal?:AbortSignal,beforeCommit?:()=>Promise<void>) {
    const root=this.roots.find(r=>r.id===rootId);
    if(!root?.allowCreate)throw new NasError('CREATE_DENIED');
    if(signal?.aborted)throw new NasError('CANCELLED');
    const parts=this.segments(relative),name=parts.pop();
    if(!name)throw new NasError('PATH_DENIED');
    if(!textExtensions.has(path.extname(name).toLowerCase()))throw new NasError('UNSUPPORTED_TEXT_FORMAT');
    const bytes=Buffer.from(content,'utf8');
    if(bytes.length>16384)throw new NasError('FILE_TOO_LARGE');
    if(bytes.toString('utf8')!==content)throw new NasError('INVALID_UTF8');
    if(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(content))throw new NasError('BINARY_CONTENT');
    // A portable path-based fallback cannot safely pin a writable parent during a rename race.
    if(process.platform!=='linux')throw new NasError('CREATE_REQUIRES_LINUX');
    return this.withHandle(rootId,parts.join('/'),true,async(_parent,ref)=>{
      const temporary=path.join(ref,`.nas-create-${randomUUID()}.tmp`),target=path.join(ref,name);
      let staged=false;
      try {
        const handle=await open(temporary,constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW,0o600);
        staged=true;
        try {await handle.writeFile(bytes);await handle.sync();} finally {await handle.close();}
        await beforeCommit?.();
        if(signal?.aborted)throw new NasError('CANCELLED');
        try {await link(temporary,target);} catch(error) {
          if((error as NodeJS.ErrnoException).code==='EEXIST')throw new NasError('FILE_EXISTS');
          throw new NasError('CREATE_FAILED');
        }
        try {await _parent.sync();} catch {throw new NasError('WRITE_RESULT_UNKNOWN');}
        // No cancellation or authorization check after the commit. If durability
        // or result delivery fails, callers must inspect the path before retrying.
        return {rootId,path:relative,created:true as const,size:bytes.length,sha256:createHash('sha256').update(bytes).digest('hex')};
      } finally {if(staged)await unlink(temporary).catch(()=>{});}
    });
  }
  private segments(relative: string): string[] {
    if (relative.length > 2048 || relative.includes('\\') || relative.includes('\0') || path.posix.isAbsolute(relative))
      throw new NasError('PATH_DENIED');
    if (!relative) return [];
    const parts = relative.split('/');
    if (parts.some(p => !p || p === '..' || p === '.' || /[\x00-\x1f\x7f]/.test(p) || this.denied(p)))
      throw new NasError('PATH_DENIED');
    return parts;
  }
  private denied(name: string): boolean {
    const n = name.toLowerCase();
    return n.startsWith('.') || n.startsWith('@') || privateNames.has(n) ||
      sensitiveExtensions.has(path.extname(n)) || this.config.denyNames.some(v => v.toLowerCase() === n);
  }
  private async withHandle<T>(rootId: string, relative: string, directory: boolean, fn: (h: FileHandle, ref: string) => Promise<T>): Promise<T> {
    const root = this.roots.find(r => r.id === rootId);
    if (!root) throw new NasError('ROOT_DENIED');
    const parts = this.segments(relative);
    const handles: FileHandle[] = [];
    try {
      // Linux/DSM: open each component relative to a pinned directory descriptor.
      // O_NOFOLLOW prevents both final and intermediate symlink substitution.
      if (process.platform === 'linux') {
        let h = await open(root.canonical, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
        handles.push(h);
        for (let i = 0; i < parts.length; i++) {
          const flags = constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK |
            (i < parts.length - 1 || directory ? constants.O_DIRECTORY : 0);
          h = await open(`/proc/self/fd/${h.fd}/${parts[i]}`, flags);
          handles.push(h);
        }
        const stat = await h.stat();
        if (directory ? !stat.isDirectory() : !stat.isFile()) throw new NasError('UNSUPPORTED_FILE');
        return await fn(h, `/proc/self/fd/${h.fd}`);
      }
      // Portable dev fallback. See SECURITY.md for concurrent rename limitations.
      let full = root.canonical;
      for (const p of parts) {
        full = path.join(full, p);
        if ((await lstat(full)).isSymbolicLink()) throw new NasError('PATH_DENIED');
      }
      const resolved = await realpath(full);
      if (resolved !== root.canonical && !resolved.startsWith(root.canonical + path.sep)) throw new NasError('PATH_DENIED');
      const before = await lstat(full);
      const h = await open(full, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
      handles.push(h);
      const stat = await h.stat();
      if (stat.ino !== before.ino || stat.dev !== before.dev ||
          (directory ? !stat.isDirectory() : !stat.isFile())) throw new NasError('PATH_DENIED');
      if (await realpath(full) !== resolved) throw new NasError('PATH_DENIED');
      return await fn(h, full);
    } catch (error) {
      if (error instanceof NasError) throw error;
      throw new NasError('NOT_FOUND_OR_DENIED'); // Never disclose absolute paths or raw OS errors.
    } finally {
      await Promise.all(handles.map(h => h.close()));
    }
  }
  private async entries(rootId: string, relative: string, budget: {remaining: number; deadline: number}, signal?: AbortSignal) {
    return this.withHandle(rootId, relative, true, async (_handle, ref) => {
      const out: Entry[] = [];
      const dir = await opendir(ref);
      try {
        for await (const d of dir) {
          if (signal?.aborted || Date.now() >= budget.deadline || budget.remaining <= 0) break;
          budget.remaining--;
          if (this.denied(d.name) || (!d.isDirectory() && !d.isFile())) continue;
          try {
            const s = await lstat(path.join(ref, d.name));
            if (s.isSymbolicLink() || (!s.isDirectory() && !s.isFile())) continue;
            out.push({rootId, path: relative ? `${relative}/${d.name}` : d.name, name: d.name,
              type: s.isDirectory() ? 'directory' : 'file', size: s.size, modifiedAt: s.mtime.toISOString(),
              readableText: s.isFile() && textExtensions.has(path.extname(d.name).toLowerCase())});
          } catch { /* Concurrent deletion or inaccessible entry: do not disclose it. */ }
        }
      } finally { await dir.close().catch(() => {}); }
      return out;
    });
  }
  async listDirectory(rootId: string, relative = '', limit = 100, signal?: AbortSignal, offset = 0) {
    if (!Number.isInteger(limit) || limit < 1 || limit > 200) throw new NasError('INVALID_LIMIT');
    if (!Number.isInteger(offset) || offset < 0 || offset > this.config.limits.maxEntries) throw new NasError('INVALID_OFFSET');
    const budget = {remaining: this.config.limits.maxEntries, deadline: Date.now() + this.config.limits.timeoutMs};
    const entries = await this.entries(rootId, relative, budget, signal);
    entries.sort((a, b) => a.path.localeCompare(b.path));
    const scanTruncated = budget.remaining <= 0 || Date.now() >= budget.deadline || !!signal?.aborted;
    const nextOffset = entries.length > offset + limit ? offset + limit : null;
    return {entries: entries.slice(offset, offset + limit), offset, nextOffset, scanTruncated,
      truncated: nextOffset !== null || scanTruncated};
  }
  async searchFiles(rootId: string, query: string, limit = 100, signal?: AbortSignal) {
    if (!query.trim() || query.length > 200) throw new NasError('INVALID_QUERY');
    if (!Number.isInteger(limit) || limit < 1 || limit > 200) throw new NasError('INVALID_LIMIT');
    const budget = {remaining: this.config.limits.maxEntries, deadline: Date.now() + this.config.limits.timeoutMs};
    const stack = [{relative: '', depth: 0}];
    const entries: Entry[] = [];
    let truncated = false;
    let skippedDirectories = 0;
    while (stack.length) {
      if (budget.remaining <= 0 || Date.now() >= budget.deadline || signal?.aborted) { truncated = true; break; }
      const current = stack.pop()!;
      let children: Entry[];
      try { children = await this.entries(rootId, current.relative, budget, signal); }
      catch (e) { if (!current.relative) throw e; skippedDirectories++; continue; }
      for (const e of children) {
        if (e.type === 'file' && e.name.toLocaleLowerCase().includes(query.toLocaleLowerCase())) {
          entries.push(e);
          if (entries.length >= limit) return {entries, truncated: true, skippedDirectories};
        }
        if (e.type === 'directory') {
          if (current.depth < this.config.limits.maxDepth) stack.push({relative: e.path, depth: current.depth + 1});
          else truncated = true;
        }
      }
    }
    return {entries, truncated: truncated || budget.remaining <= 0 || Date.now() >= budget.deadline, skippedDirectories};
  }
  async metadata(rootId: string, relative: string, signal?: AbortSignal) {
    if(signal?.aborted)throw new NasError('CANCELLED');
    // Determine type without following links; retry as directory only after a safe file open.
    const inspect = async (h: FileHandle) => {
      const s = await h.stat();
      if(signal?.aborted)throw new NasError('CANCELLED');
      return {rootId, path: relative, type: s.isDirectory() ? 'directory' : 'file', size: s.size,
        modifiedAt: s.mtime.toISOString(), readableText: s.isFile() && textExtensions.has(path.extname(relative).toLowerCase())};
    };
    try { return await this.withHandle(rootId, relative, false, inspect); }
    catch { if(signal?.aborted)throw new NasError('CANCELLED');return this.withHandle(rootId, relative, true, inspect); }
  }
  async readText(rootId: string, relative: string, startLine = 1, maxLines = 200, signal?: AbortSignal) {
    if(signal?.aborted)throw new NasError('CANCELLED');
    if (!Number.isInteger(startLine) || startLine < 1 || !Number.isInteger(maxLines) || maxLines < 1 || maxLines > 500)
      throw new NasError('INVALID_RANGE');
    if (!textExtensions.has(path.extname(relative).toLowerCase())) throw new NasError('UNSUPPORTED_TEXT_FORMAT');
    return this.withHandle(rootId, relative, false, async h => {
      const s = await h.stat();
      if (s.size > this.config.limits.maxReadBytes) throw new NasError('FILE_TOO_LARGE');
      // Read a fixed buffer, including one overflow byte; a growing file cannot allocate unbounded memory.
      const buf = Buffer.alloc(this.config.limits.maxReadBytes + 1);
      let count = 0;
      while (count < buf.length) {
        if(signal?.aborted)throw new NasError('CANCELLED');
        const {bytesRead} = await h.read(buf, count, buf.length - count, count);
        if (!bytesRead) break;
        count += bytesRead;
      }
      if (count > this.config.limits.maxReadBytes) throw new NasError('FILE_TOO_LARGE');
      let text: string;
      try { text = new TextDecoder('utf-8', {fatal: true}).decode(buf.subarray(0, count)); }
      catch { throw new NasError('INVALID_UTF8'); }
      if (/[\x00-\x08\x0b\x0c\x0e-\x1f]/.test(text)) throw new NasError('BINARY_CONTENT');
      const lines = text.split(/\r?\n/);
      if(signal?.aborted)throw new NasError('CANCELLED');
      return {rootId, path: relative, text: lines.slice(startLine - 1, startLine - 1 + maxLines).join('\n'),
        startLine, totalLines: lines.length, truncated: startLine - 1 + maxLines < lines.length,
        trust: 'untrusted-document-content'};
    });
  }
}
