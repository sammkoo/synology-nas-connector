import { DatabaseSync } from 'node:sqlite';
import { createHmac } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, mkdir, open, realpath } from 'node:fs/promises';
import path from 'node:path';

/** Gateway-only state. NAS core and DSM bundle do not import SQLite. */
export class GatewayStore {
  private inTransaction=false;
  private constructor(private readonly db: DatabaseSync,private readonly pepper:Buffer,readonly now:()=>number) {
    if(pepper.length!==32)throw new Error('A private 32-byte gateway key is required');
    db.exec(`PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000; PRAGMA synchronous=FULL;
      CREATE TABLE IF NOT EXISTS records (
        kind TEXT NOT NULL, id TEXT NOT NULL, data TEXT NOT NULL, expires INTEGER NOT NULL,
        PRIMARY KEY(kind,id)
      ) STRICT;
      CREATE INDEX IF NOT EXISTS records_expiry ON records(expires);`);
  }
  static async open(directory:string,pepper:Buffer,now:()=>number=Date.now) {
    if(pepper.length!==32)throw new Error('A private 32-byte gateway key is required');
    const absolute=path.resolve(directory);
    await mkdir(absolute,{recursive:true,mode:0o700});
    const s=await lstat(absolute);
    if(!s.isDirectory()||s.isSymbolicLink()||s.uid!==process.getuid?.()||(s.mode&0o077))
      throw new Error('Gateway data directory must be private and owned by the process');
    const canonical=await realpath(absolute);
    const filename=path.join(canonical,'gateway.sqlite');
    const handle=await open(filename,constants.O_RDWR|constants.O_CREAT|constants.O_NOFOLLOW,0o600);
    try {
      const file=await handle.stat();
      if(!file.isFile()||file.uid!==process.getuid?.()||(file.mode&0o077))throw new Error('Unsafe gateway database permissions');
    }finally{await handle.close();}
    const db=new DatabaseSync(filename,{enableForeignKeyConstraints:true,allowExtension:false});
    return new GatewayStore(db,Buffer.from(pepper),now);
  }
  key(kind:string,credential:string) {
    return createHmac('sha256',this.pepper).update(JSON.stringify([kind,credential])).digest('hex');
  }
  get<T>(kind:string,id:string):T|undefined {
    const row=this.db.prepare('SELECT data FROM records WHERE kind=? AND id=? AND expires>?').get(kind,id,this.now());
    return row?JSON.parse(String(row.data)) as T:undefined;
  }
  put(kind:string,id:string,data:unknown,expires:number) {
    if(!Number.isSafeInteger(expires)||expires<=this.now())throw new Error('Invalid record expiration');
    this.db.prepare('INSERT INTO records(kind,id,data,expires) VALUES(?,?,?,?) ON CONFLICT(kind,id) DO UPDATE SET data=excluded.data,expires=excluded.expires')
      .run(kind,id,JSON.stringify(data),expires);
  }
  delete(kind:string,id:string){this.db.prepare('DELETE FROM records WHERE kind=? AND id=?').run(kind,id);}
  count(kind:string){return Number(this.db.prepare('SELECT COUNT(*) AS n FROM records WHERE kind=? AND expires>?').get(kind,this.now())!.n);}
  prune(){this.db.prepare('DELETE FROM records WHERE expires<=?').run(this.now());}
  transaction<T>(operation:()=>T):T {
    if(this.inTransaction)throw new Error('Nested gateway transaction is not supported');
    this.db.exec('BEGIN IMMEDIATE');this.inTransaction=true;
    try{const result=operation();
      if(result&&typeof result==='object'&&'then' in result)throw new Error('Gateway transactions must be synchronous');
      this.db.exec('COMMIT');return result;}
    catch(e){this.db.exec('ROLLBACK');throw e;}
    finally{this.inTransaction=false;}
  }
  close(){this.db.close();this.pepper.fill(0);}
}
