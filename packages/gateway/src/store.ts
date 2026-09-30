import { DatabaseSync } from 'node:sqlite';
import { createHmac } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, mkdir, open, realpath } from 'node:fs/promises';
import path from 'node:path';

/** Gateway-only state. NAS core and DSM bundle do not import SQLite. */
export class GatewayStore {
  private inTransaction=false;
  private constructor(private readonly db: DatabaseSync,private readonly pepper:Buffer,readonly now:()=>number,options:{exclusive?:boolean;maxDatabaseBytes?:number}) {
    if(pepper.length!==32)throw new Error('A private 32-byte gateway key is required');
    db.exec(`PRAGMA foreign_keys=ON; PRAGMA busy_timeout=${options.exclusive?500:5000}; PRAGMA synchronous=FULL; PRAGMA trusted_schema=OFF;`);
    // Holding the SQLite lock avoids two gateways with independent relay/session
    // state sharing one database. The OS releases it after a crash too.
    if(options.exclusive)db.exec('PRAGMA locking_mode=EXCLUSIVE; BEGIN EXCLUSIVE; COMMIT;');
    if(options.maxDatabaseBytes!==undefined){
      if(!Number.isSafeInteger(options.maxDatabaseBytes)||options.maxDatabaseBytes<65536)throw new Error('Invalid database budget');
      const pageSize=Number(db.prepare('PRAGMA page_size').get()!.page_size),pages=Math.floor(options.maxDatabaseBytes/pageSize);
      const actual=Number(db.prepare(`PRAGMA max_page_count=${pages}`).get()!.max_page_count);
      if(actual>pages)throw new Error('Existing database exceeds the configured budget');
      db.exec('PRAGMA journal_size_limit=0;');
    }
    db.exec(`
      CREATE TABLE IF NOT EXISTS records (
        kind TEXT NOT NULL, id TEXT NOT NULL, data TEXT NOT NULL, expires INTEGER NOT NULL,
        PRIMARY KEY(kind,id)
      ) STRICT;
      CREATE INDEX IF NOT EXISTS records_expiry ON records(expires);`);
  }
  static async open(directory:string,pepper:Buffer,now:()=>number=Date.now,options:{exclusive?:boolean;maxDatabaseBytes?:number;create?:boolean}={}) {
    if(pepper.length!==32)throw new Error('A private 32-byte gateway key is required');
    const absolute=path.resolve(directory);
    await mkdir(absolute,{recursive:true,mode:0o700});
    const s=await lstat(absolute);
    if(!s.isDirectory()||s.isSymbolicLink()||s.uid!==process.getuid?.()||(s.mode&0o077))
      throw new Error('Gateway data directory must be private and owned by the process');
    const canonical=await realpath(absolute);
    const filename=path.join(canonical,'gateway.sqlite');
    const handle=await open(filename,constants.O_RDWR|(options.create===false?0:constants.O_CREAT)|constants.O_NOFOLLOW|constants.O_NONBLOCK,0o600);
    try {
      const file=await handle.stat();
      if(!file.isFile()||file.uid!==process.getuid?.()||(file.mode&0o077))throw new Error('Unsafe gateway database permissions');
    }finally{await handle.close();}
    const db=new DatabaseSync(filename,{enableForeignKeyConstraints:true,allowExtension:false});
    try{return new GatewayStore(db,Buffer.from(pepper),now,options);}catch(e){db.close();throw e;}
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
  list<T>(kind:string,limit:number):{id:string;data:T}[] {
    if(!Number.isInteger(limit)||limit<1||limit>10000)throw new Error('Invalid record limit');
    return this.db.prepare('SELECT id,data FROM records WHERE kind=? AND expires>? ORDER BY id LIMIT ?').all(kind,this.now(),limit)
      .map(row=>({id:String(row.id),data:JSON.parse(String(row.data)) as T}));
  }
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
