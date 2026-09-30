import { randomBytes,timingSafeEqual } from 'node:crypto';
import type { Request,Response } from 'express';
import { GatewayStore } from './store.js';

export const SESSION_COOKIE='__Host-nas_session';
type Record={subject?:string;authorizationKey?:string;expires:number};
export type BrowserSession=Record&{id:string;csrf:string};
const idPattern=/^[A-Za-z0-9_-]{43}$/;

/** Private durable first-party sessions. Never adopt identity from headers/query/body. */
export class GatewaySessions {
  constructor(private readonly store:GatewayStore) {}
  private readId(req:Request) {
    const cookies=(req.headers.cookie??'').split(';').map(x=>x.trim()).filter(x=>x.startsWith(`${SESSION_COOKIE}=`));
    if(cookies.length!==1)return undefined;
    const id=cookies[0]!.slice(SESSION_COOKIE.length+1);return idPattern.test(id)?id:undefined;
  }
  read(req:Request):BrowserSession|undefined {
    const id=this.readId(req);if(!id)return undefined;
    const record=this.store.get<Record>('browser-session',this.store.key('browser-session',id));
    return record?{...record,id,csrf:this.store.key('browser-csrf',id)}:undefined;
  }
  private cookie(res:Response,id:string,seconds:number) {
    res.append('Set-Cookie',`${SESSION_COOKIE}=${id}; Path=/; Max-Age=${seconds}; HttpOnly; Secure; SameSite=Lax`);
  }
  private create(res:Response,subject?:string,authorizationKey?:string):BrowserSession {
    this.store.prune();if(this.store.count('browser-session')>=10000)throw new Error('Session capacity reached');
    const id=randomBytes(32).toString('base64url'),seconds=subject?12*3600:1800;
    const record:Record={...(subject?{subject}:{}),...(authorizationKey?{authorizationKey}:{}),expires:this.store.now()+seconds*1000};
    this.store.put('browser-session',this.store.key('browser-session',id),record,record.expires);this.cookie(res,id,seconds);
    return {...record,id,csrf:this.store.key('browser-csrf',id)};
  }
  getOrCreate(req:Request,res:Response){return this.read(req)??this.create(res);}
  bind(session:BrowserSession,handle:string) {
    const authorizationKey=this.store.key('browser-authorization',handle);
    const record:Record={...(session.subject?{subject:session.subject}:{}),authorizationKey,expires:session.expires};
    this.store.put('browser-session',this.store.key('browser-session',session.id),record,record.expires);
    return {...session,authorizationKey};
  }
  bound(session:BrowserSession,handle:string) {return session.authorizationKey===this.store.key('browser-authorization',handle);}
  validCsrf(session:BrowserSession,submitted:unknown) {
    return typeof submitted==='string'&&/^[a-f0-9]{64}$/.test(submitted)&&timingSafeEqual(Buffer.from(session.csrf),Buffer.from(submitted));
  }
  /** Call only after one-time NAS proof completion, never with a submitted subject. */
  rotate(res:Response,session:BrowserSession,verifiedSubject:string) {
    if(!verifiedSubject||verifiedSubject.length>256)throw new Error('Invalid verified account');
    return this.store.transaction(()=>{
      this.store.delete('browser-session',this.store.key('browser-session',session.id));
      return this.create(res,verifiedSubject,session.authorizationKey);
    });
  }
  logout(res:Response,session:BrowserSession) {
    this.store.delete('browser-session',this.store.key('browser-session',session.id));this.cookie(res,'',0);
  }
}
