import express from 'express';
import { z } from 'zod';
import { NAS_CREATE_SCOPE,NAS_SHARE_SCOPE } from '../../auth/src/index.js';
import { InvalidGrantError } from '@modelcontextprotocol/sdk/server/auth/errors.js';
import { GatewayOAuthProvider } from './oauth.js';
import { DevicePairing } from './pairing.js';
import { GatewaySessions,type BrowserSession } from './sessions.js';

const escape=(value:string)=>value.replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]!));
const secret=z.string().regex(/^[A-Za-z0-9_-]{43}$/);
const requestHandle=z.union([secret,z.literal('')]).optional();
const formBase={csrf:z.string(),request:requestHandle};
const field=(name:string,value:string)=>`<input type="hidden" name="${name}" value="${escape(value)}">`;
const page=(title:string,body:string)=>`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escape(title)} · NAS Connector</title><link rel="stylesheet" href="/connect/style.css"></head><body><main><a class="brand" href="/connect/">NAS Connector</a><p class="eyebrow">YOUR NAS · YOUR PERMISSION</p><h1>${escape(title)}</h1>${body}<footer>Independent open-source project. Explicit folder permissions. Not affiliated with Synology or OpenAI.</footer></main></body></html>`;
const style=`:root{color-scheme:dark;font-family:system-ui,sans-serif;background:#101621;color:#eef1f5}*{box-sizing:border-box}body{margin:0}main{max-width:780px;margin:0 auto;padding:40px 24px}a{color:#a7e4d1}p{line-height:1.6;color:#c6ceda}h1{font-size:32px}h2{font-size:21px}.eyebrow{font-size:12px;letter-spacing:.1em;color:#a7e4d1}.brand{text-decoration:none;font-weight:700}section{border:1px solid #394252;border-radius:16px;background:#1b2332;padding:24px;margin:20px 0}label{display:block;margin:16px 0}input[type=text]{display:block;width:100%;max-width:420px;padding:14px;margin-top:8px;border:1px solid #66728a;border-radius:8px;background:#101621;color:inherit;font:inherit}input[type=checkbox]{width:20px;height:20px;vertical-align:middle;accent-color:#a7e4d1;margin-right:10px}button,.button{display:inline-block;background:#a7e4d1;color:#10251f;padding:13px 20px;border:0;border-radius:8px;font:inherit;font-weight:650;text-decoration:none;cursor:pointer;margin:8px 8px 8px 0}.secondary{background:#303e51;color:#eef1f5}.danger{background:#563239;color:#ffe1e1}.comparison{font-size:44px;letter-spacing:.18em;font-variant-numeric:tabular-nums;color:#a7e4d1;margin:16px 0}code{overflow-wrap:anywhere}footer{margin-top:32px;color:#94a2b8;font-size:12px;line-height:1.6}:focus-visible{outline:3px solid #ecdc9c;outline-offset:4px}@media(max-width:500px){main{padding:24px 18px}section{padding:18px}.comparison{font-size:36px}}`;

/** HTML consent routes. Mount only behind the gateway's TLS/Host guard. */
export function gatewayBrowserRouter(oauth:GatewayOAuthProvider,pairing:DevicePairing,sessions=new GatewaySessions(oauth.store)) {
  const router=express.Router(),origin=new URL(oauth.issuer).origin;
  router.use((req,res,next)=>{
    // no-referrer makes native form POSTs send Origin:null. same-origin keeps
    // exact Origin validation usable while withholding referrers externally.
    res.set({'Cache-Control':'no-store','Referrer-Policy':'same-origin','X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY',
      'Content-Security-Policy':`default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self' ${oauth.callbackOrigins().join(' ')}; base-uri 'none'; frame-ancestors 'none'`});
    next();
  });
  router.get('/style.css',(_req,res)=>{res.type('text/css').send(style);});
  router.use(express.urlencoded({extended:false,limit:'16kb',parameterLimit:40}));
  const csrfFields=(session:BrowserSession,handle='')=>field('csrf',session.csrf)+field('request',handle);
  const continuation=(handle:string)=>handle?`?request=${encodeURIComponent(handle)}`:'';
  function getHandle(req:express.Request) {
    const parsed=requestHandle.safeParse(req.query.request);if(!parsed.success)throw new Error('Invalid request');return parsed.data??'';
  }
  function prepare(req:express.Request,res:express.Response,handle:string) {
    let session=sessions.getOrCreate(req,res);
    if(handle){oauth.inspectAuthorization(handle);session=sessions.bind(session,handle);}return session;
  }
  function checked(req:express.Request,handle:string,csrf:unknown) {
    const session=sessions.read(req);
    if(req.headers.origin!==origin||!session||!sessions.validCsrf(session,csrf)||(handle&&!sessions.bound(session,handle)))throw new Error('Invalid browser confirmation');
    return session;
  }
  router.get('/',(req,res)=>{
    const session=sessions.getOrCreate(req,res);
    const devices=session.subject?oauth.devicesFor(session.subject):[];
    res.type('html').send(page(session.subject?'Your NAS connections':'Connect your NAS',session.subject?
      `<p>You are signed in using a NAS ownership confirmation. Only the folders approved on your NAS can be offered to ChatGPT.</p>${devices.map(d=>`<section><h2>${escape(d.label)}</h2><p>${d.rootIds.length} enabled folder(s). Device pairing is registered; relay availability is checked separately.</p><form method="post" action="/connect/revoke-device">${csrfFields(session)}${field('device',d.id)}<p>Disconnecting revokes this NAS's ChatGPT access. Reconnection requires a fresh confirmation on the NAS.</p><button class="danger">Disconnect NAS</button></form></section>`).join('')}<a class="button" href="/connect/pair">Pair another NAS</a><form method="post" action="/connect/logout">${csrfFields(session)}<button class="secondary">Sign out</button></form>`:
      '<p>Open NAS Connector in DSM and start pairing. Enter the browser code shown there, then compare and confirm the number on both screens.</p><a class="button" href="/connect/pair">Enter NAS pairing code</a><p>No DSM password is sent to this website.</p>'));
  });
  router.get('/pair',(req,res)=>{
    const handle=getHandle(req),session=prepare(req,res,handle);
    let pending:ReturnType<DevicePairing['browserStatus']>|undefined;
    try{pending=pairing.browserStatus(session.id);}catch(e){if(!(e instanceof InvalidGrantError))throw e;}
    if(pending){res.type('html').send(page('Pairing in progress',`<p>A confirmation for ${escape(pending.label)} is already open in this browser.</p><a class="button" href="/connect/confirm${continuation(handle)}">Continue confirmation</a><form method="post" action="/connect/cancel-pair">${csrfFields(session,handle)}<button class="secondary">Cancel pairing and start again</button></form>`));return;}
    res.type('html').send(page('Pair your NAS',`<p>In DSM, open NAS Connector and start pairing. Enter the browser code displayed by your NAS.</p><section><form method="post" action="/connect/pair">${csrfFields(session,handle)}<label>NAS pairing code<input type="text" name="code" autocomplete="off" autocapitalize="characters" spellcheck="false" maxlength="32" required placeholder="16-character code"></label><button>Continue</button></form></section><p>Your DSM password and NAS private key stay on the NAS.</p>`));
  });
  router.post('/pair',(req,res)=>{
    const form=z.object({...formBase,code:z.string().min(1).max(32)}).strict().parse(req.body),handle=form.request??'';
    const session=checked(req,handle,form.csrf);
    pairing.claim(form.code.replace(/[- ]/g,'').toUpperCase(),session.id,session.subject);
    res.redirect(303,`/connect/confirm${continuation(handle)}`);
  });
  router.get('/confirm',(req,res)=>{
    const handle=getHandle(req),session=sessions.read(req);
    if(!session||(handle&&!sessions.bound(session,handle)))throw new Error('Session expired');
    const status=pairing.browserStatus(session.id);
    res.type('html').send(page('Confirm on your NAS',`<p>Connecting <strong>${escape(status.label)}</strong>. Make sure this number matches the number in your DSM window:</p><section><p class="comparison" aria-label="Comparison number">${escape(status.comparison)}</p><p>In DSM, confirm only if both numbers match. If they differ, stop and start a new pairing.</p><form method="post" action="/connect/complete">${csrfFields(session,handle)}<button>${status.approved?'Finish sign-in':'I have confirmed in DSM'}</button></form><form method="post" action="/connect/cancel-pair">${csrfFields(session,handle)}<button class="secondary">Cancel pairing</button></form></section><p>The confirmation expires in ${Math.ceil(status.expiresIn/60)} minute(s).</p>`));
  });
  router.post('/cancel-pair',(req,res)=>{
    const form=z.object(formBase).strict().parse(req.body),handle=form.request??'',session=checked(req,handle,form.csrf);
    pairing.cancelBrowser(session.id);res.redirect(303,`/connect/pair${continuation(handle)}`);
  });
  router.post('/complete',(req,res)=>{
    const form=z.object(formBase).strict().parse(req.body),handle=form.request??'',session=checked(req,handle,form.csrf);
    if(!pairing.browserStatus(session.id).approved){res.status(409).type('html').send(page('Confirm in DSM first',`<p>The NAS has not confirmed this pairing yet. Compare the number in DSM and confirm there before continuing.</p><a class="button" href="/connect/confirm${continuation(handle)}">Return to confirmation</a>`));return;}
    const verified=pairing.completeBrowser(session.id);sessions.rotate(res,session,verified.subject);
    res.redirect(303,handle?`/connect/authorize${continuation(handle)}`:'/connect/');
  });
  router.get('/authorize',(req,res)=>{
    const handle=getHandle(req);if(!handle)throw new Error('Missing authorization');
    const details=oauth.inspectAuthorization(handle),session=prepare(req,res,handle);
    if(!session.subject){res.type('html').send(page('Sign in with your NAS',`<p>A client requests access to your selected NAS folders. Sign in by confirming ownership on your NAS, then review the permissions.</p><a class="button" href="/connect/pair${continuation(handle)}">Sign in using NAS confirmation</a>`));return;}
    const wantsCreate=details.scopes.includes(NAS_CREATE_SCOPE),wantsShare=details.scopes.includes(NAS_SHARE_SCOPE);
    const devices=oauth.devicesFor(session.subject),requested=req.query.device;
    if(requested!==undefined&&typeof requested!=='string')throw new Error('Invalid device');
    const selected=requested?devices.find(d=>d.id===requested):devices.length===1?devices[0]:undefined;
    if(requested&&!selected)throw new Error('Device unavailable');
    res.type('html').send(page('Choose ChatGPT permissions',`<p>Client label: <strong>${escape(details.clientName)}</strong> (provided by the client). Resource: <code>${escape(details.resource)}</code>.</p><p>Selected document contents and file metadata are transmitted to the requesting client through this gateway. The gateway terminates TLS and can process those contents. It does not persist document bodies.</p>${selected?
      `<section><h2>${escape(selected.label)}</h2><p>${wantsCreate?'This request allows reading and creating new text files in every folder selected below. Existing files cannot be overwritten. Only folders enabled for creation in DSM can be selected.':'This request allows reading only.'} ${wantsShare?' This request also permits creating Drive links with existing permissions; it does not enable public access.':''} No folders are selected by default.</p><form method="post" action="/connect/authorize">${csrfFields(session,handle)}${field('device',selected.id)}${selected.roots.filter(r=>(!wantsCreate||r.allowCreate)&&(!wantsShare||r.allowShare)).map(r=>`<label><input type="checkbox" name="roots" value="${escape(r.id)}">${escape(r.label)} (${escape(r.id)})</label>`).join('')}<button name="decision" value="approve">Allow ${wantsCreate?'reading and creating files':wantsShare?'reading and creating Drive links':'read-only access'}</button><button class="secondary" name="decision" value="deny">Cancel</button></form></section>`:
      `<section><h2>Choose a NAS</h2>${devices.map(d=>`<p><a href="/connect/authorize${continuation(handle)}&amp;device=${encodeURIComponent(d.id)}">${escape(d.label)}</a></p>`).join('')||'<p>No NAS is paired with this account.</p>'}</section><a class="button" href="/connect/pair${continuation(handle)}">Pair a NAS</a>`}<p>You can remove folder access in DSM or disconnect your NAS here at any time. Signing out of this website does not revoke a previously approved ChatGPT connection.</p>`));
  });
  router.post('/authorize',(req,res)=>{
    const form=z.object({...formBase,request:secret,device:z.string().uuid(),decision:z.enum(['approve','deny']),roots:z.union([z.string(),z.array(z.string()).max(20)]).optional()}).strict().parse(req.body);
    const session=checked(req,form.request,form.csrf);if(!session.subject)throw new Error('Sign-in required');
    const callback=form.decision==='deny'?oauth.denyAuthorization(form.request):oauth.approveAuthorization(form.request,session.subject,form.device,form.roots===undefined?[]:typeof form.roots==='string'?[form.roots]:form.roots);
    res.redirect(303,callback);
  });
  router.post('/revoke-device',(req,res)=>{
    const form=z.object({...formBase,device:z.string().uuid()}).strict().parse(req.body),session=checked(req,form.request??'',form.csrf);
    if(!session.subject)throw new Error('Sign-in required');oauth.revokeDevice(form.device,session.subject);res.redirect(303,'/connect/');
  });
  router.post('/logout',(req,res)=>{
    const form=z.object(formBase).strict().parse(req.body),session=checked(req,form.request??'',form.csrf);sessions.logout(res,session);res.redirect(303,'/connect/');
  });
  router.use((e:{status?:number},_req:express.Request,res:express.Response,_next:express.NextFunction)=>{
    res.status(e.status===413?413:400).type('html').send(page('Unable to continue','<p>This request could not be confirmed. The session or pairing may have expired. Return to the connection page and start again.</p><a class="button" href="/connect/">Return to connections</a>'));
  });
  return router;
}
