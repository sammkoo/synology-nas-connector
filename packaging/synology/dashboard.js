'use strict';
const notice = document.getElementById('notice');
const form = document.getElementById('folders');
const save = document.getElementById('save');
const preview = document.getElementById('preview');
const root = document.getElementById('root');
let csrf = '', revision = '';
let connectionState={state:'not-configured'},polling=false,acting=false,sessionReady=false,connectionVersion=0;
const element=id=>document.getElementById(id);
const errors = {
  DSM_ADMIN_REQUIRED:'Open this app while signed in to DSM as an administrator.',
  DSM_LOGIN_REQUIRED:'Your DSM session has ended. Sign in to DSM and open this app again.',
  DSM_BRIDGE_UNAVAILABLE:'The DSM management bridge is unavailable. This preview needs verification on your NAS; no folder permissions were changed.',
  SESSION_EXPIRED:'Your setup session expired. Refresh this page before saving.',
  CONFIGURATION_CHANGED:'Folder settings changed in another session. Refresh this page to see the latest selection.',
  FOLDER_PERMISSION_REQUIRED:'Give the package read-only permission to that folder in DSM, then refresh.',
  FOLDER_UNAVAILABLE:'That folder is no longer available. Refresh and choose again.',
  GATEWAY_URL_INVALID:'Enter a public HTTPS gateway address without a path, credentials or query.',
  GATEWAY_ADDRESS_DENIED:'The gateway must resolve only to public internet addresses. Local DSM and private addresses are not allowed.',
  GATEWAY_TLS_REQUIRED:'The gateway needs a valid HTTPS certificate. Ask its operator to check the certificate.',
  GATEWAY_DNS_FAILED:'The gateway address could not be found. Check the address and your NAS internet connection.',
  GATEWAY_UNAVAILABLE:'The gateway could not be reached. Check the address and your NAS internet connection.',
  GATEWAY_TIMEOUT:'The gateway did not respond in time. Try again.',
  GATEWAY_REQUEST_DENIED:'The gateway rejected this request. The pairing may have expired; cancel and start again.',
  GATEWAY_RESPONSE_INVALID:'The gateway returned an unexpected response. Check its address and software version.',
  PAIRING_CHANGED:'The pairing changed. Cancel and start again; compare the new number.',
  PAIRING_PROOF_INVALID:'The gateway pairing details did not match this NAS. Cancel and check the gateway address.',
  PAIRING_EXPIRED:'The pairing expired. Start a new pairing.',
  PAIRING_OTHER_ADMIN:'Another DSM administrator started this pairing. Continue in that DSM session.',
  CONNECTION_BUSY:'Another connection action is in progress. Wait and try again.',
  SELECT_FOLDERS_FIRST:'Select and save at least one folder before pairing.',
  DISCONNECT_FIRST:'Disconnect the current NAS connection before starting a new pairing.',
  CONNECTION_RESTORE_FAILED:'The saved connection or private key could not be restored. The NAS has not reconnected. Ask the administrator to check its private connection files.',
  CONNECTION_STORAGE_UNSAFE:'Connection storage permissions are unsafe. Ask the administrator to check the private package directory.',
  CONNECTION_NOT_SAVED:'The connection could not be saved. Check package storage before continuing.',
  DISCONNECT_NOT_PERSISTED:'The NAS is stopped now, but the disconnection could not be saved. Resolve package storage permissions before restarting the service.'
};
async function api(action,body) {
  const response = await fetch(`api.cgi?action=${action}`,{credentials:'same-origin',cache:'no-store',
    ...(body ? {method:'POST',headers:{'Content-Type':'application/json','X-NAS-CSRF':csrf},body:JSON.stringify(body)} : {})});
  let data;
  try {data=await response.json();} catch {throw new Error(`DSM returned HTTP ${response.status} instead of a JSON management response. Ask the package maintainer to check the CGI service.`);}
  if (!response.ok) {
    if(data.error==='SESSION_EXPIRED'){sessionReady=false;save.disabled=true;preview.disabled=true;renderConnection();}
    throw new Error(errors[data.error] || 'Unable to complete this action. No extra folders were enabled.');
  }
  return data;
}
function render(data) {
  connectionVersion++;
  revision=data.revision;
  const shares=document.getElementById('shares'); shares.replaceChildren();
  for(const share of data.shares) {
    const label=document.createElement('label');
    const checkbox=document.createElement('input'); checkbox.type='checkbox'; checkbox.value=share.id;
    checkbox.checked=share.selected; checkbox.disabled=!share.readable&&!share.selected;
    label.append(checkbox,document.createTextNode(` ${share.label}${share.readable?'':' (permission needed)'}`));
    const row=document.createElement('p'); row.append(label); shares.append(row);
  }
  if(!data.shares.length) shares.textContent='No shared folders are available.';
  document.getElementById('permissions').hidden=!data.shares.some(s=>!s.readable);
  root.replaceChildren();
  for(const folder of data.roots) {
    const option=document.createElement('option'); option.value=folder.id; option.textContent=folder.label; root.append(option);
  }
  root.disabled=preview.disabled=!data.roots.length;
  save.disabled=false;
  document.getElementById('entries').replaceChildren();
  renderConnection(data.connection);
}
function renderConnection(data) {
  if(data)connectionState=data;
  const c=connectionState,pending=['pairing','confirmation-required'].includes(c.state),linked=Boolean(c.mcpUrl);
  const labels={'not-configured':'Choose folders first, then pair with a gateway you trust.',pairing:'Waiting for you to open the gateway.',
    'confirmation-required':'Compare the numbers on both pages.',connecting:'Connecting to the gateway…',online:'NAS connected to the gateway.',
    offline:'The gateway connection is offline. The NAS will retry automatically.',stopped:'The NAS connection is stopped.',
    disconnected:'NAS disconnected.',busy:'Another DSM administrator is pairing this NAS.',error:'The connection needs attention.'};
  element('connection').textContent=labels[c.state]||'The connection needs attention.';
  if(c.error)element('connection').textContent+=' '+(errors[c.error]||'Ask the gateway operator to check the connection.');
  element('pairing-form').hidden=pending||['busy','error'].includes(c.state)||(linked&&(c.state!=='disconnected'||c.revocationPending));
  element('pair-begin').disabled=!sessionReady||!root.options.length||acting;
  element('pairing').hidden=!pending;element('connected').hidden=!linked||pending;
  if(pending){element('user-code').textContent=c.userCode;element('verification').href=c.verificationUri;
    element('comparison-panel').hidden=c.state!=='confirmation-required';element('comparison').textContent=c.comparison||'';}
  element('pair-confirm').disabled=element('pair-cancel').disabled=element('pair-disconnect').disabled=acting;
  if(linked){element('connected-label').textContent=`${c.label} · ${c.issuer}`;element('mcp-url').textContent=c.mcpUrl;
    element('chatgpt-instructions').hidden=c.state!=='online';element('remote-revocation').hidden=!c.revocationPending;
    element('pair-disconnect').textContent=c.revocationPending?'Retry gateway revocation':'Disconnect NAS and revoke access';
    element('pair-disconnect').hidden=c.state==='disconnected'&&!c.revocationPending;}
}
async function connectionAction(action,body) {
  if(acting)return;acting=true;connectionVersion++;renderConnection();
  try{renderConnection(await api(action,body));if(['pair-begin','pair-disconnect'].includes(action))element('gateway-consent').checked=false;
    notice.textContent=action==='pair-confirm'?'NAS pairing confirmed. Finish the gateway page to continue.':
    action==='pair-disconnect'?'NAS transmission stopped. See connection status for gateway revocation.':action==='pair-cancel'?'Pairing cancelled.':'Open the gateway and enter the pairing code.';}
  catch(e){notice.textContent=e.message;}finally{acting=false;renderConnection();}
}
element('pairing-form').addEventListener('submit',event=>{event.preventDefault();if(!element('gateway-consent').checked)return;
  void connectionAction('pair-begin',{issuer:element('gateway').value,label:element('nas-label').value,consent:true,revision});});
element('gateway').addEventListener('input',()=>{element('gateway-consent').checked=false;});
element('pair-confirm').addEventListener('click',()=>{const c=connectionState;void connectionAction('pair-confirm',{pairId:c.pairId,proofHash:c.proofHash,comparison:c.comparison});});
element('pair-cancel').addEventListener('click',()=>void connectionAction('pair-cancel',{pairId:connectionState.pairId}));
element('pair-disconnect').addEventListener('click',()=>void connectionAction('pair-disconnect',{}));
setInterval(async()=>{
  if(!sessionReady||polling||acting||document.hidden||!['pairing','confirmation-required','connecting','online','offline','stopped'].includes(connectionState.state))return;
  polling=true;const version=connectionVersion;
  try{const state=await api('pair-status',{});if(version===connectionVersion&&!acting)renderConnection(state);}catch(e){if(version===connectionVersion&&!acting)notice.textContent=e.message;}finally{polling=false;}
},5000);
form.addEventListener('submit',async event=>{
  event.preventDefault(); save.disabled=true;
  try {
    const ids=[...form.querySelectorAll('input:checked')].map(input=>input.value);
    render(await api('roots',{ids,revision}));
    notice.textContent=ids.length?'Folder selection saved. Only these folders are enabled.':'All folder access removed.';
  } catch(e){notice.textContent=e.message; save.disabled=false;}
});
preview.addEventListener('click',async()=>{
  preview.disabled=true;
  try {
    const data=await api('preview',{rootId:root.value});
    const entries=document.getElementById('entries'); entries.replaceChildren();
    for(const entry of data.entries) {const li=document.createElement('li'); li.textContent=entry.name; entries.append(li);}
    notice.textContent=data.entries.length?'Folder access works. Showing up to 10 entries.':'Folder access works. No visible entries.';
  } catch(e){notice.textContent=e.message;} finally{preview.disabled=!root.options.length;}
});
void api('bootstrap').then(data=>{
  csrf=data.csrf; sessionReady=true;render(data); notice.textContent='DSM administrator verified. Choose the folders you want to enable.';
}).catch(e=>{notice.textContent=e.message;});
