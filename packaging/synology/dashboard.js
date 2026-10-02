'use strict';
const notice = document.getElementById('notice');
const form = document.getElementById('folders');
const save = document.getElementById('save');
const preview = document.getElementById('preview');
const root = document.getElementById('root');
let csrf = '', revision = '', dsmToken = '';
let connectionState={state:'not-configured'},polling=false,acting=false,sessionReady=false,connectionVersion=0;
const element=id=>document.getElementById(id);
const errors = {
  DSM_ADMIN_REQUIRED:'Open this app while signed in to DSM as an administrator.',
  DSM_LOGIN_REQUIRED:'Your DSM session has ended. Sign in to DSM and open this app again.',
  DSM_BRIDGE_UNAVAILABLE:'The DSM management bridge is unavailable. This preview needs verification on your NAS; no folder permissions were changed.',
  DSM_AUTH_EXECUTION_FAILED:'DSM session verification could not run. Ask the package maintainer to check the authentication helper (DSM_AUTH_EXECUTION_FAILED).',
  DSM_SESSION_TOKEN_UNAVAILABLE:'DSM could not provide its session protection token. Sign in to DSM and reopen this app. If this continues, report DSM_SESSION_TOKEN_UNAVAILABLE to the package maintainer.',
  DSM_AUTH_SESSION_REJECTED:'DSM did not confirm this session. Sign in to DSM and reopen this app. If this continues, report DSM_AUTH_SESSION_REJECTED to the package maintainer.',
  DSM_AUTH_HELPER_MISSING:'The DSM authentication helper is unavailable (DSM_AUTH_HELPER_MISSING). Ask the package maintainer to check DSM compatibility.',
  DSM_AUTH_HELPER_DENIED:'DSM blocked authentication helper execution (DSM_AUTH_HELPER_DENIED). Ask the package maintainer to check compatibility; do not broaden permissions.',
  DSM_AUTH_HELPER_OUTPUT_LIMIT:'The authentication helper exceeded its output limit (DSM_AUTH_HELPER_OUTPUT_LIMIT). Ask the package maintainer to check compatibility.',
  DSM_AUTH_HELPER_INTERRUPTED:'DSM session verification was interrupted (DSM_AUTH_HELPER_INTERRUPTED). Ask the package maintainer to check compatibility.',
  DSM_GROUP_LOOKUP_FAILED:'DSM administrator membership could not be checked. Ask the package maintainer to check the account lookup (DSM_GROUP_LOOKUP_FAILED).',
  DSM_CONFIG_READ_FAILED:'The management bridge could not read the package configuration (DSM_CONFIG_READ_FAILED). Ask the package maintainer to check the CGI account; do not broaden private file permissions.',
  DSM_SIGNING_KEY_READ_FAILED:'The management bridge could not read its private signing key (DSM_SIGNING_KEY_READ_FAILED). Ask the package maintainer to check the CGI account; do not broaden private file permissions.',
  DSM_LOCAL_SERVICE_UNAVAILABLE:'The management bridge could not reach the local package service (DSM_LOCAL_SERVICE_UNAVAILABLE). Check that the package is running.',
  PRIVATE_SECRET_REQUIRED:'The management key is not safely accessible to the CGI account (PRIVATE_SECRET_REQUIRED). Ask the package maintainer to check package ownership; do not broaden private file permissions.',
  INVALID_MANAGEMENT_SECRET:'The private management key is invalid (INVALID_MANAGEMENT_SECRET). Ask the package maintainer to check preserved package state.',
  MANAGEMENT_UNAVAILABLE:'The local package service is not configured for DSM management (MANAGEMENT_UNAVAILABLE).',
  SESSION_EXPIRED:'Your setup session expired. Refresh this page before saving.',
  CONFIGURATION_CHANGED:'Folder settings changed in another session. Refresh this page to see the latest selection.',
  FOLDER_PERMISSION_REQUIRED:'Give the package read-only permission to that folder in DSM, then refresh.',
  FOLDER_WRITE_PERMISSION_REQUIRED:'Creation needs Read/Write permission for this dedicated folder in DSM. No permissions were changed automatically.',
  DRIVE_LOGIN_FAILED:'Drive sign-in failed. Check the NAS HTTPS address, Drive version and dedicated account. MFA accounts may require a different supported sign-in method.',
  DRIVE_SESSION_REQUIRED:'Connect the dedicated Drive account again; its session is missing or expired.',
  DRIVE_CONFIGURATION_INVALID:'Use the canonical HTTPS origin of your own NAS, without a path, query or credentials.',
  DRIVE_PATH_MISMATCH:'Drive could not verify this file belongs to the selected NAS folder. Enable the same team folder in Drive and check its permissions.',
  DRIVE_RESPONSE_INVALID:'Drive returned a response this version could not verify.',
  DRIVE_UNAVAILABLE:'The Drive API is unavailable. Check the NAS address and certificate.',
  CREATE_REQUIRES_LINUX:'Safe creation is supported on Linux/DSM only.',
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
async function loadDsmToken() {
  try {
    // This same-origin GET and header are documented in Synology's DSM 6 guide.
    // Compatibility with newer DSM must be device-tested. Never put this token
    // in a URL, DOM node, storage, log, gateway request or management signature.
    const response=await fetch('/webman/login.cgi',{credentials:'same-origin',cache:'no-store',redirect:'error',signal:AbortSignal.timeout(3000)});
    if(!response.ok)throw new Error();
    const data=await response.json();
    if(data?.success!==true||data.error||typeof data.SynoToken!=='string'||!/^[\x21-\x7e]{1,512}$/.test(data.SynoToken))throw new Error();
    dsmToken=data.SynoToken;
  } catch {
    dsmToken='';throw new Error(errors.DSM_SESSION_TOKEN_UNAVAILABLE);
  }
}
function endSession() {
  sessionReady=false;csrf='';dsmToken='';element('drive-password').value='';element('drive-connect').disabled=true;save.disabled=true;preview.disabled=true;root.disabled=true;renderConnection();
}
async function api(action,body) {
  if(!dsmToken)throw new Error(errors.DSM_SESSION_TOKEN_UNAVAILABLE);
  const headers={'X-SYNO-TOKEN':dsmToken,...(body?{'Content-Type':'application/json','X-NAS-CSRF':csrf}:{})};
  const response = await fetch(`api.cgi?action=${action}`,{credentials:'same-origin',cache:'no-store',redirect:'error',headers,
    ...(body ? {method:'POST',body:JSON.stringify(body)} : {})});
  if([401,403,419].includes(response.status))endSession();
  let data;
  try {data=await response.json();} catch {throw new Error(`DSM returned HTTP ${response.status} instead of a JSON management response. Ask the package maintainer to check the CGI service.`);}
  // DSM may replace HTTP 5xx bodies with HTML. The CGI preserves those errors
  // in a 200 JSON envelope; an error never establishes a management session.
  if (!response.ok || data.error) {
    if(['SESSION_EXPIRED','DSM_LOGIN_REQUIRED','DSM_ADMIN_REQUIRED','DSM_AUTH_SESSION_REJECTED'].includes(data.error))endSession();
    throw new Error(errors[data.error] || 'Unable to complete this action. No extra folders were enabled.');
  }
  return data;
}
function render(data) {
  connectionVersion++;
  revision=data.revision;
  element('drive-status').textContent=data.driveConfigured?'Drive account configured. Enable links only for selected team folders.':'Drive is not configured.';
  element('drive-connect').disabled=!sessionReady;
  const sharing=element('sharing-settings');sharing.replaceChildren();
  for(const folder of data.roots){
    const row=document.createElement('p'),button=document.createElement('button');button.type='button';
    button.textContent=`${folder.label}: ${folder.allowShare?'Disable Drive links':'Enable Drive links'}`;button.disabled=!sessionReady||!data.driveConfigured;
    button.addEventListener('click',async()=>{
      if(!sessionReady)return;button.disabled=true;
      try{render(await api('sharing',{rootId:folder.id,allowShare:!folder.allowShare,revision}));notice.textContent='Drive-link permission saved. Review nas:share when reconnecting ChatGPT.';}
      catch(e){notice.textContent=e.message;button.disabled=!sessionReady;}
    });row.append(button);sharing.append(row);
  }
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
  const creation=element('creation-settings'); creation.replaceChildren();
  for(const folder of data.roots){
    const share=data.shares.find(s=>s.id===folder.id),row=document.createElement('p'),button=document.createElement('button');
    button.type='button';button.textContent=`${folder.label}: ${folder.allowCreate?'Turn creation off':'Enable creation'}`;
    button.disabled=!sessionReady||(!folder.allowCreate&&(!data.createSupported||!share?.writable));
    button.addEventListener('click',async()=>{
      if(!sessionReady)return;button.disabled=true;
      try{render(await api('creation',{rootId:folder.id,allowCreate:!folder.allowCreate,revision}));notice.textContent='Creation permission saved. Review the new permission when reconnecting ChatGPT.';}
      catch(e){notice.textContent=e.message;button.disabled=!sessionReady;}
    });
    row.append(button);if(!folder.allowCreate&&!share?.writable)row.append(document.createTextNode(' Read/Write permission required in DSM.'));creation.append(row);
  }
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
  element('pair-confirm').disabled=element('pair-cancel').disabled=element('pair-disconnect').disabled=!sessionReady||acting;
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
element('drive-form').addEventListener('submit',async event=>{
  event.preventDefault();if(!sessionReady)return;
  const passwd=element('drive-password').value;element('drive-password').value='';element('drive-connect').disabled=true;
  try{render(await api('drive-connect',{baseUrl:element('drive-url').value,account:element('drive-account').value,passwd,revision}));notice.textContent='Drive connected. Link permissions were reset; enable only the folders you choose.';}
  catch(e){notice.textContent=e.message;}finally{element('drive-connect').disabled=!sessionReady;}
});
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
  } catch(e){notice.textContent=e.message; save.disabled=!sessionReady;}
});
preview.addEventListener('click',async()=>{
  preview.disabled=true;
  try {
    const data=await api('preview',{rootId:root.value});
    const entries=document.getElementById('entries'); entries.replaceChildren();
    for(const entry of data.entries) {const li=document.createElement('li'); li.textContent=entry.name; entries.append(li);}
    notice.textContent=data.entries.length?'Folder access works. Showing up to 10 entries.':'Folder access works. No visible entries.';
  } catch(e){notice.textContent=e.message;} finally{preview.disabled=!sessionReady||!root.options.length;}
});
void loadDsmToken().then(()=>api('bootstrap')).then(data=>{
  csrf=data.csrf; sessionReady=true;render(data); notice.textContent='DSM administrator verified. Choose the folders you want to enable.';
}).catch(e=>{notice.textContent=e.message;});
