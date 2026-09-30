'use strict';
const notice = document.getElementById('notice');
const form = document.getElementById('folders');
const save = document.getElementById('save');
const preview = document.getElementById('preview');
const root = document.getElementById('root');
let csrf = '', revision = '';
const errors = {
  DSM_ADMIN_REQUIRED:'Open this app while signed in to DSM as an administrator.',
  DSM_LOGIN_REQUIRED:'Your DSM session has ended. Sign in to DSM and open this app again.',
  DSM_BRIDGE_UNAVAILABLE:'The DSM management bridge is unavailable. This preview needs verification on your NAS; no folder permissions were changed.',
  SESSION_EXPIRED:'Your setup session expired. Refresh this page before saving.',
  CONFIGURATION_CHANGED:'Folder settings changed in another session. Refresh this page to see the latest selection.',
  FOLDER_PERMISSION_REQUIRED:'Give the package read-only permission to that folder in DSM, then refresh.',
  FOLDER_UNAVAILABLE:'That folder is no longer available. Refresh and choose again.'
};
async function api(action,body) {
  const response = await fetch(`api.cgi?action=${action}`,{credentials:'same-origin',cache:'no-store',
    ...(body ? {method:'POST',headers:{'Content-Type':'application/json','X-NAS-CSRF':csrf},body:JSON.stringify(body)} : {})});
  let data;
  try {data=await response.json();} catch {throw new Error('The DSM management service did not return a valid response.');}
  if (!response.ok) throw new Error(errors[data.error] || 'Unable to complete this action. No extra folders were enabled.');
  return data;
}
function render(data) {
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
}
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
  csrf=data.csrf; render(data); notice.textContent='DSM administrator verified. Choose the folders you want to enable.';
}).catch(e=>{notice.textContent=e.message;});
