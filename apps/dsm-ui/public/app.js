'use strict';
const form = document.querySelector('#connection');
const message = document.querySelector('#message');
form.addEventListener('submit', async event => {
  event.preventDefault();
  const token = document.querySelector('#token');
  const value = token.value;
  token.value = '';
  message.textContent = 'Checking…';
  try {
    const response = await fetch('/api/status', {headers: {Authorization: `Bearer ${value}`}, cache: 'no-store', signal: AbortSignal.timeout(8000)});
    if (!response.ok) throw new Error(`Service returned HTTP ${response.status}`);
    const status = await response.json();
    message.textContent = `Running · ${status.readOnly?'read only':'explicit write permissions'} · ${status.mode}`;
    const roots = document.querySelector('#roots');
    roots.replaceChildren();
    for (const root of status.roots) {
      const li = document.createElement('li');
      li.textContent = `${root.label} (${root.id})`;
      roots.append(li);
    }
    if (!status.roots.length) {const li = document.createElement('li'); li.textContent = 'No folders exposed.'; roots.append(li);}
  } catch (error) { message.textContent = `${error.message}. Open the connector service dashboard after configuring local access or a reverse proxy.`; }
});
