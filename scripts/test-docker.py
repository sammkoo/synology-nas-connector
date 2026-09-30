#!/usr/bin/env python3
"""CI runtime smoke: real container, local auth, MCP read, and an OS read-only mount."""
import json
import os
from pathlib import Path
import secrets
import ssl
import subprocess
import tempfile
import time
import urllib.request

def run(*args):
    return subprocess.check_output(args, text=True).strip()

with tempfile.TemporaryDirectory() as temporary:
    folder = Path(temporary)
    token = secrets.token_urlsafe(32)
    (folder/'token').write_text(token)
    (folder/'token').chmod(0o600)
    (folder/'note.txt').write_text('container sample')
    (folder/'config.json').write_text(json.dumps({
        'roots':[{'id':'docs','label':'Docs','path':'/data'}],
        'http':{'host':'0.0.0.0','allowedHosts':['127.0.0.1'],'tokenFile':'token'}
    }))
    container = run('docker','run','-d','--read-only','--cap-drop=ALL','--security-opt=no-new-privileges:true',
        '--user',f'{os.getuid()}:{os.getgid()}', '-p','127.0.0.1::8787',
        '-v',f'{folder}:/config:ro','-v',f'{folder}:/data:ro','nas-connector:ci')
    try:
        port = run('docker','port',container,'8787/tcp').rsplit(':',1)[1]
        base = f'http://127.0.0.1:{port}'
        for _ in range(30):
            try:
                with urllib.request.urlopen(base+'/healthz',timeout=1) as res:
                    assert res.status == 200
                break
            except OSError: time.sleep(0.2)
        else: raise AssertionError('container failed to start')
        req = urllib.request.Request(base+'/mcp', data=json.dumps({
            'jsonrpc':'2.0','id':1,'method':'tools/call',
            'params':{'name':'read_text','arguments':{'rootId':'docs','path':'note.txt'}}
        }).encode(), headers={'Authorization':'Bearer '+token,'Content-Type':'application/json',
            'Accept':'application/json, text/event-stream','MCP-Protocol-Version':'2025-03-26'})
        with urllib.request.urlopen(req,timeout=10) as res:
            assert 'container sample' in res.read().decode()
        write = subprocess.run(['docker','exec',container,'node','-e',
            "require('fs').writeFileSync('/data/attempt.txt','must fail')"],capture_output=True)
        assert write.returncode != 0 and not (folder/'attempt.txt').exists()
        print('Docker HTTP/MCP smoke and read-only mount verified')
    finally:
        subprocess.run(['docker','rm','-f',container],check=True,stdout=subprocess.DEVNULL)

# Exercise the actual gateway image and its shipped CLI, not a fixture server.
run('docker','build','--target','gateway','-t','nas-gateway:ci','.')
with tempfile.TemporaryDirectory() as temporary:
    folder = Path(temporary)
    user = f'{os.getuid()}:{os.getgid()}'
    run('docker','run','--rm','--network=none','--read-only','--cap-drop=ALL',
        '--security-opt=no-new-privileges:true','--user',user,'-v',f'{folder}:/config',
        'nas-gateway:ci','node','dist/gateway.cjs','--init','--config','/config/config.json',
        '--issuer','https://localhost:8788/','--callback','https://client.example/callback')
    cert, key = folder/'tls/cert.pem', folder/'tls/key.pem'
    subprocess.run(['openssl','req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:prime256v1',
        '-nodes','-days','2','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost,IP:127.0.0.1',
        '-keyout',str(key),'-out',str(cert)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    config = json.loads((folder/'config.json').read_text())
    config['transport']['host'] = '0.0.0.0'
    (folder/'config.json').write_text(json.dumps(config))
    original_key = (folder/'state/auth.key').read_bytes()
    context = ssl.create_default_context(cafile=str(cert))
    container = run('docker','run','-d','--read-only','--cap-drop=ALL',
        '--security-opt=no-new-privileges:true','--user',user,'--pids-limit=64','--memory=512m',
        '-p','127.0.0.1::8788','--env','NODE_EXTRA_CA_CERTS=/config/tls/cert.pem',
        '-v',f'{folder}/config.json:/config/config.json:ro','-v',f'{folder}/tls:/config/tls:ro',
        '-v',f'{folder}/state:/config/state','nas-gateway:ci')
    try:
        port = run('docker','port',container,'8788/tcp').rsplit(':',1)[1]
        base = f'https://127.0.0.1:{port}'
        def gateway_request(route, body=None):
            headers = {'Host':'localhost:8788'}
            if body is not None: headers.update({'Content-Type':'application/json','Accept':'application/json, text/event-stream'})
            req = urllib.request.Request(base+route, data=None if body is None else json.dumps(body).encode(), headers=headers)
            with urllib.request.urlopen(req,context=context,timeout=3) as response:
                return json.loads(response.read().decode())
        def ready():
            for _ in range(40):
                try:
                    assert gateway_request('/health') == {'status':'ready','relay':'attached'}
                    return
                except OSError: time.sleep(0.2)
            raise AssertionError('gateway container failed to start')
        ready()
        run('docker','exec',container,'node','dist/gateway.cjs','--healthcheck')
        metadata = gateway_request('/.well-known/oauth-protected-resource/mcp')
        assert metadata['resource'] == 'https://localhost:8788/mcp'
        catalog = gateway_request('/mcp',{'jsonrpc':'2.0','id':1,'method':'tools/list'})
        assert len(catalog['result']['tools']) == 5
        assert all(tool['securitySchemes'] == [{'type':'oauth2','scopes':['nas:read']}] for tool in catalog['result']['tools'])
        denied = gateway_request('/mcp',{'jsonrpc':'2.0','id':2,'method':'tools/call','params':{'name':'list_roots'}})['result']
        assert denied['isError'] and denied['_meta']['mcp/www_authenticate']
        write = subprocess.run(['docker','exec',container,'node','-e',
            "require('fs').writeFileSync('/config/config.json','must fail')"],capture_output=True)
        assert write.returncode != 0
        run('docker','restart',container)
        ready()
        assert (folder/'state/auth.key').read_bytes() == original_key
        run('docker','exec',container,'node','dist/gateway.cjs','--healthcheck')
        print('Gateway Docker TLS, OAuth metadata/catalog, read-only config, private writable state and restart verified')
    finally:
        subprocess.run(['docker','rm','-f',container],check=True,stdout=subprocess.DEVNULL)
