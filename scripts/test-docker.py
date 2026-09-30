#!/usr/bin/env python3
"""CI runtime smoke: real container, local auth, MCP read, and an OS read-only mount."""
import json
import os
from pathlib import Path
import secrets
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
