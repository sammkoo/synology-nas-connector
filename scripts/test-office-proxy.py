#!/usr/bin/env python3
"""Ephemeral official-image startup/auth smoke; no NAS, user credentials or documents."""
import json
import secrets
import subprocess
import time
import urllib.error
import urllib.request

def run(*args):
    return subprocess.check_output(args, text=True).strip()

container = None
try:
    container = run('docker', 'run', '-d', '--read-only', '--cap-drop=ALL',
        '--security-opt=no-new-privileges:true', '--user', '1000:1000',
        '--pids-limit=64', '--memory=512m', '--cpu-shares=256',
        '--tmpfs', '/tmp:size=64m,mode=1777', '-p', '127.0.0.1::3000',
        '-e', 'AUTH_SECRET='+secrets.token_urlsafe(48), '-e', 'WORKER_TIMEOUT=30000',
        '-e', 'USER_TIMEOUT=30000', 'synology/spreadsheet-api:3.4.1')
    port = run('docker', 'port', container, '3000/tcp').rsplit(':', 1)[1]
    url = 'http://127.0.0.1:'+port+'/spreadsheets/abcdefghijklmnop1234567890ABCDEF'
    for _ in range(60):
        try:
            with urllib.request.urlopen(url, timeout=1) as response:
                raise AssertionError('official Office proxy accepted an unauthenticated document request')
        except urllib.error.HTTPError as response:
            assert response.code == 401, 'unexpected unauthenticated proxy status'
            break
        except OSError:
            time.sleep(0.2)
    else:
        raise AssertionError('hardened official Office proxy did not start')
    manifest = json.loads(run('docker', 'inspect', container))[0]
    assert manifest['Config']['User'] == '1000:1000'
    assert manifest['HostConfig']['ReadonlyRootfs']
    assert manifest['HostConfig']['CapDrop'] == ['ALL']
    assert not manifest['Mounts'] or all(item['Type'] == 'tmpfs' for item in manifest['Mounts'])
    print('Official Spreadsheet 3.4.1 proxy starts without root, rejects unauthenticated access, and has no NAS mounts; native document interoperability is not tested')
finally:
    if container:
        subprocess.run(['docker', 'rm', '-f', container], check=True, stdout=subprocess.DEVNULL)
