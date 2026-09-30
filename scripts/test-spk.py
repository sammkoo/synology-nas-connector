#!/usr/bin/env python3
"""Validate container, permissions, checksum, payload, shell syntax and reproducibility."""
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
spk = ROOT/'artifacts/SynologyNASConnector-0.1.0-0002-noarch.spk'
original = spk.read_bytes()
with tarfile.open(spk) as tar:
    names = set(tar.getnames())
    assert {'INFO','package.tgz','conf/privilege','PACKAGE_ICON.PNG','PACKAGE_ICON_256.PNG','scripts/start-stop-status'} <= names
    assert json.loads(tar.extractfile('conf/privilege').read()) == {'defaults': {'run-as':'package'}}
    info = tar.extractfile('INFO').read().decode()
    data = tar.extractfile('package.tgz').read()
    assert f'checksum="{hashlib.md5(data).hexdigest()}"' in info
    assert 'arch="noarch"' in info and 'install_dep_packages="Node.js_v22"' in info
    for member in tar.getmembers():
        assert not member.name.startswith('/') and '..' not in Path(member.name).parts
        if member.name.startswith('scripts/'):
            assert member.mode == 0o755
            with tempfile.NamedTemporaryFile() as f:
                f.write(tar.extractfile(member).read()); f.flush()
                subprocess.run(['sh','-n',f.name],check=True)
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as payload:
        assert {'server.cjs','dsm-bridge.cjs','ui/index.html','dsm/index.html','dsm/app.js','dsm/api.cgi','dsm/config','bin/init-config.mjs','bin/enable-management.mjs','THIRD_PARTY_NOTICES.txt'} <= set(payload.getnames())
        assert payload.getmember('dsm/api.cgi').mode == 0o755
        assert not any('node_modules' in n or n.endswith('.node') for n in payload.getnames())
        cfg = json.loads(payload.extractfile('dsm/config').read())
        assert cfg['.url']['org.nasconnector.dashboard']['allUsers'] is False
        assert cfg['.url']['org.nasconnector.dashboard']['url'] == '/webman/3rdparty/SynologyNASConnector/index.html'
subprocess.run(['python3',str(ROOT/'scripts/build-spk.py')],check=True,cwd=ROOT)
assert spk.read_bytes() == original, 'SPK must be reproducible with the same inputs'
print('SPK structure, scripts, privileges, checksum and reproducibility verified')
