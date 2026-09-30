#!/usr/bin/env python3
"""Build a deterministic, architecture-independent DSM 7 package; no native code."""
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import struct
import tarfile
import zlib

ROOT = Path(__file__).resolve().parents[1]
META = ROOT / 'packaging/synology'
EPOCH = int(os.environ.get('SOURCE_DATE_EPOCH', '0'))

def add(tar, name, data, mode=0o644):
    info = tarfile.TarInfo(name)
    info.size, info.mode, info.mtime = len(data), mode, EPOCH
    info.uid = info.gid = 0
    info.uname = info.gname = ''
    tar.addfile(info, io.BytesIO(data))

def icon(size):
    # Deterministic original folder glyph, generated with the standard library.
    pixels = bytearray()
    for y in range(size):
        pixels.append(0)
        for x in range(size):
            folder = (size//5 <= x < 4*size//5 and 2*size//5 <= y < 3*size//4) or (size//5 <= x < size//2 and size//3 <= y < size//2)
            pixels.extend((142, 225, 198, 255) if folder else (25, 35, 52, 255))
    def chunk(kind, data):
        return struct.pack('!I', len(data)) + kind + data + struct.pack('!I', zlib.crc32(kind + data) & 0xffffffff)
    return b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('!2I5B', size, size, 8, 6, 0, 0, 0)) + chunk(b'IDAT', zlib.compress(bytes(pixels))) + chunk(b'IEND', b'')

def main():
    if not (ROOT/'dist/server.cjs').is_file():
        raise SystemExit('Run npm run build first')
    payload = io.BytesIO()
    with tarfile.open(fileobj=payload, mode='w', format=tarfile.USTAR_FORMAT) as tar:
        add(tar, 'server.cjs', (ROOT/'dist/server.cjs').read_bytes())
        add(tar, 'dsm-bridge.cjs', (ROOT/'dist/dsm-bridge.cjs').read_bytes())
        for p in sorted((ROOT/'dist/ui').rglob('*')):
            if p.is_file(): add(tar, 'ui/' + p.relative_to(ROOT/'dist/ui').as_posix(), p.read_bytes())
        add(tar, 'dsm/config', (META/'ui-config.json').read_bytes())
        add(tar, 'dsm/index.html', (META/'dashboard.html').read_bytes())
        add(tar, 'dsm/app.js', (META/'dashboard.js').read_bytes())
        add(tar, 'dsm/api.cgi', (META/'api.cgi').read_bytes(),0o755)
        add(tar, 'dsm/style.css', (META/'dashboard.css').read_bytes())
        for size in (16, 24, 32, 48, 64, 72, 128, 256):
            add(tar, f'dsm/images/app_{size}.png', icon(size))
        add(tar, 'bin/init-config.mjs', (ROOT/'scripts/init-config.mjs').read_bytes())
        add(tar, 'bin/enable-management.mjs', (ROOT/'scripts/enable-management.mjs').read_bytes())
        for name in ('node-runtime', 'postinst'):
            add(tar, 'bin/'+name, (META/'scripts'/name).read_bytes(), 0o755)
        add(tar, 'LICENSE', (ROOT/'LICENSE').read_bytes())
        add(tar, 'THIRD_PARTY_NOTICES.txt', (ROOT/'dist/THIRD_PARTY_NOTICES.txt').read_bytes())
    compressed = io.BytesIO()
    with gzip.GzipFile(fileobj=compressed, mode='wb', mtime=EPOCH, filename='') as gz:
        gz.write(payload.getvalue())
    out = ROOT/'artifacts'
    out.mkdir(exist_ok=True)
    package = out/'SynologyNASConnector-0.1.0-0003-noarch.spk'
    with tarfile.open(package, 'w', format=tarfile.USTAR_FORMAT) as tar:
        info = (META/'INFO').read_text()
        info += f'checksum="{hashlib.md5(compressed.getvalue()).hexdigest()}"\n'
        add(tar, 'INFO', info.encode())
        add(tar, 'package.tgz', compressed.getvalue())
        add(tar, 'LICENSE', (ROOT/'LICENSE').read_bytes())
        for size, name in ((64,'PACKAGE_ICON.PNG'), (256,'PACKAGE_ICON_256.PNG')):
            add(tar, name, icon(size))
        add(tar, 'conf/privilege', (META/'conf/privilege').read_bytes())
        for name in ('preinst','preuninst','postuninst','preupgrade'):
            add(tar, 'scripts/'+name, b'#!/bin/sh\nexit 0\n', 0o755)
        for name in ('postinst','postupgrade','start-stop-status'):
            add(tar, 'scripts/'+name, (META/'scripts'/name).read_bytes(), 0o755)
    digest = hashlib.sha256(package.read_bytes()).hexdigest()
    (out/(package.name+'.sha256')).write_text(f'{digest}  {package.name}\n')
    print(f'Built {package.name} ({package.stat().st_size} bytes), SHA-256 {digest}')

if __name__ == '__main__': main()
