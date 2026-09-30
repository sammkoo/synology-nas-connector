import { test, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, symlink, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { NasFiles, configSchema } from '../packages/core/src/index.js';
let dir: string, files: NasFiles;
beforeEach(async () => {
  dir = await mkdtemp(path.join(tmpdir(), 'nas-test-'));
  await mkdir(path.join(dir, 'root'));
  await mkdir(path.join(dir, 'root/sub'));
  await writeFile(path.join(dir, 'root/hello.md'), 'first\nsecond\nthird');
  await writeFile(path.join(dir, 'root/sub/REPORT.txt'), 'report');
  await writeFile(path.join(dir, 'outside.txt'), 'outside secret');
  await writeFile(path.join(dir, 'root/.env'), 'secret');
  await writeFile(path.join(dir, 'root/private.pem'), 'secret');
  await mkdir(path.join(dir, 'root/@eaDir'));
  await symlink(path.join(dir, 'outside.txt'), path.join(dir, 'root/link.txt'));
  await symlink(dir, path.join(dir, 'root/escape'));
  files = await NasFiles.create(configSchema.parse({roots: [{id: 'docs', path: path.join(dir, 'root'), label: 'Docs'}], http: {tokenFile: 'unused'}}));
});
afterEach(async () => {await rm(dir, {recursive: true, force: true});});
test('roots and listing expose aliases without private paths, hidden entries or symlinks', async () => {
  assert.deepEqual(files.listRoots(), [{id: 'docs', label: 'Docs'}]);
  const result = await files.listDirectory('docs');
  assert.deepEqual(result.entries.map(e => e.name), ['hello.md', 'sub']);
  assert.ok(!JSON.stringify(result).includes(dir));
});
test('case insensitive recursive filename search and line ranges', async () => {
  assert.equal((await files.searchFiles('docs', 'report')).entries[0]?.path, 'sub/REPORT.txt');
  const text = await files.readText('docs', 'hello.md', 2, 1);
  assert.equal(text.text, 'second');
  assert.equal(text.truncated, true);
  assert.equal(text.trust, 'untrusted-document-content');
  assert.equal((await files.metadata('docs', 'sub')).type, 'directory');
});
test('directory pagination exposes continuation without bypassing scan policy', async () => {
  const first = await files.listDirectory('docs', '', 1);
  assert.equal(first.nextOffset, 1);
  assert.equal(first.scanTruncated, false);
  const second = await files.listDirectory('docs', '', 1, undefined, first.nextOffset!);
  assert.equal(second.entries[0]?.path, 'sub');
  assert.equal(second.nextOffset, null);
  await assert.rejects(files.listDirectory('docs', '', 100, undefined, -1), /INVALID_OFFSET/);
});
test('reject traversal, absolute paths, empty components, secret files and root escapes', async () => {
  for (const p of ['../outside.txt', '/etc/passwd', 'sub/../../outside.txt', 'sub//x', './hello.md', '.env', 'private.pem', '@eaDir/x', 'link.txt', 'escape/outside.txt', 'sub\\x', 'x\0.txt']) {
    await assert.rejects(files.metadata('docs', p), /DENIED/);
  }
  await assert.rejects(files.readText('unknown', 'hello.md'), /ROOT_DENIED/);
});
test('reject binary, invalid UTF-8, unsupported Office formats and oversized files', async () => {
  await writeFile(path.join(dir, 'root/binary.txt'), Buffer.from([0, 1, 2]));
  await writeFile(path.join(dir, 'root/invalid.txt'), Buffer.from([0xff]));
  await writeFile(path.join(dir, 'root/large.txt'), Buffer.alloc(262145, 65));
  await assert.rejects(files.readText('docs', 'binary.txt'), /BINARY_CONTENT/);
  await assert.rejects(files.readText('docs', 'invalid.txt'), /INVALID_UTF8/);
  await assert.rejects(files.readText('docs', 'file.docx'), /UNSUPPORTED_TEXT_FORMAT/);
  await assert.rejects(files.readText('docs', 'large.txt'), /FILE_TOO_LARGE/);
});
test('bounded scans, depth and cancellation report partial coverage', async () => {
  const bounded = await NasFiles.create(configSchema.parse({roots: [{id: 'docs', path: path.join(dir, 'root'), label: 'Docs'}], http: {tokenFile: 'unused'}, limits: {maxEntries: 1}}));
  assert.equal((await bounded.listDirectory('docs')).truncated, true);
  assert.equal((await bounded.searchFiles('docs', 'hello')).truncated, true);
  const signal = AbortSignal.abort();
  assert.equal((await files.searchFiles('docs', 'report', 100, signal)).truncated, true);
});
test('configuration fails closed and rejects duplicate roots, unknown options and filesystem root', async () => {
  assert.throws(() => configSchema.parse({roots: [], http: {tokenFile: 'unused'}, writable: true}));
  assert.throws(() => configSchema.parse({roots: [{id:'same',path:'/a',label:'a'},{id:'same',path:'/b',label:'b'}], http:{tokenFile:'x'}}));
  await assert.rejects(NasFiles.create(configSchema.parse({roots: [{id:'root',path:'/',label:'root'}], http:{tokenFile:'x'}})), /FILESYSTEM_ROOT_FORBIDDEN/);
});
