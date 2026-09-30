import { generateKeyPairSync,createPrivateKey,createPublicKey } from 'node:crypto';
import { constants } from 'node:fs';
import { mkdir,lstat,open,realpath } from 'node:fs/promises';
import path from 'node:path';

/** Persistent NAS identity; never expose its private key to DSM/browser/gateway. */
export async function loadOrCreateRelayIdentity(directory:string) {
  await mkdir(directory,{recursive:true,mode:0o700});const stat=await lstat(directory);
  if(!stat.isDirectory()||stat.isSymbolicLink()||stat.uid!==process.getuid?.()||(stat.mode&0o077))throw new Error('Unsafe NAS identity directory');
  const file=path.join(await realpath(directory),'identity.key');
  try{
    const handle=await open(file,constants.O_CREAT|constants.O_EXCL|constants.O_WRONLY|constants.O_NOFOLLOW,0o600);
    try{const key=generateKeyPairSync('ed25519').privateKey.export({type:'pkcs8',format:'pem'});await handle.writeFile(key);await handle.sync();}finally{await handle.close();}
  }catch(e){if((e as NodeJS.ErrnoException).code!=='EEXIST')throw e;}
  const handle=await open(file,constants.O_RDONLY|constants.O_NOFOLLOW);
  try{
    const s=await handle.stat();if(!s.isFile()||s.size>4096||s.uid!==process.getuid?.()||(s.mode&0o077))throw new Error('Unsafe NAS identity file');
    const privateKey=createPrivateKey(await handle.readFile('utf8'));
    if(privateKey.asymmetricKeyType!=='ed25519')throw new Error('Ed25519 NAS identity required');
    const publicKey=createPublicKey(privateKey).export({type:'spki',format:'der'}).toString('base64url');return {privateKey,publicKey};
  }finally{await handle.close();}
}
