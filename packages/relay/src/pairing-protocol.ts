import { z } from 'zod';
const secret=z.string().regex(/^[A-Za-z0-9_-]{43}$/),publicKey=z.string().regex(/^[A-Za-z0-9_-]{59}$/);
const rootIds=z.array(z.string().regex(/^[A-Za-z0-9_-]{1,40}$/)).max(20).refine(ids=>new Set(ids).size===ids.length);
export const pairingProofSchema=z.object({issuer:z.string().url(),publicKey,label:z.string().min(1).max(100),rootIds,challenge:secret,
  browserKey:z.string().regex(/^[a-f0-9]{64}$/),comparison:z.string().regex(/^\d{6}$/)}).strict();
export type PairingProof=z.infer<typeof pairingProofSchema>;
/** Shared byte contract; importing it on the NAS never imports gateway SQLite. */
export function pairingApprovalMessage(proof:PairingProof) {
  return Buffer.from(JSON.stringify(['nas-pairing-v1',proof.issuer,proof.publicKey,proof.label,[...proof.rootIds].sort(),proof.challenge,proof.browserKey,proof.comparison]));
}
export const pairingBeginSchema=z.object({deviceCode:secret,userCode:z.string().regex(/^[0-9A-F]{16}$/),expiresIn:z.number().int().min(1).max(600),verificationUri:z.string().url()}).strict();
export const pairingPollSchema=z.discriminatedUnion('state',[
  z.object({state:z.literal('waiting-for-browser')}).strict(),
  pairingProofSchema.extend({state:z.literal('confirmation-required')}).strict(),
  z.object({state:z.literal('approved'),deviceId:z.string().uuid()}).strict()
]);
export const deviceRevocationSchema=z.object({publicKey,deviceId:z.string().uuid(),timestamp:z.number().int().positive().safe(),nonce:secret,signature:z.string().regex(/^[A-Za-z0-9_-]{86}$/)}).strict();
export type DeviceRevocation=z.infer<typeof deviceRevocationSchema>;
export function deviceRevocationMessage(issuer:string,request:Omit<DeviceRevocation,'signature'>) {
  return Buffer.from(JSON.stringify(['nas-device-revoke-v1',issuer,request.publicKey,request.deviceId,request.timestamp,request.nonce]));
}
