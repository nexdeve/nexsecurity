import crypto from 'node:crypto';

const IV_LENGTH = 12;
const TAG_LENGTH = 16;

function deriveKey(key: string): Buffer {
  return crypto.createHash('sha256').update(key).digest();
}

/** AES-256-GCM encrypt. Returns base64(iv || authTag || ciphertext). */
export function encryptData(data: string, key: string): string {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv('aes-256-gcm', deriveKey(key), iv);
  const encrypted = Buffer.concat([cipher.update(data, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, encrypted]).toString('base64');
}

/** Inverse of encryptData. Throws if the payload was tampered with or the key is wrong. */
export function decryptData(payload: string, key: string): string {
  const buf = Buffer.from(payload, 'base64');
  const iv = buf.subarray(0, IV_LENGTH);
  const tag = buf.subarray(IV_LENGTH, IV_LENGTH + TAG_LENGTH);
  const encrypted = buf.subarray(IV_LENGTH + TAG_LENGTH);
  const decipher = crypto.createDecipheriv('aes-256-gcm', deriveKey(key), iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString('utf8');
}
