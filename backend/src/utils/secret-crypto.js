import crypto from 'crypto';
import { env } from '../config/env.js';

const ALGORITHM = 'aes-256-gcm';

const getKey = () => {
  const key = Buffer.from(env.handoffEncryptionKey, 'base64');

  if (key.length !== 32) {
    throw new Error('HANDOFF_ENCRYPTION_KEY must decode to 32 bytes');
  }

  return key;
};

export const encryptHandoff = (plaintext) => {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(ALGORITHM, getKey(), iv);

  const encrypted = Buffer.concat([
    cipher.update(plaintext, 'utf8'),
    cipher.final(),
  ]);

  const authTag = cipher.getAuthTag();

  return [
    iv.toString('base64url'),
    authTag.toString('base64url'),
    encrypted.toString('base64url'),
  ].join('.');
};

export const decryptHandoff = (payload) => {
  const [ivEncoded, authTagEncoded, encryptedEncoded] = payload.split('.');

  const decipher = crypto.createDecipheriv(
    ALGORITHM,
    getKey(),
    Buffer.from(ivEncoded, 'base64url'),
  );

  decipher.setAuthTag(Buffer.from(authTagEncoded, 'base64url'));

  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(encryptedEncoded, 'base64url')),
    decipher.final(),
  ]);

  return decrypted.toString('utf8');
};
