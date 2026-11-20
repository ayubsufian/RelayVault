import crypto from 'crypto';
import { env } from '../config/env.js';

const algorithm = 'aes-256-gcm';

const getKey = () => Buffer.from(env.mfaEncryptionKey, 'base64');

const encryptSecret = (value) => {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(algorithm, getKey(), iv);

  const encrypted = Buffer.concat([
    cipher.update(value, 'utf8'),
    cipher.final(),
  ]);

  const tag = cipher.getAuthTag();

  return [
    iv.toString('base64url'),
    tag.toString('base64url'),
    encrypted.toString('base64url'),
  ].join('.');
};

const decryptSecret = (value) => {
  const [ivText, tagText, encryptedText] = value.split('.');

  const decipher = crypto.createDecipheriv(
    algorithm,
    getKey(),
    Buffer.from(ivText, 'base64url'),
  );

  decipher.setAuthTag(Buffer.from(tagText, 'base64url'));

  return Buffer.concat([
    decipher.update(Buffer.from(encryptedText, 'base64url')),
    decipher.final(),
  ]).toString('utf8');
};

export { encryptSecret, decryptSecret };
