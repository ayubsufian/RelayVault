import dotenv from 'dotenv';

dotenv.config({
  path: './.env',
});

const requiredEnvVars = [
  'MONGODB_URI',
  'ACCESS_TOKEN_SECRET',
  'REFRESH_TOKEN_SECRET',
  'BREVO_API_KEY',
  'BREVO_SENDER_EMAIL',
  'CLIENT_URL',
  'GOOGLE_CLIENT_ID',
  'GOOGLE_CLIENT_SECRET',
  'GOOGLE_REDIRECT_URI',
  'MFA_ENCRYPTION_KEY',
  'MFA_REAUTH_SECRET',
  'GOOGLE_MFA_REAUTH_REDIRECT_URI',
  'HANDOFF_ENCRYPTION_KEY',
  'REDIS_URL',
];

const missingEnvVars = requiredEnvVars.filter((name) => !process.env[name]);

if (missingEnvVars.length > 0) {
  throw new Error(
    `Missing required environment variables: ${missingEnvVars.join(', ')}`,
  );
}

if (process.env.ACCESS_TOKEN_SECRET === process.env.REFRESH_TOKEN_SECRET) {
  throw new Error(
    'ACCESS_TOKEN_SECRET and REFRESH_TOKEN_SECRET must be different',
  );
}

export const env = {
  port: process.env.PORT || 8000,
  mongodbUri: process.env.MONGODB_URI,
  accessTokenSecret: process.env.ACCESS_TOKEN_SECRET,
  refreshTokenSecret: process.env.REFRESH_TOKEN_SECRET,
  brevoApiKey: process.env.BREVO_API_KEY,
  brevoSenderEmail: process.env.BREVO_SENDER_EMAIL,
  brevoSenderName: process.env.BREVO_SENDER_NAME || 'RelayVault',
  clientUrl: process.env.CLIENT_URL,
  googleClientId: process.env.GOOGLE_CLIENT_ID,
  googleClientSecret: process.env.GOOGLE_CLIENT_SECRET,
  googleRedirectUri: process.env.GOOGLE_REDIRECT_URI,
  mfaEncryptionKey: process.env.MFA_ENCRYPTION_KEY,
  mfaReauthSecret: process.env.MFA_REAUTH_SECRET,
  googleMfaReauthRedirectUri: process.env.GOOGLE_MFA_REAUTH_REDIRECT_URI,
  handoffEncryptionKey: process.env.HANDOFF_ENCRYPTION_KEY,
  redisUrl: process.env.REDIS_URL,
  trustProxy:
    process.env.TRUST_PROXY === 'true'
      ? true
      : Number(process.env.TRUST_PROXY || 0),
};
