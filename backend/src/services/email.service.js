import { env } from '../config/env.js';

const sendBrevoEmail = async ({ to, subject, textContent, htmlContent }) => {
  const response = await fetch('https://api.brevo.com/v3/smtp/email', {
    method: 'POST',
    headers: {
      accept: 'application/json',
      'api-key': env.brevoApiKey,
      'content-type': 'application/json',
    },
    body: JSON.stringify({
      sender: {
        name: env.brevoSenderName,
        email: env.brevoSenderEmail,
      },
      to: [{ email: to }],
      subject,
      textContent,
      htmlContent,
    }),
  });

  if (!response.ok) {
    const details = await response.text();
    throw new Error(`Brevo email failed: ${details}`);
  }

  const data = await response.json();

  return data.messageId;
};

const sendPasswordResetEmail = async (email, rawToken) => {
  const resetUrl =
    `${env.clientUrl}/reset-password?token=` + encodeURIComponent(rawToken);

  await sendBrevoEmail({
    to: email,
    subject: 'Reset your password',
    textContent: [
      'We received a request to reset your password.',
      '',
      `Reset your password here: ${resetUrl}`,
      '',
      'This link expires in 15 minutes.',
      'If you did not request this, you can ignore this email.',
    ].join('\n'),
    htmlContent: `
          <p>We received a request to reset your password.</p>
          <p>
            <a href="${resetUrl}">Reset your password</a>
          </p>
          <p>This link expires in 15 minutes.</p>
          <p>If you did not request this, you can ignore this email.</p>
        `,
  });
};

const sendVerificationEmail = async (email, rawToken) => {
  const verificationUrl =
    `${env.clientUrl}/verify-email?token=` + encodeURIComponent(rawToken);

  await sendBrevoEmail({
    to: email,
    subject: 'Verify your email address',
    textContent: [
      'Please verify your email address:',
      '',
      verificationUrl,
      '',
      'This link expires in 24 hours.',
    ].join('\n'),
    htmlContent: `<p>Please verify your email address.</p>
          <p>
            <a href="${verificationUrl}">Verify email</a>
          </p>
          <p>This link expires in 24 hours.</p>
        `,
  });
};

const sendMfaChangedEmail = async (email, action) => {
  const actionTextByType = {
    enabled: 'enabled',
    replaced: 'replaced',
    disabled: 'disabled',
    'recovery-codes-regenerated': 'regenerated',
  };

  const actionText = actionTextByType[action];

  if (!actionText) {
    throw new TypeError(`Unsupported MFA action: ${action}`);
  }

  await sendBrevoEmail({
    to: email,
    subject: 'Your MFA settings changed',
    textContent: [
      `MFA was ${actionText} on your account.`,
      '',
      'If you did not make this change, reset your password and contact support immediately.',
    ].join('\n'),
    htmlContent: `
      <p>MFA was <strong>${actionText}</strong> on your account.</p>
      <p>
        If you did not make this change, reset your password and contact
        support immediately.
      </p>
    `,
  });
};

export { sendPasswordResetEmail, sendVerificationEmail, sendMfaChangedEmail };
