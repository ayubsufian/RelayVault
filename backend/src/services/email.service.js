import { env } from '../config/env.js';

const escapeHtml = (value) =>
  String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');

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
  const safeResetUrl = escapeHtml(resetUrl);

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
            <a href="${safeResetUrl}">Reset your password</a>
          </p>
          <p>This link expires in 15 minutes.</p>
          <p>If you did not request this, you can ignore this email.</p>
        `,
  });
};

const sendVerificationEmail = async (email, rawToken) => {
  const verificationUrl =
    `${env.clientUrl}/verify-email?token=` + encodeURIComponent(rawToken);
  const safeVerificationUrl = escapeHtml(verificationUrl);

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
            <a href="${safeVerificationUrl}">Verify email</a>
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

  const safeActionText = escapeHtml(actionText);

  await sendBrevoEmail({
    to: email,
    subject: 'Your MFA settings changed',
    textContent: [
      `MFA was ${actionText} on your account.`,
      '',
      'If you did not make this change, reset your password and contact support immediately.',
    ].join('\n'),
    htmlContent: `
      <p>MFA was <strong>${safeActionText}</strong> on your account.</p>
      <p>
        If you did not make this change, reset your password and contact
        support immediately.
      </p>
    `,
  });
};

const sendHandoffEmail = async (email, { title, redemptionUrl, expiresAt }) => {
  const expiryText = new Date(expiresAt).toISOString();
  const safeTitle = escapeHtml(title);
  const safeRedemptionUrl = escapeHtml(redemptionUrl);
  const safeExpiryText = escapeHtml(expiryText);

  await sendBrevoEmail({
    to: email,
    subject: 'You received a RelayVault handoff',
    textContent: [
      'Someone shared a secure RelayVault handoff with you.',
      '',
      `Title: ${title}`,
      `Open it once here: ${redemptionUrl}`,
      '',
      `This link expires at ${expiryText}.`,
      'Do not forward this link. RelayVault will never ask for your password through this email.',
    ].join('\n'),
    htmlContent: `
      <p>Someone shared a secure RelayVault handoff with you.</p>
      <p><strong>Title:</strong> ${safeTitle}</p>
      <p><a href="${safeRedemptionUrl}">Open the handoff</a></p>
      <p>This link can be used once and expires at ${safeExpiryText}.</p>
      <p>Do not forward this link. RelayVault will never ask for your password through this email.</p>
    `,
  });
};

export {
  sendPasswordResetEmail,
  sendVerificationEmail,
  sendMfaChangedEmail,
  sendHandoffEmail,
};
