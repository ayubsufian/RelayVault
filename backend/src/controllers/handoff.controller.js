import {
  createHandoffService,
  getHandoffsService,
  getHandoffService,
  getHandoffDeliveryStatusService,
  updateHandoffService,
  shareHandoffService,
  revokeHandoffService,
  redeemHandoffService,
} from '../services/handoff.service.js';
import HttpError from '../utils/http-error.js';
import getRequestMetadata from '../utils/request-metadata.js';

const requireObjectBody = (body) => {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    throw new HttpError('A JSON object body is required', 400);
  }
};

const createHandoff = async (req, res) => {
  requireObjectBody(req.body);

  const handoff = await createHandoffService({
    ownerId: req.userId,
    title: req.body.title,
    instructions: req.body.instructions,
    recipientEmails: req.body.recipientEmails ?? req.body.recipientEmail,
    expiresAt: req.body.expiresAt,
  });

  return res.status(201).json({
    message: 'Handoff created successfully',
    handoff,
  });
};

const getHandoffs = async (req, res) => {
  const handoffs = await getHandoffsService(req.userId);
  return res.status(200).json({ handoffs });
};

const getHandoff = async (req, res) => {
  const handoff = await getHandoffService(req.userId, req.params.id);
  return res.status(200).json({ handoff });
};

const getHandoffDeliveryStatus = async (req, res) => {
  const delivery = await getHandoffDeliveryStatusService(
    req.userId,
    req.params.id,
  );

  return res.status(200).json({ delivery });
};

const updateHandoff = async (req, res) => {
  requireObjectBody(req.body);

  const allowedFields = [
    'title',
    'instructions',
    'recipientEmails',
    'recipientEmail',
    'expiresAt',
  ];

  const unknownFields = Object.keys(req.body).filter(
    (field) => !allowedFields.includes(field),
  );

  if (req.body.recipientEmail !== undefined && req.body.recipientEmails !== undefined) {
    throw new HttpError('Use recipientEmails instead of recipientEmail', 400);
  }
  if (req.body.recipientEmail !== undefined) {
    req.body.recipientEmails = req.body.recipientEmail;
    delete req.body.recipientEmail;
  }

  if (unknownFields.length > 0) {
    throw new HttpError(`Unsupported update field: ${unknownFields[0]}`, 400);
  }

  const handoff = await updateHandoffService(
    req.userId,
    req.params.id,
    req.body,
  );

  return res.status(200).json({
    message: 'Handoff updated successfully',
    handoff,
  });
};

const shareHandoff = async (req, res) => {
  const handoff = await shareHandoffService(
    req.userId,
    req.params.id,
    getRequestMetadata(req),
  );

  return res.status(200).json({
    message: 'Handoff shared successfully',
    handoff,
  });
};

const revokeHandoff = async (req, res) => {
  const handoff = await revokeHandoffService(
    req.userId,
    req.params.id,
    getRequestMetadata(req),
  );

  return res.status(200).json({
    message: 'Handoff revoked successfully',
    handoff,
  });
};

const redeemHandoff = async (req, res) => {
  const handoff = await redeemHandoffService(
    req.params.token,
    getRequestMetadata(req),
  );

  return res.status(200).set('Cache-Control', 'no-store').json({
    message: 'Handoff redeemed successfully',
    handoff,
  });
};

export {
  createHandoff,
  getHandoffs,
  getHandoff,
  getHandoffDeliveryStatus,
  updateHandoff,
  shareHandoff,
  revokeHandoff,
  redeemHandoff,
};
