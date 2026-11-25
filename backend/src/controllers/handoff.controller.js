import {
  createHandoffService,
  getHandoffsService,
  getHandoffService,
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
    recipientEmail: req.body.recipientEmail,
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

const updateHandoff = async (req, res) => {
  requireObjectBody(req.body);

  const allowedFields = [
    'title',
    'instructions',
    'recipientEmail',
    'expiresAt',
  ];

  const unknownFields = Object.keys(req.body).filter(
    (field) => !allowedFields.includes(field),
  );

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
  updateHandoff,
  shareHandoff,
  revokeHandoff,
  redeemHandoff,
};
