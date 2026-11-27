import crypto from 'node:crypto';
import HttpError from '../utils/http-error.js';

const serviceErrorResponses = Object.freeze({
  USERNAME_GENERATION_FAILED: [
    503,
    'USERNAME_GENERATION_FAILED',
    'Unable to create the account right now',
  ],
  EMAIL_DELIVERY_FAILED: [
    503,
    'EMAIL_DELIVERY_FAILED',
    'Unable to send the email right now',
  ],
  SESSION_CREATION_FAILED: [
    503,
    'SESSION_CREATION_FAILED',
    'Unable to create a session right now',
  ],
  HANDOFF_INVALID_ID: [400, 'HANDOFF_INVALID_ID', 'Invalid handoff identifier'],
  HANDOFF_VALIDATION_FAILED: [
    400,
    'HANDOFF_VALIDATION_FAILED',
    'Invalid handoff data',
  ],
  HANDOFF_NOT_FOUND: [404, 'HANDOFF_NOT_FOUND', 'Handoff not found'],
  HANDOFF_EDIT_CONFLICT: [
    409,
    'HANDOFF_EDIT_CONFLICT',
    'Handoff cannot be edited in its current state',
  ],
  HANDOFF_SHARE_CONFLICT: [
    409,
    'HANDOFF_SHARE_CONFLICT',
    'Handoff cannot be shared in its current state',
  ],
  HANDOFF_EXPIRED: [409, 'HANDOFF_EXPIRED', 'Handoff has expired'],
  HANDOFF_SHARE_FAILED: [
    409,
    'HANDOFF_SHARE_FAILED',
    'Handoff could not be shared',
  ],
  HANDOFF_UNAVAILABLE: [
    410,
    'HANDOFF_UNAVAILABLE',
    'Invalid or unavailable handoff',
  ],
  HANDOFF_DECRYPTION_FAILED: [
    500,
    'HANDOFF_DECRYPTION_FAILED',
    'Handoff could not be opened',
  ],
});
const requestIdPattern = /^[A-Za-z0-9._-]{1,128}$/;
const getRequestId = (req) => {
  const supplied = req.requestId || req.get('x-request-id');
  const id =
    typeof supplied === 'string' && requestIdPattern.test(supplied)
      ? supplied
      : crypto.randomUUID();
  req.requestId = id;
  return id;
};
const normalizeStatus = (error) => {
  const status = Number(error.statusCode ?? error.status);
  return Number.isInteger(status) && status >= 400 && status <= 599
    ? status
    : 500;
};
const normalizeError = (error) => {
  if (error?.type === 'entity.too.large' || error?.status === 413)
    return [413, 'PAYLOAD_TOO_LARGE', 'Request body is too large'];
  if (error?.type === 'entity.parse.failed')
    return [400, 'INVALID_JSON', 'Request body contains invalid JSON'];
  if (error?.name === 'ValidationError')
    return [400, 'VALIDATION_ERROR', 'Invalid data'];
  if (error?.name === 'CastError')
    return [400, 'INVALID_RESOURCE_ID', 'Invalid resource ID'];
  if (error?.code === 11000)
    return [
      409,
      'DUPLICATE_RESOURCE',
      'A record with that value already exists',
    ];
  const mapped = serviceErrorResponses[error?.code];
  if (mapped) return mapped;
  const status = normalizeStatus(error);
  const operational = error?.isOperational === true;
  return [
    status,
    operational && typeof error.code === 'string'
      ? error.code
      : operational
        ? 'REQUEST_FAILED'
        : 'INTERNAL_SERVER_ERROR',
    operational && typeof error.message === 'string'
      ? error.message
      : 'Internal server error',
  ];
};
const notFound = (req, res, next) =>
  next(new HttpError('Route not found', 404));
const errorHandler = (error, req, res, next) => {
  if (res.headersSent) return next(error);
  const requestId = getRequestId(req);
  const [statusCode, code, message] = normalizeError(error);
  const operational = error?.isOperational === true || statusCode < 500;
  res.set('X-Request-Id', requestId);
  console.error('HTTP request failed', {
    requestId,
    method: req.method,
    path: req.path,
    statusCode,
    code,
    operational,
    ...(operational || process.env.NODE_ENV === 'production' ? {} : { error }),
  });
  return res.status(statusCode).json({
    error: {
      code,
      message:
        process.env.NODE_ENV === 'production' && !operational
          ? 'Internal server error'
          : message,
      requestId,
    },
  });
};
export { notFound, errorHandler };
