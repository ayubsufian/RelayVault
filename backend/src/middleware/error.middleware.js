import HttpError from '../utils/http-error.js';

const isProduction = process.env.NODE_ENV === 'production';

const notFound = (req, res, next) => {
  next(new HttpError(`Route not found: ${req.method} ${req.originalUrl}`, 404));
};

const serviceErrorResponses = {
  USERNAME_GENERATION_FAILED: {
    statusCode: 503,
    message: 'Unable to create the account right now',
  },
  EMAIL_DELIVERY_FAILED: {
    statusCode: 503,
    message: 'Unable to send the email right now',
  },
  SESSION_CREATION_FAILED: {
    statusCode: 503,
    message: 'Unable to create a session right now',
  },
};

const errorHandler = (error, req, res, next) => {
  if (res.headersSent) {
    return next(error);
  }

  let statusCode = error.statusCode || 500;
  let message = isProduction
    ? 'Internal server error'
    : error.message || 'Internal server error';

  const serviceResponse = serviceErrorResponses[error.code];

  if (serviceResponse) {
    statusCode = serviceResponse.statusCode;
    message = serviceResponse.message;
  }

  if (error.name === 'ValidationError') {
    statusCode = 400;
    message = 'Invalid data';
  }

  if (error.name === 'CastError') {
    statusCode = 400;
    message = 'Invalid resource ID';
  }

  if (error.code === 11000) {
    statusCode = 409;
    message = 'A record with that value already exists';
  }

  console.error(error);

  return res.status(statusCode).json({ message });
};

export { notFound, errorHandler };
