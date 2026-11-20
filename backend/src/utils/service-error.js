class ServiceError extends Error {
  constructor(message, code, options = {}) {
    super(message, options);
    this.name = 'ServiceError';
    this.code = code;
    this.isOperational = true;
  }
}

export default ServiceError;
