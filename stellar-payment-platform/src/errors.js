'use strict';

/**
 * Machine-readable error codes and the HTTP status each maps to.
 *
 * The code is the stable part of the contract: clients branch on it rather
 * than on status alone or on message text, which is free to be reworded.
 */
const ERROR_CODES = {
  INVALID_INPUT: 400,
  UNAUTHENTICATED: 401,
  FORBIDDEN: 403,
  NOT_FOUND: 404,
  METHOD_NOT_ALLOWED: 405,
  CONFLICT: 409,
  PAYLOAD_TOO_LARGE: 413,
  UNSUPPORTED_MEDIA_TYPE: 415,
  VALIDATION_FAILED: 422,
  RATE_LIMITED: 429,
  INTERNAL_ERROR: 500,
  UPSTREAM_ERROR: 502,
  SERVICE_UNAVAILABLE: 503,
};

/**
 * Fallback message per code, so `new ApiError(CODE)` never sends the raw code
 * as a human-facing message.
 */
const DEFAULT_MESSAGES = {
  INVALID_INPUT: 'Invalid request',
  UNAUTHENTICATED: 'Authentication required',
  FORBIDDEN: 'Forbidden',
  NOT_FOUND: 'Not Found',
  METHOD_NOT_ALLOWED: 'Method Not Allowed',
  CONFLICT: 'Conflict',
  PAYLOAD_TOO_LARGE: 'Payload Too Large',
  UNSUPPORTED_MEDIA_TYPE: 'Unsupported Media Type',
  VALIDATION_FAILED: 'Request validation failed',
  RATE_LIMITED: 'Too many requests, please try again later.',
  INTERNAL_ERROR: 'Internal Server Error',
  UPSTREAM_ERROR: 'Upstream request failed',
  SERVICE_UNAVAILABLE: 'Service Unavailable',
};

/**
 * An error carrying everything the response envelope needs.
 *
 * Throw or pass to `next()` from anywhere; the error handler is the only place
 * that turns one into a response.
 */
class ApiError extends Error {
  /**
   * @param {keyof typeof ERROR_CODES} code
   * @param {string} [message] defaults to the code's generic message
   * @param {{ details?: unknown[], statusCode?: number, cause?: unknown }} [options]
   */
  constructor(code, message, options = {}) {
    const resolvedCode = code in ERROR_CODES ? code : 'INTERNAL_ERROR';
    super(message || DEFAULT_MESSAGES[resolvedCode] || resolvedCode, { cause: options.cause });

    this.name = 'ApiError';
    this.code = resolvedCode;
    this.statusCode = options.statusCode || ERROR_CODES[resolvedCode];
    if (options.details) {
      this.details = options.details;
    }
  }
}

/**
 * An expected, operational failure — a condition the application anticipated
 * and handled deliberately (e.g. validation errors, not-found, rate limits).
 *
 * These map directly to HTTP status codes and are safe to surface to clients.
 * The global error handler treats them as handled and does NOT trigger alerts.
 *
 * @extends ApiError
 */
class OperationalError extends ApiError {
  constructor(code, message, options = {}) {
    super(code, message, options);
    this.name = 'OperationalError';
    /** @type {true} Distinguishes handled failures from programming mistakes. */
    this.isOperational = true;
  }
}

/**
 * An unexpected programmer error — a bug in the application (e.g. a null
 * dereference, failed assertion, or violated invariant).
 *
 * These always result in a 500 Internal Server Error with a generic message
 * so internal details are never leaked to clients. The global error handler
 * treats them as unhandled and fires a critical alert.
 *
 * @extends Error
 */
class ProgrammerError extends Error {
  /**
   * @param {string} message - Internal description of the bug (not sent to clients).
   * @param {{ cause?: unknown, context?: Record<string, unknown> }} [options]
   */
  constructor(message, options = {}) {
    super(message, { cause: options.cause });
    this.name = 'ProgrammerError';
    /** @type {false} Marks this as an unhandled, unexpected failure. */
    this.isOperational = false;
    this.statusCode = 500;
    this.code = 'INTERNAL_ERROR';
    /** @type {Record<string, unknown> | undefined} Extra debug context for logs. */
    if (options.context) {
      this.context = options.context;
    }
  }
}

/** Reverse lookup for errors that carry only a status (thrown by libraries). */
const codeForStatus = (statusCode) =>
  Object.keys(ERROR_CODES).find((code) => ERROR_CODES[code] === statusCode) ||
  (statusCode >= 500 ? 'INTERNAL_ERROR' : 'INVALID_INPUT');

/**
 * Builds the response body. Kept separate from the handler so the shape has a
 * single definition that non-handler responders (rate limiter, 404) reuse.
 *
 * @returns {{ success: false, error: { code: string, message: string, details?: unknown[] } }}
 */
const errorBody = (code, message, { details, correlationId, referenceId } = {}) => ({
  success: false,
  error: {
    code,
    message,
    ...(details ? { details } : {}),
  },
  ...(correlationId ? { correlation_id: correlationId } : {}),
  ...(referenceId ? { reference_id: referenceId } : {}),
});

module.exports = { ApiError, OperationalError, ProgrammerError, ERROR_CODES, DEFAULT_MESSAGES, codeForStatus, errorBody };
