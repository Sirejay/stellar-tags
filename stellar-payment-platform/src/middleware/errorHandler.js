'use strict';

const crypto = require('crypto');
const { logger } = require('../logger');
const { ApiError, ProgrammerError, codeForStatus, errorBody, DEFAULT_MESSAGES } = require('../errors');

/**
 * Fires a critical alert for programmer errors.
 *
 * In production this would page on-call (PagerDuty, OpsGenie, SNS, etc.).
 * Currently logs at `fatal` level so any log aggregator or alert rule can
 * key on severity=fatal. Extend this function to call your alerting provider.
 *
 * @param {Error} err - The programmer error that triggered the alert.
 * @param {import('express').Request} req - The originating request.
 * @param {string} referenceId - The reference ID logged with the error.
 */
const triggerCriticalAlert = (err, req, referenceId) => {
  const logPayload = {
    referenceId,
    correlationId: req && req.correlationId,
    method: req && req.method,
    path: req && req.path,
    errorName: err.name,
    errorMessage: err.message,
    context: err.context,
  };
  const criticalMessage = '[CRITICAL] Programmer error detected — this is a bug that needs immediate attention';

  // Use fatal level when available (winston/pino support it); fall back to
  // error so the alert fires regardless of the logger implementation.
  if (typeof logger.fatal === 'function') {
    logger.fatal(logPayload, criticalMessage);
  } else {
    logger.error(logPayload, criticalMessage);
  }

  // Production hook: call your alerting provider here.
  // Examples:
  //   await pagerduty.createIncident({ ... });
  //   await sns.publish({ TopicArn: CRITICAL_ALERTS_ARN, Message: ... });
  //   Sentry.captureException(err, { level: 'fatal' });
  //
  // The hook is intentionally synchronous (fire-and-forget) so an alerting
  // provider failure can never suppress the error response to the client.
};

/**
 * Maps errors thrown by libraries, which carry their own conventions rather
 * than a code, onto the platform's codes.
 */
const classify = (err, req, isPrismaConnectionError) => {
  if (err instanceof ProgrammerError) {
    return {
      code: 'INTERNAL_ERROR',
      statusCode: 500,
      message: err.message, // internal message - will be scrubbed in response
      expected: false,
      isOperational: false,
    };
  }

  if (err instanceof ApiError) {
    return {
      code: err.code,
      statusCode: err.statusCode,
      message: err.message,
      details: err.details,
      expected: true,
      isOperational: err.isOperational !== false, // OperationalError or ApiError are both operational
    };
  }

  if (isPrismaConnectionError(err)) {
    return {
      code: 'SERVICE_UNAVAILABLE',
      statusCode: 503,
      message: DEFAULT_MESSAGES.SERVICE_UNAVAILABLE,
      expected: true,
    };
  }

  // body-parser rejects oversized payloads with its own type tag.
  if (err.type === 'entity.too.large') {
    const bytes = req && req.bodySizeLimit;
    const maxKb = bytes ? Math.round(bytes / 1024) : 10;
    return {
      code: 'PAYLOAD_TOO_LARGE',
      statusCode: 413,
      message: `Payload too large. Maximum allowed size for this endpoint is ${maxKb}kb.`,
    };
  }

  if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
    return { code: 'INVALID_INPUT', statusCode: 400, message: 'Malformed JSON payload' };
  }

  const statusCode = err.statusCode || err.status || 500;
  return {
    code: err.code && typeof err.code === 'string' && /^[A-Z_]+$/.test(err.code)
      ? err.code
      : codeForStatus(statusCode),
    statusCode,
    message: err.message || DEFAULT_MESSAGES.INTERNAL_ERROR,
    details: err.details,
  };
};

/**
 * Terminal error handler: the single place an error becomes a response.
 *
 * Every failure leaves as
 * `{ success: false, error: { code, message, details? } }`, plus the
 * correlation id and, for 5xx, a reference id that ties the response to the
 * logged stack.
 *
 * A 5xx raised by an unexpected throw reports the generic message so internals
 * are never leaked, with the detail kept in the log under the reference id. A
 * message an author chose deliberately via ApiError is sent as written.
 */
const buildErrorHandler = (isPrismaConnectionError) =>
  // eslint-disable-next-line no-unused-vars
  (err, req, res, _next) => {
    const { code, statusCode, message, details, expected } = classify(err, req, isPrismaConnectionError);

    if (res.headersSent) {
      return;
    }

    if (statusCode >= 500) {
      const referenceId = crypto.randomUUID();
      if (process.env.NODE_ENV !== 'test') {
        console.warn(`[Correlation ID: ${req.correlationId}] [Error ID: ${referenceId}]`, err);
      }
      logger.error(`[Correlation ID: ${req.correlationId}] [Error ID: ${referenceId}]`, err);

      // Programmer errors (isOperational === false or unknown unexpected errors)
      // trigger a critical alert so the on-call team is paged immediately.
      const isProgrammerError = err.isOperational === false || !(err instanceof ApiError);
      if (isProgrammerError) {
        triggerCriticalAlert(err, req, referenceId);
      }

      return res.status(statusCode).json(
        errorBody(code, expected ? message : DEFAULT_MESSAGES.INTERNAL_ERROR, {
          correlationId: req.correlationId,
          referenceId,
        }),
      );
    }

    return res.status(statusCode).json(
      errorBody(code, message, { details, correlationId: req.correlationId }),
    );
  };

/** Terminal 404 for unmatched routes, so misses use the same envelope. */
const notFoundHandler = (req, res) =>
  res.status(404).json(
    errorBody('NOT_FOUND', `Cannot ${req.method} ${req.path}`, {
      correlationId: req.correlationId,
    }),
  );

module.exports = { buildErrorHandler, notFoundHandler, classify, triggerCriticalAlert };
