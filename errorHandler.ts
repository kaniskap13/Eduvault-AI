import type { ErrorRequestHandler, RequestHandler } from 'express';
import { ZodError } from 'zod';
import { AppError, MSG } from '../utils/errors';

export const notFound: RequestHandler = (_req, res) => {
  res.status(404).json({ error: { code: 'NOT_FOUND', message: MSG.notFound } });
};

export const errorHandler: ErrorRequestHandler = (err, req, res, _next) => {
  const requestId = res.locals.requestId as string | undefined;
  const send = (status: number, code: string, message: string, details?: unknown) =>
    res.status(status).json({ error: { code, message, details, requestId } });

  if (err instanceof AppError) return send(err.status, err.code, err.message, err.details);

  if (err instanceof ZodError) {
    return send(
      400,
      'VALIDATION_ERROR',
      MSG.validation,
      err.issues.map((i) => ({ field: i.path.join('.'), message: i.message })),
    );
  }

  if (err?.type === 'entity.parse.failed') return send(400, 'BAD_JSON', MSG.validation);
  if (err?.type === 'entity.too.large') return send(413, 'PAYLOAD_TOO_LARGE', MSG.validation);

  // Postgres / PostgREST errors — map to safe, generic messages.
  switch (err?.code) {
    case '42501': // RLS violation / insufficient_privilege
      return send(403, 'FORBIDDEN', MSG.forbidden);
    case 'PGRST116': // .single() matched no rows (or RLS hid the row)
      return send(404, 'NOT_FOUND', MSG.notFound);
    case '23505':
      return send(409, 'CONFLICT', MSG.conflict);
    case '23502':
    case '23503':
    case '23514':
    case '22P02':
    case '22007':
    case '22008':
      return send(400, 'VALIDATION_ERROR', MSG.validation);
  }

  // Unexpected: log details server-side only (no bodies, no tokens).
  console.error(
    JSON.stringify({
      level: 'error',
      requestId,
      method: req.method,
      path: req.path,
      code: err?.code,
      message: err?.message,
    }),
  );
  return send(500, 'INTERNAL', MSG.generic);
};
