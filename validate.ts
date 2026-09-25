import type { RequestHandler } from 'express';
import type { ZodTypeAny } from 'zod';

/** Parses and replaces req[source] with the validated (whitelisted) value. */
export const validate =
  (schema: ZodTypeAny, source: 'body' | 'query' | 'params' = 'body'): RequestHandler =>
  (req, _res, next) => {
    const result = schema.safeParse(req[source]);
    if (!result.success) return next(result.error);
    (req as unknown as Record<string, unknown>)[source] = result.data;
    next();
  };
