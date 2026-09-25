import type { Request, Response } from 'express';
import rateLimit from 'express-rate-limit';
import { MSG } from '../utils/errors';

const handler = (_req: Request, res: Response) => {
  res.status(429).json({ error: { code: 'RATE_LIMITED', message: MSG.tooMany } });
};

const base = { standardHeaders: 'draft-7' as const, legacyHeaders: false, handler };

export const apiLimiter = rateLimit({ ...base, windowMs: 60_000, limit: 300 });

export const loginIpLimiter = rateLimit({ ...base, windowMs: 15 * 60_000, limit: 20 });

// Keyed by IP + register number so an attacker cannot lock a victim out
// from a different IP. Successful logins do not count.
export const loginAccountLimiter = rateLimit({
  ...base,
  windowMs: 15 * 60_000,
  limit: 5,
  skipSuccessfulRequests: true,
  keyGenerator: (req: Request) =>
    `${req.ip}:${String(req.body?.registerNumber ?? '').toUpperCase().slice(0, 32)}`,
});

export const forgotPasswordLimiter = rateLimit({ ...base, windowMs: 60 * 60_000, limit: 5 });

export const uploadLimiter = rateLimit({ ...base, windowMs: 10 * 60_000, limit: 30 });
