import type { RequestHandler } from 'express';
import { userClient } from '../config/supabase';
import { AppError, MSG } from '../utils/errors';

/**
 * Verifies the bearer token with Supabase Auth (not just decoding it) and
 * attaches a user-scoped DB client. student_id is ALWAYS derived from this
 * verified identity — never from the request body, query or URL.
 */
export const requireAuth: RequestHandler = async (req, _res, next) => {
  try {
    const [scheme, token] = (req.header('authorization') ?? '').split(' ');
    if (scheme?.toLowerCase() !== 'bearer' || !token) {
      throw new AppError(401, 'UNAUTHENTICATED', MSG.unauthenticated);
    }

    const db = userClient(token);
    const { data, error } = await db.auth.getUser(token);
    if (error || !data.user) throw new AppError(401, 'UNAUTHENTICATED', MSG.unauthenticated);

    // RLS lets a user read only their own role rows.
    const { data: roleRows, error: roleErr } = await db
      .from('user_roles')
      .select('role')
      .eq('user_id', data.user.id);
    if (roleErr) throw roleErr;

    const roles = (roleRows ?? []).map((r) => r.role as string);
    req.auth = { userId: data.user.id, token, db, roles, isAdmin: roles.includes('admin') };
    next();
  } catch (err) {
    next(err);
  }
};

/** Role-based authorization. Use AFTER requireAuth. */
export const requireAdmin: RequestHandler = (req, _res, next) => {
  if (!req.auth?.isAdmin) return next(new AppError(403, 'FORBIDDEN', MSG.forbidden));
  next();
};
