import type { CookieOptions } from 'express';
import { env, isProd } from '../config/env';
import { adminClient, newAnonClient } from '../config/supabase';
import { forgotPasswordSchema, loginSchema } from '../models/auth.schema';
import { asyncHandler } from '../utils/asyncHandler';
import { audit } from '../utils/audit';
import { AppError, MSG } from '../utils/errors';

const REFRESH_COOKIE = 'ev_refresh';
const COOKIE_PATH = '/api/auth';

// Refresh token lives ONLY in an httpOnly cookie (invisible to page JS).
// The short-lived access token is returned in the body and kept in memory by the SPA.
const cookieOpts: CookieOptions = {
  httpOnly: true,
  secure: isProd,
  sameSite: 'strict',
  path: COOKIE_PATH,
  maxAge: 7 * 24 * 60 * 60 * 1000,
};
const clearOpts: CookieOptions = { httpOnly: true, secure: isProd, sameSite: 'strict', path: COOKIE_PATH };

const invalidLogin = () => new AppError(401, 'INVALID_CREDENTIALS', MSG.invalidLogin);

export const login = asyncHandler(async (req, res) => {
  // Malformed input gets the SAME response as wrong credentials.
  const parsed = loginSchema.safeParse(req.body);
  if (!parsed.success) throw invalidLogin();
  const { registerNumber, password } = parsed.data;

  // Service role is used ONLY to resolve register number -> email.
  const { data: profile, error: lookupErr } = await adminClient
    .from('profiles')
    .select('id, email, full_name, register_number, department, semester')
    .eq('register_number', registerNumber)
    .maybeSingle();
  if (lookupErr) throw lookupErr;
  if (!profile) throw invalidLogin();

  const { data, error } = await newAnonClient().auth.signInWithPassword({
    email: profile.email,
    password,
  });

  if (error || !data.session) {
    const isCredentialError = error?.code === 'invalid_credentials' || error?.status === 400;
    if (!isCredentialError) throw new AppError(503, 'UPSTREAM_UNAVAILABLE', MSG.network);
    await audit(profile.id, 'login_failed');
    throw invalidLogin();
  }

  const { data: roleRows } = await adminClient.from('user_roles').select('role').eq('user_id', profile.id);
  const roles = (roleRows ?? []).map((r) => r.role as string);

  await audit(profile.id, 'login');
  res.cookie(REFRESH_COOKIE, data.session.refresh_token, cookieOpts);
  res.json({
    accessToken: data.session.access_token,
    expiresIn: data.session.expires_in,
    user: {
      id: profile.id,
      registerNumber: profile.register_number,
      fullName: profile.full_name,
      department: profile.department,
      semester: profile.semester,
      roles,
      isAdmin: roles.includes('admin'),
    },
  });
});

export const refresh = asyncHandler(async (req, res) => {
  const token = req.cookies?.[REFRESH_COOKIE] as string | undefined;
  if (!token) throw new AppError(401, 'UNAUTHENTICATED', MSG.unauthenticated);

  const { data, error } = await newAnonClient().auth.refreshSession({ refresh_token: token });
  if (error || !data.session) {
    res.clearCookie(REFRESH_COOKIE, clearOpts);
    throw new AppError(401, 'UNAUTHENTICATED', MSG.unauthenticated);
  }

  // Refresh tokens rotate: store the new one.
  res.cookie(REFRESH_COOKIE, data.session.refresh_token, cookieOpts);
  res.json({ accessToken: data.session.access_token, expiresIn: data.session.expires_in });
});

export const logout = asyncHandler(async (req, res) => {
  const auth = req.auth!;
  await adminClient.auth.admin.signOut(auth.token, 'local').catch(() => undefined);
  await audit(auth.userId, 'logout');
  res.clearCookie(REFRESH_COOKIE, clearOpts);
  res.status(204).end();
});

export const me = asyncHandler(async (req, res) => {
  const { userId, roles, isAdmin } = req.auth!;
  res.json({ userId, roles, isAdmin });
});

export const forgotPassword = asyncHandler(async (req, res) => {
  const generic = {
    message: 'If the register number is registered, a reset link has been sent to the email on file.',
  };

  const parsed = forgotPasswordSchema.safeParse(req.body);
  if (parsed.success) {
    const { data: profile } = await adminClient
      .from('profiles')
      .select('email')
      .eq('register_number', parsed.data.registerNumber)
      .maybeSingle();
    if (profile) {
      await newAnonClient().auth.resetPasswordForEmail(profile.email, {
        redirectTo: env.PASSWORD_RESET_REDIRECT,
      });
    }
  }
  // Same response whether or not the register number exists.
  res.status(202).json(generic);
});
