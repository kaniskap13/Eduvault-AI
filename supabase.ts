import { createClient, type SupabaseClient } from '@supabase/supabase-js';
import { env } from './env';

const authOpts = { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false };

/**
 * Service-role client. BYPASSES Row Level Security.
 * Import only from: auth controller (login lookup), audit util, admin module, seed script.
 * Never use it to serve student data on behalf of a request.
 */
export const adminClient: SupabaseClient = createClient(
  env.SUPABASE_URL,
  env.SUPABASE_SERVICE_ROLE_KEY,
  { auth: authOpts },
);

/**
 * Fresh anonymous client per call. Auth methods (signInWithPassword) keep the
 * session in memory, so a shared instance would mix up concurrent users.
 */
export function newAnonClient(): SupabaseClient {
  return createClient(env.SUPABASE_URL, env.SUPABASE_ANON_KEY, { auth: authOpts });
}

/** Per-request client that acts AS the caller — RLS applies to every query. */
export function userClient(accessToken: string): SupabaseClient {
  return createClient(env.SUPABASE_URL, env.SUPABASE_ANON_KEY, {
    auth: authOpts,
    global: { headers: { Authorization: `Bearer ${accessToken}` } },
  });
}
