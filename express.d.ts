import type { SupabaseClient } from '@supabase/supabase-js';

export interface AuthContext {
  userId: string;
  token: string;
  /** Supabase client bound to the caller's JWT — RLS enforced. */
  db: SupabaseClient;
  roles: string[];
  isAdmin: boolean;
}

declare global {
  namespace Express {
    interface Request {
      auth?: AuthContext;
    }
  }
}
