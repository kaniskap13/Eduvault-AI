import 'dotenv/config';
import { z } from 'zod';

const schema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.coerce.number().int().positive().default(4000),
  CORS_ORIGIN: z.string().url(),
  SUPABASE_URL: z.string().url(),
  SUPABASE_ANON_KEY: z.string().min(20),
  SUPABASE_SERVICE_ROLE_KEY: z.string().min(20),
  PASSWORD_RESET_REDIRECT: z.string().url(),
  SIGNED_URL_TTL_SECONDS: z.coerce.number().int().min(10).max(600).default(60),
  MAX_UPLOAD_BYTES: z.coerce.number().int().positive().default(10 * 1024 * 1024),
  AI_PROVIDER: z.string().default('mock'),
  AI_API_KEY: z.string().optional(),
});

const parsed = schema.safeParse(process.env);
if (!parsed.success) {
  // Print variable NAMES only — never values.
  const bad = [...new Set(parsed.error.issues.map((i) => i.path.join('.')))].join(', ');
  console.error(`Invalid environment configuration. Check: ${bad}`);
  process.exit(1);
}

export const env = parsed.data;
export const isProd = env.NODE_ENV === 'production';
