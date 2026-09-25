import { z } from 'zod';

export const registerNumberSchema = z
  .string()
  .trim()
  .toUpperCase()
  .regex(/^RA[0-9]{13}$/, 'Invalid register number format');

export const loginSchema = z
  .object({
    registerNumber: registerNumberSchema,
    password: z.string().min(1).max(128),
  })
  .strict();

export const forgotPasswordSchema = z.object({ registerNumber: registerNumberSchema }).strict();
