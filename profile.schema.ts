import { z } from 'zod';

const isoDateInPast = (s: string) => {
  const d = new Date(`${s}T00:00:00Z`);
  return !Number.isNaN(d.getTime()) && d.toISOString().startsWith(s) && d < new Date() && d.getUTCFullYear() > 1900;
};

const text = (max: number) => z.string().trim().max(max).nullable();

/**
 * Whitelist of student-editable fields. `.strict()` rejects anything else,
 * so register_number, email, department, id, etc. can never be sent through.
 * (The database trigger enforces the same rule as a second layer.)
 */
export const updateProfileSchema = z
  .object({
    full_name: z.string().trim().min(1).max(120),
    phone: z.string().trim().regex(/^\+?[0-9]{7,15}$/, 'Invalid phone number').nullable(),
    date_of_birth: z
      .string()
      .regex(/^\d{4}-\d{2}-\d{2}$/, 'Use YYYY-MM-DD')
      .refine(isoDateInPast, 'Invalid date of birth')
      .nullable(),
    course: text(100),
    year: z.number().int().min(1).max(6).nullable(),
    semester: z.number().int().min(1).max(12).nullable(),
    section: text(10),
    address: text(500),
    city: text(100),
    state: text(100),
    country: text(100),
    postal_code: text(20),
  })
  .partial()
  .strict()
  .refine((o) => Object.keys(o).length > 0, 'No fields to update');
