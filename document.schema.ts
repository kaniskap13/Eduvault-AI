import { z } from 'zod';

const emptyToUndef = (v: unknown) => (v === '' ? undefined : v);
const optional = <T extends z.ZodTypeAny>(schema: T) => z.preprocess(emptyToUndef, schema.optional());

const isoDate = z
  .string()
  .regex(/^\d{4}-\d{2}-\d{2}$/, 'Use YYYY-MM-DD')
  .refine((s) => {
    const d = new Date(`${s}T00:00:00Z`);
    return !Number.isNaN(d.getTime()) && d.toISOString().startsWith(s) && d.getUTCFullYear() >= 1950;
  }, 'Invalid date');

// eslint-disable-next-line no-control-regex
const noControlChars = (s: string) => !/[\u0000-\u001f\u007f]/.test(s);

/** Multipart text fields that accompany the file. */
export const createDocumentSchema = z
  .object({
    document_category: z.string().trim().min(1).max(50),
    document_name: optional(z.string().trim().min(1).max(200).refine(noControlChars, 'Invalid characters')),
    document_type: optional(z.string().trim().max(100)),
    description: optional(z.string().trim().max(2000)),
    organization: optional(z.string().trim().max(200)),
    issue_date: optional(isoDate),
  })
  .strict();

export const listDocumentsQuery = z
  .object({
    category: z.string().trim().max(50).optional(),
    q: z.string().trim().max(100).optional(),
    page: z.coerce.number().int().min(1).default(1),
    pageSize: z.coerce.number().int().min(1).max(50).default(20),
  })
  .strict();

export const idParam = z.object({ id: z.string().uuid() }).strict();

export const urlQuery = z
  .object({ disposition: z.enum(['inline', 'attachment']).default('inline') })
  .strict();
