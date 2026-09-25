import { z } from 'zod';

const emptyToNull = (v: unknown) => (typeof v === 'string' && v.trim() === '' ? null : v);

export const isoDate = z
  .string()
  .trim()
  .regex(/^\d{4}-\d{2}-\d{2}$/, 'Use YYYY-MM-DD')
  .refine((s) => {
    const d = new Date(`${s}T00:00:00Z`);
    return !Number.isNaN(d.getTime()) && d.toISOString().startsWith(s) && d.getUTCFullYear() >= 1950;
  }, 'Invalid date');

export const reqStr = (max: number) => z.string().trim().min(1).max(max);
export const optStr = (max: number) => z.preprocess(emptyToNull, z.string().trim().max(max).nullish());
export const optDate = z.preprocess(emptyToNull, isoDate.nullish());
export const optUuid = z.preprocess(emptyToNull, z.string().uuid().nullish());
export const optHttpsUrl = z.preprocess(
  emptyToNull,
  z
    .string()
    .trim()
    .max(500)
    .url()
    .refine((u) => u.toLowerCase().startsWith('https://'), 'Must be an https:// link')
    .nullish(),
);

/** Predicate: if both dates are present, `end` must not be before `start` (ISO strings sort correctly). */
export const ordered =
  <K extends string>(start: K, end: K) =>
  (o: Partial<Record<K, string | null | undefined>>) => {
    const a = o[start];
    const b = o[end];
    return !a || !b || b >= a;
  };

export const nonEmpty = (o: object) => Object.keys(o).length > 0;
