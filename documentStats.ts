import type { SupabaseClient } from '@supabase/supabase-js';

/** Per-category document counts for the caller (all active categories, zeros included). */
export async function loadCategoryCounts(db: SupabaseClient, userId: string) {
  const [cats, docs] = await Promise.all([
    db.from('document_categories').select('code, label, sort_order').eq('is_active', true).order('sort_order'),
    db.from('documents').select('document_category').eq('student_id', userId),
  ]);
  if (cats.error) throw cats.error;
  if (docs.error) throw docs.error;

  const counts: Record<string, number> = {};
  for (const d of docs.data ?? []) counts[d.document_category] = (counts[d.document_category] ?? 0) + 1;
  return (cats.data ?? []).map((c) => ({ code: c.code as string, label: c.label as string, count: counts[c.code] ?? 0 }));
}
