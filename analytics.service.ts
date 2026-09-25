import type { SupabaseClient } from '@supabase/supabase-js';
import { loadAcademics } from './academics.service';
import { loadCategoryCounts } from './documentStats';

const COUNT_TABLES = [
  'documents',
  'certifications',
  'internships',
  'workshops',
  'hackathons',
  'projects',
  'achievements',
] as const;

export async function loadAnalytics(db: SupabaseClient, userId: string) {
  const [counts, academics, documentsByCategory] = await Promise.all([
    Promise.all(
      COUNT_TABLES.map(async (t) => {
        const { count, error } = await db
          .from(t)
          .select('id', { count: 'exact', head: true })
          .eq('student_id', userId);
        if (error) throw error;
        return [t, count ?? 0] as const;
      }),
    ),
    loadAcademics(db, userId),
    loadCategoryCounts(db, userId),
  ]);

  return {
    totals: Object.fromEntries(counts) as Record<(typeof COUNT_TABLES)[number], number>,
    cgpa: academics.cgpa,
    totalCredits: academics.totalCredits,
    averageAttendance: academics.averageAttendance,
    performanceTrend: academics.trend,
    documentsByCategory,
  };
}
