-- =====================================================================
-- EduVault AI — database/policies.sql
-- Row Level Security + Storage policies.
-- Principle: deny by default. No policy grants "all authenticated users"
-- or "public" access to student data.
-- (select auth.uid()) is used so Postgres evaluates it once per query.
-- =====================================================================

-- ---------------------------------------------------------------------
-- Defense in depth: strip default Supabase grants that we never want
-- ---------------------------------------------------------------------
revoke all on all tables    in schema public from anon;
revoke all on all sequences in schema public from anon;
revoke all on all functions in schema public from anon;

-- Tables that only the backend (service role) may write
revoke insert, update, delete on public.user_roles           from authenticated;
revoke insert, update, delete on public.audit_logs           from authenticated;
revoke insert, update, delete on public.document_ai_metadata from authenticated;

-- ---------------------------------------------------------------------
-- Enable RLS everywhere
-- ---------------------------------------------------------------------
alter table public.user_roles           enable row level security;
alter table public.profiles             enable row level security;
alter table public.documents            enable row level security;
alter table public.academic_records     enable row level security;
alter table public.semester_attendance  enable row level security;
alter table public.certifications       enable row level security;
alter table public.internships          enable row level security;
alter table public.workshops            enable row level security;
alter table public.hackathons           enable row level security;
alter table public.projects             enable row level security;
alter table public.achievements         enable row level security;
alter table public.document_ai_metadata enable row level security;
alter table public.audit_logs           enable row level security;
alter table public.document_categories  enable row level security;
alter table public.grade_scale          enable row level security;

-- ---------------------------------------------------------------------
-- user_roles: read own role only; writes are service-role only
-- ---------------------------------------------------------------------
create policy user_roles_select_own on public.user_roles
  for select to authenticated using (user_id = (select auth.uid()));
create policy user_roles_select_admin on public.user_roles
  for select to authenticated using (public.is_admin());

-- ---------------------------------------------------------------------
-- profiles: students read/update own row. Insert/delete = service role.
-- Protected columns are enforced by trigger trg_profiles_protect.
-- ---------------------------------------------------------------------
create policy profiles_select_own on public.profiles
  for select to authenticated using (id = (select auth.uid()));
create policy profiles_select_admin on public.profiles
  for select to authenticated using (public.is_admin());
create policy profiles_update_own on public.profiles
  for update to authenticated
  using (id = (select auth.uid()))
  with check (id = (select auth.uid()));
create policy profiles_update_admin on public.profiles
  for update to authenticated
  using (public.is_admin()) with check (public.is_admin());

-- ---------------------------------------------------------------------
-- documents: full CRUD on own rows; admins can read and verify.
-- (Admins cannot delete student files by default.)
-- ---------------------------------------------------------------------
create policy documents_select_own on public.documents
  for select to authenticated using (student_id = (select auth.uid()));
create policy documents_select_admin on public.documents
  for select to authenticated using (public.is_admin());
create policy documents_insert_own on public.documents
  for insert to authenticated
  with check (
    student_id = (select auth.uid())
    and exists (select 1 from public.document_categories c
                where c.code = document_category and c.is_active)
  );
create policy documents_update_own on public.documents
  for update to authenticated
  using (student_id = (select auth.uid()))
  with check (student_id = (select auth.uid()));
create policy documents_update_admin on public.documents
  for update to authenticated
  using (public.is_admin()) with check (public.is_admin());
create policy documents_delete_own on public.documents
  for delete to authenticated using (student_id = (select auth.uid()));

-- ---------------------------------------------------------------------
-- Academic data: students READ own; admins write.
-- ---------------------------------------------------------------------
do $$
declare t text;
begin
  foreach t in array array['academic_records', 'semester_attendance'] loop
    execute format(
      'create policy %1$s_select_own on public.%1$I
         for select to authenticated using (student_id = (select auth.uid()))', t);
    execute format(
      'create policy %1$s_select_admin on public.%1$I
         for select to authenticated using (public.is_admin())', t);
    execute format(
      'create policy %1$s_write_admin on public.%1$I
         for all to authenticated
         using (public.is_admin()) with check (public.is_admin())', t);
  end loop;
end $$;

-- ---------------------------------------------------------------------
-- Student-managed records: full CRUD on own rows, and any linked
-- document must also belong to the same student.
-- ---------------------------------------------------------------------
do $$
declare
  t     text;
  extra text;
begin
  foreach t in array array[
    'certifications', 'internships', 'workshops', 'hackathons', 'projects', 'achievements'
  ] loop
    extra := case when t in ('hackathons', 'projects')
                  then ' and public.owns_document(report_document_id)' else '' end;

    execute format(
      'create policy %1$s_select_own on public.%1$I
         for select to authenticated using (student_id = (select auth.uid()))', t);
    execute format(
      'create policy %1$s_select_admin on public.%1$I
         for select to authenticated using (public.is_admin())', t);
    execute format(
      'create policy %1$s_insert_own on public.%1$I
         for insert to authenticated
         with check (student_id = (select auth.uid()) and public.owns_document(document_id)%2$s)',
      t, extra);
    execute format(
      'create policy %1$s_update_own on public.%1$I
         for update to authenticated
         using (student_id = (select auth.uid()))
         with check (student_id = (select auth.uid()) and public.owns_document(document_id)%2$s)',
      t, extra);
    execute format(
      'create policy %1$s_delete_own on public.%1$I
         for delete to authenticated using (student_id = (select auth.uid()))', t);
  end loop;
end $$;

-- ---------------------------------------------------------------------
-- AI metadata + audit log: read-only from the client side
-- ---------------------------------------------------------------------
create policy ai_meta_select_own on public.document_ai_metadata
  for select to authenticated using (student_id = (select auth.uid()));
create policy ai_meta_select_admin on public.document_ai_metadata
  for select to authenticated using (public.is_admin());

create policy audit_select_own on public.audit_logs
  for select to authenticated using (user_id = (select auth.uid()));
create policy audit_select_admin on public.audit_logs
  for select to authenticated using (public.is_admin());

-- ---------------------------------------------------------------------
-- Lookup tables: readable by signed-in users, writable by admins
-- ---------------------------------------------------------------------
create policy categories_select on public.document_categories
  for select to authenticated using (true);
create policy categories_write_admin on public.document_categories
  for all to authenticated
  using (public.is_admin()) with check (public.is_admin());

create policy grade_scale_select on public.grade_scale
  for select to authenticated using (true);
create policy grade_scale_write_admin on public.grade_scale
  for all to authenticated
  using (public.is_admin()) with check (public.is_admin());

-- ---------------------------------------------------------------------
-- Storage: private bucket, one folder per student
-- Path convention: {student_id}/{category_folder}/{uuid}_{safe-name}
-- ---------------------------------------------------------------------
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values (
  'students', 'students', false, 10485760,
  array[
    'application/pdf', 'image/jpeg', 'image/png', 'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
  ]
)
on conflict (id) do update
  set public = false,
      file_size_limit = excluded.file_size_limit,
      allowed_mime_types = excluded.allowed_mime_types;

create policy students_storage_select_own on storage.objects
  for select to authenticated
  using (bucket_id = 'students'
         and (storage.foldername(name))[1] = (select auth.uid())::text);

create policy students_storage_select_admin on storage.objects
  for select to authenticated
  using (bucket_id = 'students' and public.is_admin());

create policy students_storage_insert_own on storage.objects
  for insert to authenticated
  with check (bucket_id = 'students'
              and (storage.foldername(name))[1] = (select auth.uid())::text);

create policy students_storage_update_own on storage.objects
  for update to authenticated
  using (bucket_id = 'students'
         and (storage.foldername(name))[1] = (select auth.uid())::text)
  with check (bucket_id = 'students'
              and (storage.foldername(name))[1] = (select auth.uid())::text);

create policy students_storage_delete_own on storage.objects
  for delete to authenticated
  using (bucket_id = 'students'
         and (storage.foldername(name))[1] = (select auth.uid())::text);
