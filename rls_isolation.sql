-- =====================================================================
-- EduVault AI — database/tests/rls_isolation.sql
-- SQL-level isolation tests: impersonates Student A, Student B, an admin
-- and an anonymous caller, and checks what Row Level Security, triggers,
-- grants and storage policies actually allow.
--
-- HOW TO RUN (development database only — never production):
--   psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f database/tests/rls_isolation.sql
--   (local Supabase: postgresql://postgres:postgres@127.0.0.1:54322/postgres)
--
-- Requires schema.sql and policies.sql to be applied first.
-- Everything runs inside one transaction and is ROLLED BACK at the end, so
-- no test users or rows remain. Output: one PASS/FAIL row per check; the
-- script raises an error if any check failed.
-- =====================================================================
begin;

-- ---------------------------------------------------------------------
-- Mini test harness (functions run as the *invoking* role, on purpose)
-- ---------------------------------------------------------------------
create schema rls_test;

create table rls_test.results (
  id     bigint generated always as identity primary key,
  label  text    not null,
  passed boolean not null,
  detail text
);

grant usage on schema rls_test to authenticated, anon;
grant insert on rls_test.results to authenticated, anon;

create function rls_test.record(p_label text, p_passed boolean, p_detail text default null)
returns void language sql as $$
  insert into rls_test.results (label, passed, detail) values (p_label, p_passed, p_detail);
$$;

-- Passes when the statement (SELECT, or DML ... RETURNING) yields exactly p_expected rows.
create function rls_test.expect_count(p_sql text, p_expected bigint, p_label text)
returns void language plpgsql as $$
declare n bigint;
begin
  begin
    execute 'with x as (' || p_sql || ') select count(*) from x' into n;
  exception when others then
    perform rls_test.record(p_label, false, 'unexpected error ' || sqlstate || ': ' || sqlerrm);
    return;
  end;
  perform rls_test.record(
    p_label, n = p_expected,
    case when n = p_expected then null else format('expected %s row(s), got %s', p_expected, n) end);
end $$;

-- Passes when the statement raises exactly the expected SQLSTATE.
create function rls_test.expect_error(p_sql text, p_state text, p_label text)
returns void language plpgsql as $$
begin
  begin
    execute p_sql;
  exception when others then
    perform rls_test.record(
      p_label, sqlstate = p_state,
      case when sqlstate = p_state then null
           else format('expected SQLSTATE %s, got %s (%s)', p_state, sqlstate, sqlerrm) end);
    return;
  end;
  perform rls_test.record(p_label, false, 'statement succeeded but should have been rejected');
end $$;

-- Passes when the single value returned (as text) equals p_expected.
create function rls_test.expect_value(p_sql text, p_expected text, p_label text)
returns void language plpgsql as $$
declare v text;
begin
  begin
    execute p_sql into v;
  exception when others then
    perform rls_test.record(p_label, false, 'unexpected error ' || sqlstate || ': ' || sqlerrm);
    return;
  end;
  perform rls_test.record(
    p_label, v is not distinct from p_expected,
    case when v is not distinct from p_expected then null
         else format('expected %L, got %L', p_expected, v) end);
end $$;

-- Impersonation (same mechanism Supabase uses: JWT claims + role switch).
create function rls_test.act_as(p_uid uuid) returns void language plpgsql as $$
begin
  perform set_config('request.jwt.claims', json_build_object('sub', p_uid, 'role', 'authenticated')::text, true);
  perform set_config('request.jwt.claim.sub', p_uid::text, true);
  perform set_config('request.jwt.claim.role', 'authenticated', true);
  perform set_config('role', 'authenticated', true);
end $$;

create function rls_test.act_as_anon() returns void language plpgsql as $$
begin
  perform set_config('request.jwt.claims', '{"role":"anon"}', true);
  perform set_config('request.jwt.claim.sub', '', true);
  perform set_config('request.jwt.claim.role', 'anon', true);
  perform set_config('role', 'anon', true);
end $$;

grant execute on all functions in schema rls_test to authenticated, anon;

-- ---------------------------------------------------------------------
-- Fixtures (created as the privileged setup role)
-- A = student A, B = student B, C = admin
-- ---------------------------------------------------------------------
insert into auth.users (id, aud, role, email) values
  ('00000000-0000-0000-0000-00000000000a', 'authenticated', 'authenticated', 'rls-a@test.invalid'),
  ('00000000-0000-0000-0000-00000000000b', 'authenticated', 'authenticated', 'rls-b@test.invalid'),
  ('00000000-0000-0000-0000-00000000000c', 'authenticated', 'authenticated', 'rls-admin@test.invalid');

insert into public.profiles (id, register_number, full_name, email, department) values
  ('00000000-0000-0000-0000-00000000000a', 'RA9999900000001', 'RLS Test A',     'rls-a@test.invalid',     'CSBS'),
  ('00000000-0000-0000-0000-00000000000b', 'RA9999900000002', 'RLS Test B',     'rls-b@test.invalid',     'CSBS'),
  ('00000000-0000-0000-0000-00000000000c', 'RA9999900000003', 'RLS Test Admin', 'rls-admin@test.invalid', 'ADMIN');

insert into public.user_roles (user_id, role) values ('00000000-0000-0000-0000-00000000000c', 'admin');

insert into public.documents (id, student_id, document_name, document_category, file_path, file_type, file_size) values
  ('d0000000-0000-0000-0000-00000000000a', '00000000-0000-0000-0000-00000000000a', 'A doc', 'certification', '00000000-0000-0000-0000-00000000000a/certifications/a.pdf', 'application/pdf', 100),
  ('d0000000-0000-0000-0000-00000000000b', '00000000-0000-0000-0000-00000000000b', 'B doc', 'certification', '00000000-0000-0000-0000-00000000000b/certifications/b.pdf', 'application/pdf', 100);

insert into public.certifications (student_id, certification_name, issuing_organization, document_id) values
  ('00000000-0000-0000-0000-00000000000a', 'A cert', 'Org A', 'd0000000-0000-0000-0000-00000000000a'),
  ('00000000-0000-0000-0000-00000000000b', 'B cert', 'Org B', 'd0000000-0000-0000-0000-00000000000b');

insert into public.internships (student_id, company_name, role) values ('00000000-0000-0000-0000-00000000000b', 'B Corp', 'Intern');

insert into public.academic_records (student_id, semester, subject_code, subject_name, marks, grade, credits) values
  ('00000000-0000-0000-0000-00000000000a', 1, 'T-A1', 'Subject A', 90, 'A+', 4),
  ('00000000-0000-0000-0000-00000000000b', 1, 'T-B1', 'Subject B', 95, 'O', 4);

insert into public.semester_attendance (student_id, semester, attendance_percent) values
  ('00000000-0000-0000-0000-00000000000a', 1, 80), ('00000000-0000-0000-0000-00000000000b', 1, 90);

insert into public.audit_logs (user_id, action, metadata) values
  ('00000000-0000-0000-0000-00000000000a', 'login', '{"test":"rls"}'), ('00000000-0000-0000-0000-00000000000b', 'login', '{"test":"rls"}');

insert into public.document_ai_metadata (document_id, student_id, status) values
  ('d0000000-0000-0000-0000-00000000000a', '00000000-0000-0000-0000-00000000000a', 'done'), ('d0000000-0000-0000-0000-00000000000b', '00000000-0000-0000-0000-00000000000b', 'done');

insert into storage.objects (bucket_id, name) values
  ('students', '00000000-0000-0000-0000-00000000000a/marksheets/a.pdf'),
  ('students', '00000000-0000-0000-0000-00000000000b/marksheets/b.pdf');

-- ---------------------------------------------------------------------
-- Structural guards (as setup role)
-- ---------------------------------------------------------------------
do $$ begin
  perform rls_test.expect_count(
    $q$select 1 from pg_tables where schemaname = 'public' and not rowsecurity$q$, 0,
    'STRUCT: every table in public has RLS enabled');
  perform rls_test.expect_count(
    $q$select 1 from pg_policies where schemaname = 'public' and qual = 'true'
       and tablename not in ('document_categories', 'grade_scale')$q$, 0,
    'STRUCT: no "USING (true)" policy on student data tables');
  perform rls_test.expect_value(
    $q$select "public"::text from storage.buckets where id = 'students'$q$, 'false',
    'STRUCT: students storage bucket is private');
end $$;

-- =====================================================================
-- STUDENT A
-- =====================================================================
select rls_test.act_as('00000000-0000-0000-0000-00000000000a');

do $$ begin
  -- profiles
  perform rls_test.expect_count($q$select 1 from public.profiles$q$, 1, 'A: sees only own profile row');
  perform rls_test.expect_count($q$select 1 from public.profiles where id = '00000000-0000-0000-0000-00000000000b'$q$, 0, 'A: cannot read B profile');
  perform rls_test.expect_count($q$update public.profiles set full_name = 'hacked' where id = '00000000-0000-0000-0000-00000000000b' returning 1$q$, 0, 'A: cannot update B profile');
  perform rls_test.expect_count($q$delete from public.profiles where id = '00000000-0000-0000-0000-00000000000b' returning 1$q$, 0, 'A: cannot delete B profile');
  perform rls_test.expect_count($q$delete from public.profiles where id = '00000000-0000-0000-0000-00000000000a' returning 1$q$, 0, 'A: cannot delete own profile');
  perform rls_test.expect_count($q$update public.profiles set phone = '+919999999999' where id = '00000000-0000-0000-0000-00000000000a' returning 1$q$, 1, 'A: can update own permitted fields (phone)');
  perform rls_test.expect_error($q$update public.profiles set register_number = 'RA9999900000099' where id = '00000000-0000-0000-0000-00000000000a'$q$, '42501', 'A: cannot change own register_number');
  perform rls_test.expect_error($q$update public.profiles set email = 'new@test.invalid' where id = '00000000-0000-0000-0000-00000000000a'$q$, '42501', 'A: cannot change own email');
  perform rls_test.expect_error($q$update public.profiles set department = 'ADMIN' where id = '00000000-0000-0000-0000-00000000000a'$q$, '42501', 'A: cannot change own department');
  perform rls_test.expect_error($q$insert into public.profiles (id, register_number, full_name, email) values (gen_random_uuid(), 'RA9999900000098', 'x', 'x@test.invalid')$q$, '42501', 'A: cannot create profiles');

  -- roles / privilege escalation
  perform rls_test.expect_value($q$select public.is_admin()::text$q$, 'false', 'A: is_admin() is false');
  perform rls_test.expect_count($q$select 1 from public.user_roles$q$, 1, 'A: sees only own role row');
  perform rls_test.expect_error($q$insert into public.user_roles (user_id, role) values ('00000000-0000-0000-0000-00000000000a', 'admin')$q$, '42501', 'A: cannot grant self admin');
  perform rls_test.expect_error($q$update public.user_roles set role = 'admin' where user_id = '00000000-0000-0000-0000-00000000000a'$q$, '42501', 'A: cannot edit own role');

  -- documents
  perform rls_test.expect_count($q$select 1 from public.documents$q$, 1, 'A: sees only own documents');
  perform rls_test.expect_count($q$select 1 from public.documents where id = 'd0000000-0000-0000-0000-00000000000b'$q$, 0, 'A: cannot read B document by id');
  perform rls_test.expect_error($q$insert into public.documents (student_id, document_name, document_category, file_path, file_type, file_size) values ('00000000-0000-0000-0000-00000000000b', 'x', 'other', '00000000-0000-0000-0000-00000000000b/other/x.pdf', 'application/pdf', 10)$q$, '42501', 'A: cannot insert a document owned by B');
  perform rls_test.expect_error($q$insert into public.documents (document_name, document_category, file_path, file_type, file_size) values ('x', 'other', '00000000-0000-0000-0000-00000000000b/other/x.pdf', 'application/pdf', 10)$q$, '23514', 'A: cannot point file_path into B storage folder');
  perform rls_test.expect_value($q$with i as (insert into public.documents (id, document_name, document_category, file_path, file_type, file_size, verification_status) values ('d0000000-0000-0000-0000-0000000000a1', 'self verified', 'other', '00000000-0000-0000-0000-00000000000a/other/sv.pdf', 'application/pdf', 10, 'verified') returning verification_status) select verification_status from i$q$, 'pending', 'A: cannot self-verify on insert (forced to pending)');
  perform rls_test.expect_error($q$update public.documents set verification_status = 'verified' where id = 'd0000000-0000-0000-0000-00000000000a'$q$, '42501', 'A: cannot self-verify existing document');
  perform rls_test.expect_error($q$update public.documents set file_path = '00000000-0000-0000-0000-00000000000b/other/steal.pdf' where id = 'd0000000-0000-0000-0000-00000000000a'$q$, '42501', 'A: cannot re-point own document file_path');
  perform rls_test.expect_error($q$update public.documents set student_id = '00000000-0000-0000-0000-00000000000b' where id = 'd0000000-0000-0000-0000-00000000000a'$q$, '42501', 'A: cannot hand own document to B');
  perform rls_test.expect_count($q$update public.documents set description = 'edited' where id = 'd0000000-0000-0000-0000-00000000000a' returning 1$q$, 1, 'A: can edit own document description');
  perform rls_test.expect_count($q$update public.documents set document_name = 'x' where id = 'd0000000-0000-0000-0000-00000000000b' returning 1$q$, 0, 'A: cannot update B document');
  perform rls_test.expect_count($q$delete from public.documents where id = 'd0000000-0000-0000-0000-00000000000b' returning 1$q$, 0, 'A: cannot delete B document');

  -- student-managed records + cross-student document linking
  perform rls_test.expect_count($q$select 1 from public.certifications$q$, 1, 'A: sees only own certifications');
  perform rls_test.expect_count($q$select 1 from public.internships$q$, 0, 'A: sees none of B internships');
  perform rls_test.expect_error($q$insert into public.certifications (student_id, certification_name, issuing_organization) values ('00000000-0000-0000-0000-00000000000b', 'x', 'y')$q$, '42501', 'A: cannot create certification for B');
  perform rls_test.expect_error($q$insert into public.certifications (certification_name, issuing_organization, document_id) values ('x', 'y', 'd0000000-0000-0000-0000-00000000000b')$q$, '42501', 'A: cannot link own certification to B document');
  perform rls_test.expect_count($q$insert into public.certifications (certification_name, issuing_organization, document_id) values ('linked', 'y', 'd0000000-0000-0000-0000-00000000000a') returning 1$q$, 1, 'A: can link own certification to own document');
  perform rls_test.expect_error($q$update public.certifications set document_id = 'd0000000-0000-0000-0000-00000000000b' where student_id = '00000000-0000-0000-0000-00000000000a'$q$, '42501', 'A: cannot re-link own certification to B document');
  perform rls_test.expect_count($q$update public.internships set role = 'x' where student_id = '00000000-0000-0000-0000-00000000000b' returning 1$q$, 0, 'A: cannot update B internship');
  perform rls_test.expect_count($q$delete from public.internships where student_id = '00000000-0000-0000-0000-00000000000b' returning 1$q$, 0, 'A: cannot delete B internship');
  perform rls_test.expect_error($q$insert into public.hackathons (hackathon_name, report_document_id) values ('h', 'd0000000-0000-0000-0000-00000000000b')$q$, '42501', 'A: cannot link hackathon report to B document');
  perform rls_test.expect_error($q$insert into public.projects (project_title, report_document_id) values ('p', 'd0000000-0000-0000-0000-00000000000b')$q$, '42501', 'A: cannot link project report to B document');

  -- academic data: read-only for students
  perform rls_test.expect_count($q$select 1 from public.academic_records$q$, 1, 'A: sees only own academic records');
  perform rls_test.expect_count($q$select 1 from public.academic_records where student_id = '00000000-0000-0000-0000-00000000000b'$q$, 0, 'A: cannot read B academic records');
  perform rls_test.expect_error($q$insert into public.academic_records (student_id, semester, subject_code, subject_name, marks, grade, credits) values ('00000000-0000-0000-0000-00000000000a', 2, 'X', 'X', 99, 'O', 4)$q$, '42501', 'A: cannot insert own marks');
  perform rls_test.expect_count($q$update public.academic_records set marks = 100 where student_id = '00000000-0000-0000-0000-00000000000a' returning 1$q$, 0, 'A: cannot edit own marks');
  perform rls_test.expect_count($q$delete from public.academic_records where student_id = '00000000-0000-0000-0000-00000000000a' returning 1$q$, 0, 'A: cannot delete own marks');
  perform rls_test.expect_count($q$select 1 from public.semester_attendance$q$, 1, 'A: sees only own attendance');
  perform rls_test.expect_error($q$insert into public.semester_attendance (student_id, semester, attendance_percent) values ('00000000-0000-0000-0000-00000000000a', 2, 100)$q$, '42501', 'A: cannot insert own attendance');

  -- views must honour RLS (security_invoker)
  perform rls_test.expect_count($q$select 1 from public.semester_gpa$q$, 1, 'A: semester_gpa view shows only own rows');
  perform rls_test.expect_count($q$select 1 from public.semester_gpa where student_id = '00000000-0000-0000-0000-00000000000b'$q$, 0, 'A: semester_gpa view hides B rows');
  perform rls_test.expect_value($q$select cgpa::text from public.student_cgpa$q$, '9.00', 'A: CGPA computed from own records only');

  -- audit log + AI metadata are read-only
  perform rls_test.expect_count($q$select 1 from public.audit_logs$q$, 1, 'A: sees only own audit rows');
  perform rls_test.expect_count($q$select 1 from public.audit_logs where user_id = '00000000-0000-0000-0000-00000000000b'$q$, 0, 'A: cannot read B audit rows');
  perform rls_test.expect_error($q$insert into public.audit_logs (user_id, action) values ('00000000-0000-0000-0000-00000000000a', 'forged')$q$, '42501', 'A: cannot forge audit entries');
  perform rls_test.expect_error($q$delete from public.audit_logs where user_id = '00000000-0000-0000-0000-00000000000a'$q$, '42501', 'A: cannot delete audit entries');
  perform rls_test.expect_count($q$select 1 from public.document_ai_metadata$q$, 1, 'A: sees only own AI metadata');
  perform rls_test.expect_error($q$insert into public.document_ai_metadata (document_id, student_id) values ('d0000000-0000-0000-0000-00000000000a', '00000000-0000-0000-0000-00000000000a')$q$, '42501', 'A: cannot write AI metadata');

  -- lookup tables
  perform rls_test.expect_count($q$select 1 from public.document_categories where code = 'certification'$q$, 1, 'A: can read categories');
  perform rls_test.expect_error($q$insert into public.document_categories (code, label, storage_folder) values ('evil', 'Evil', 'evil')$q$, '42501', 'A: cannot create categories');
  perform rls_test.expect_count($q$update public.grade_scale set points = 10 where grade = 'F' returning 1$q$, 0, 'A: cannot change the grade scale');

  -- storage
  perform rls_test.expect_count($q$select 1 from storage.objects where bucket_id = 'students' and name like '00000000-0000-0000-0000-00000000000a/%'$q$, 1, 'A: sees own storage objects');
  perform rls_test.expect_count($q$select 1 from storage.objects where bucket_id = 'students' and name like '00000000-0000-0000-0000-00000000000b/%'$q$, 0, 'A: cannot see B storage objects');
  perform rls_test.expect_error($q$insert into storage.objects (bucket_id, name) values ('students', '00000000-0000-0000-0000-00000000000b/marksheets/evil.pdf')$q$, '42501', 'A: cannot upload into B storage folder');
  perform rls_test.expect_count($q$insert into storage.objects (bucket_id, name) values ('students', '00000000-0000-0000-0000-00000000000a/marksheets/a2.pdf') returning 1$q$, 1, 'A: can upload into own storage folder');
  perform rls_test.expect_count($q$delete from storage.objects where bucket_id = 'students' and name = '00000000-0000-0000-0000-00000000000b/marksheets/b.pdf' returning 1$q$, 0, 'A: cannot delete B storage object');
end $$;

reset role;

-- =====================================================================
-- STUDENT B (symmetry spot-checks: isolation must hold in both directions)
-- =====================================================================
select rls_test.act_as('00000000-0000-0000-0000-00000000000b');

do $$ begin
  perform rls_test.expect_count($q$select 1 from public.documents$q$, 1, 'B: sees only own documents');
  perform rls_test.expect_count($q$select 1 from public.documents where student_id = '00000000-0000-0000-0000-00000000000a'$q$, 0, 'B: cannot read A documents');
  perform rls_test.expect_count($q$select 1 from public.certifications where student_id = '00000000-0000-0000-0000-00000000000a'$q$, 0, 'B: cannot read A certifications');
  perform rls_test.expect_value($q$select cgpa::text from public.student_cgpa$q$, '10.00', 'B: CGPA computed from own records only');
  perform rls_test.expect_count($q$select 1 from storage.objects where bucket_id = 'students' and name like '00000000-0000-0000-0000-00000000000a/%'$q$, 0, 'B: cannot see A storage objects');
end $$;

reset role;

-- =====================================================================
-- ANONYMOUS
-- =====================================================================
select rls_test.act_as_anon();

do $$ begin
  perform rls_test.expect_error($q$select 1 from public.profiles limit 1$q$, '42501', 'ANON: cannot read profiles');
  perform rls_test.expect_error($q$select 1 from public.documents limit 1$q$, '42501', 'ANON: cannot read documents');
  perform rls_test.expect_error($q$select 1 from public.academic_records limit 1$q$, '42501', 'ANON: cannot read academic records');
  perform rls_test.expect_error($q$select public.is_admin()$q$, '42501', 'ANON: cannot call is_admin()');
  perform rls_test.expect_count($q$select 1 from storage.objects where bucket_id = 'students'$q$, 0, 'ANON: sees no student files');
end $$;

reset role;

-- =====================================================================
-- ADMIN
-- =====================================================================
select rls_test.act_as('00000000-0000-0000-0000-00000000000c');

do $$ begin
  perform rls_test.expect_value($q$select public.is_admin()::text$q$, 'true', 'ADMIN: is_admin() is true');
  perform rls_test.expect_count($q$select 1 from public.profiles where id in ('00000000-0000-0000-0000-00000000000a', '00000000-0000-0000-0000-00000000000b')$q$, 2, 'ADMIN: can read student profiles');
  perform rls_test.expect_count($q$select 1 from public.documents where id in ('d0000000-0000-0000-0000-00000000000a', 'd0000000-0000-0000-0000-00000000000b')$q$, 2, 'ADMIN: can read student document metadata');
  perform rls_test.expect_count($q$update public.documents set verification_status = 'verified' where id = 'd0000000-0000-0000-0000-00000000000a' returning 1$q$, 1, 'ADMIN: can verify a document');
  perform rls_test.expect_value($q$select verification_status from public.documents where id = 'd0000000-0000-0000-0000-00000000000a'$q$, 'verified', 'ADMIN: verification persisted');
  perform rls_test.expect_count($q$delete from public.documents where id = 'd0000000-0000-0000-0000-00000000000a' returning 1$q$, 0, 'ADMIN: cannot delete student documents');
  perform rls_test.expect_count($q$insert into public.academic_records (student_id, semester, subject_code, subject_name, marks, grade, credits) values ('00000000-0000-0000-0000-00000000000a', 2, 'T-A2', 'Subject A2', 80, 'A', 3) returning 1$q$, 1, 'ADMIN: can add academic records');
  perform rls_test.expect_count($q$update public.academic_records set marks = 91 where student_id = '00000000-0000-0000-0000-00000000000a' and subject_code = 'T-A2' returning 1$q$, 1, 'ADMIN: can edit academic records');
  perform rls_test.expect_count($q$update public.profiles set city = 'Test City' where id = '00000000-0000-0000-0000-00000000000a' returning 1$q$, 1, 'ADMIN: can update student profile');
  perform rls_test.expect_error($q$insert into public.user_roles (user_id, role) values ('00000000-0000-0000-0000-00000000000a', 'admin')$q$, '42501', 'ADMIN: cannot write roles via the client role');
  perform rls_test.expect_count($q$select 1 from public.audit_logs where user_id in ('00000000-0000-0000-0000-00000000000a', '00000000-0000-0000-0000-00000000000b')$q$, 2, 'ADMIN: can read audit logs');
  perform rls_test.expect_count($q$select 1 from public.document_ai_metadata where student_id in ('00000000-0000-0000-0000-00000000000a', '00000000-0000-0000-0000-00000000000b')$q$, 2, 'ADMIN: can read AI metadata');
  perform rls_test.expect_count($q$select 1 from storage.objects where bucket_id = 'students' and name like '00000000-0000-0000-0000-00000000000a/%'$q$, 2, 'ADMIN: can read student storage objects');
  perform rls_test.expect_error($q$insert into storage.objects (bucket_id, name) values ('students', '00000000-0000-0000-0000-00000000000a/marksheets/planted.pdf')$q$, '42501', 'ADMIN: cannot write into a student storage folder');
end $$;

reset role;

-- ---------------------------------------------------------------------
-- Report
-- ---------------------------------------------------------------------
select case when passed then 'PASS' else 'FAIL' end as result, label, detail
from rls_test.results
order by id;

do $$
declare
  total  int;
  failed int;
begin
  select count(*), count(*) filter (where not passed) into total, failed from rls_test.results;
  raise notice 'RLS isolation: % checks, % failed', total, failed;
  if failed > 0 then
    raise exception 'RLS isolation tests FAILED (% of %)', failed, total;
  end if;
end $$;

rollback;
