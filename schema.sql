-- =====================================================================
-- EduVault AI — database/schema.sql
-- Run order: schema.sql -> policies.sql -> seed.sql
-- Target: Supabase (PostgreSQL 15+). Intended for a fresh database.
-- =====================================================================

create extension if not exists pg_trgm;

-- ---------------------------------------------------------------------
-- Roles (separate table: students must never be able to write this)
-- ---------------------------------------------------------------------
create type public.app_role as enum ('student', 'admin');

create table public.user_roles (
  user_id uuid not null references auth.users(id) on delete cascade,
  role    public.app_role not null default 'student',
  primary key (user_id, role)
);

-- ---------------------------------------------------------------------
-- Helper functions
-- ---------------------------------------------------------------------
create or replace function public.set_updated_at()
returns trigger language plpgsql as $$
begin
  new.updated_at = now();
  return new;
end $$;

create or replace function public.is_admin()
returns boolean language sql stable security definer set search_path = '' as $$
  select exists (
    select 1 from public.user_roles
    where user_id = auth.uid() and role = 'admin'
  );
$$;
revoke all on function public.is_admin() from public;
grant execute on function public.is_admin() to authenticated;

-- ---------------------------------------------------------------------
-- Lookup tables
-- ---------------------------------------------------------------------
create table public.document_categories (
  code           text primary key,
  label          text not null,
  storage_folder text not null unique,
  sort_order     smallint not null default 0,
  is_active      boolean not null default true
);

insert into public.document_categories (code, label, storage_folder, sort_order) values
  ('certification', 'Certification', 'certifications', 1),
  ('internship',    'Internship',    'internships',    2),
  ('workshop',      'Workshop',      'workshops',      3),
  ('hackathon',     'Hackathon',     'hackathons',     4),
  ('marksheet',     'Marksheet',     'marksheets',     5),
  ('project',       'Project',       'projects',       6),
  ('achievement',   'Achievement',   'achievements',   7),
  ('research',      'Research',      'research',       8),
  ('other',         'Other',         'other',          9);

-- 10-point scale assumed — verify against your institution's regulations.
create table public.grade_scale (
  grade  text primary key,
  points numeric(3,1) not null check (points between 0 and 10)
);

insert into public.grade_scale (grade, points) values
  ('O', 10), ('A+', 9), ('A', 8), ('B+', 7), ('B', 6), ('C', 5), ('F', 0);

-- ---------------------------------------------------------------------
-- profiles  (id = auth.users.id)
-- ---------------------------------------------------------------------
create table public.profiles (
  id                 uuid primary key references auth.users(id) on delete cascade,
  register_number    text not null unique check (register_number ~ '^RA[0-9]{13}$'),
  full_name          text not null check (char_length(full_name) between 1 and 120),
  email              text not null check (email ~* '^[^@\s]+@[^@\s]+\.[^@\s]+$'),
  phone              text check (phone is null or phone ~ '^\+?[0-9]{7,15}$'),
  date_of_birth      date check (date_of_birth is null or date_of_birth > date '1900-01-01'),
  department         text not null default 'CSBS',
  course             text,
  year               smallint check (year between 1 and 6),
  semester           smallint check (semester between 1 and 12),
  section            text,
  address            text check (char_length(address) <= 500),
  city               text,
  state              text,
  country            text,
  postal_code        text,
  profile_photo_path text,
  created_at         timestamptz not null default now(),
  updated_at         timestamptz not null default now()
);

create function public.assign_default_role()
returns trigger language plpgsql security definer set search_path = '' as $$
begin
  insert into public.user_roles (user_id, role) values (new.id, 'student')
  on conflict do nothing;
  return new;
end $$;

create trigger trg_profiles_default_role
  after insert on public.profiles
  for each row execute function public.assign_default_role();

-- Students may edit personal details, but not identity/institutional fields.
-- auth.uid() is null for the service role, which is allowed through.
create function public.protect_profile_columns()
returns trigger language plpgsql set search_path = '' as $$
begin
  if auth.uid() is not null and not public.is_admin() then
    if new.id              is distinct from old.id
    or new.register_number is distinct from old.register_number
    or new.email           is distinct from old.email
    or new.department      is distinct from old.department then
      raise exception 'Not permitted' using errcode = '42501';
    end if;
  end if;
  return new;
end $$;

create trigger trg_profiles_protect
  before update on public.profiles
  for each row execute function public.protect_profile_columns();

-- ---------------------------------------------------------------------
-- documents  (metadata only; files live in Supabase Storage)
-- ---------------------------------------------------------------------
create table public.documents (
  id                  uuid primary key default gen_random_uuid(),
  student_id          uuid not null default auth.uid() references public.profiles(id) on delete cascade,
  document_name       text not null check (char_length(document_name) between 1 and 200),
  document_category   text not null references public.document_categories(code),
  document_type       text check (char_length(document_type) <= 100),
  description         text check (char_length(description) <= 2000),
  organization        text check (char_length(organization) <= 200),
  issue_date          date,
  file_path           text not null unique,
  file_type           text not null check (file_type in (
                        'application/pdf', 'image/jpeg', 'image/png',
                        'application/msword',
                        'application/vnd.openxmlformats-officedocument.wordprocessingml.document')),
  file_size           bigint not null check (file_size > 0 and file_size <= 10485760),
  verification_status text not null default 'pending'
                        check (verification_status in ('pending', 'verified', 'rejected')),
  upload_date         timestamptz not null default now(),
  created_at          timestamptz not null default now(),
  updated_at          timestamptz not null default now(),
  search_vector       tsvector generated always as (
                        to_tsvector('simple',
                          coalesce(document_name, '') || ' ' ||
                          coalesce(document_type, '') || ' ' ||
                          coalesce(organization, '')  || ' ' ||
                          coalesce(description, ''))
                      ) stored,
  -- A file path must live inside the owner's own storage folder.
  constraint documents_path_in_own_folder check (file_path like student_id::text || '/%')
);

create index idx_documents_student_category on public.documents (student_id, document_category);
create index idx_documents_search           on public.documents using gin (search_vector);
create index idx_documents_name_trgm        on public.documents using gin (document_name gin_trgm_ops);

-- Students cannot self-verify or re-point a document.
create function public.protect_document_columns()
returns trigger language plpgsql set search_path = '' as $$
begin
  if auth.uid() is not null and not public.is_admin() then
    if tg_op = 'INSERT' then
      new.verification_status := 'pending';
    elsif new.student_id          is distinct from old.student_id
       or new.file_path           is distinct from old.file_path
       or new.file_type           is distinct from old.file_type
       or new.file_size           is distinct from old.file_size
       or new.verification_status is distinct from old.verification_status then
      raise exception 'Not permitted' using errcode = '42501';
    end if;
  end if;
  return new;
end $$;

create trigger trg_documents_protect
  before insert or update on public.documents
  for each row execute function public.protect_document_columns();

-- Used by RLS: a record may only link to a document the same student owns.
create or replace function public.owns_document(p_document_id uuid)
returns boolean language sql stable security definer set search_path = '' as $$
  select p_document_id is null or exists (
    select 1 from public.documents
    where id = p_document_id and student_id = auth.uid()
  );
$$;
revoke all on function public.owns_document(uuid) from public;
grant execute on function public.owns_document(uuid) to authenticated;

-- ---------------------------------------------------------------------
-- Academic data (written by admins; read-only for students)
-- ---------------------------------------------------------------------
create table public.academic_records (
  id           uuid primary key default gen_random_uuid(),
  student_id   uuid not null references public.profiles(id) on delete cascade,
  semester     smallint not null check (semester between 1 and 12),
  subject_code text not null check (char_length(subject_code) between 1 and 30),
  subject_name text not null check (char_length(subject_name) between 1 and 200),
  marks        numeric(5,2) check (marks between 0 and 100),
  grade        text references public.grade_scale(grade),
  credits      numeric(3,1) not null check (credits > 0 and credits <= 10),
  created_at   timestamptz not null default now(),
  updated_at   timestamptz not null default now(),
  unique (student_id, semester, subject_code)
);
create index idx_academic_student_sem on public.academic_records (student_id, semester);

create table public.semester_attendance (
  id                 uuid primary key default gen_random_uuid(),
  student_id         uuid not null references public.profiles(id) on delete cascade,
  semester           smallint not null check (semester between 1 and 12),
  attendance_percent numeric(5,2) not null check (attendance_percent between 0 and 100),
  created_at         timestamptz not null default now(),
  updated_at         timestamptz not null default now(),
  unique (student_id, semester)
);

-- security_invoker = RLS of the *caller* applies to these views.
create view public.semester_gpa with (security_invoker = true) as
select ar.student_id,
       ar.semester,
       sum(ar.credits) as total_credits,
       round(sum(gs.points * ar.credits) / nullif(sum(ar.credits), 0), 2) as sgpa
from public.academic_records ar
join public.grade_scale gs on gs.grade = ar.grade
group by ar.student_id, ar.semester;

create view public.student_cgpa with (security_invoker = true) as
select ar.student_id,
       sum(ar.credits) as total_credits,
       round(sum(gs.points * ar.credits) / nullif(sum(ar.credits), 0), 2) as cgpa
from public.academic_records ar
join public.grade_scale gs on gs.grade = ar.grade
group by ar.student_id;

-- ---------------------------------------------------------------------
-- Student-managed records
-- ---------------------------------------------------------------------
create table public.certifications (
  id                    uuid primary key default gen_random_uuid(),
  student_id            uuid not null default auth.uid() references public.profiles(id) on delete cascade,
  certification_name    text not null check (char_length(certification_name) between 1 and 200),
  issuing_organization  text not null check (char_length(issuing_organization) <= 200),
  issue_date            date,
  expiry_date           date,
  credential_id         text check (char_length(credential_id) <= 100),
  document_id           uuid references public.documents(id) on delete set null,
  created_at            timestamptz not null default now(),
  updated_at            timestamptz not null default now(),
  check (expiry_date is null or issue_date is null or expiry_date >= issue_date)
);

create table public.internships (
  id            uuid primary key default gen_random_uuid(),
  student_id    uuid not null default auth.uid() references public.profiles(id) on delete cascade,
  company_name  text not null check (char_length(company_name) between 1 and 200),
  role          text not null check (char_length(role) <= 200),
  domain        text,
  start_date    date,
  end_date      date,
  description   text check (char_length(description) <= 2000),
  document_id   uuid references public.documents(id) on delete set null,
  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now(),
  check (end_date is null or start_date is null or end_date >= start_date)
);

create table public.workshops (
  id            uuid primary key default gen_random_uuid(),
  student_id    uuid not null default auth.uid() references public.profiles(id) on delete cascade,
  workshop_name text not null check (char_length(workshop_name) between 1 and 200),
  organizer     text check (char_length(organizer) <= 200),
  domain        text,
  workshop_date date,
  description   text check (char_length(description) <= 2000),
  document_id   uuid references public.documents(id) on delete set null,
  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now()
);

create table public.hackathons (
  id                 uuid primary key default gen_random_uuid(),
  student_id         uuid not null default auth.uid() references public.profiles(id) on delete cascade,
  hackathon_name     text not null check (char_length(hackathon_name) between 1 and 200),
  organizer          text check (char_length(organizer) <= 200),
  event_date         date,
  position           text,
  project_name       text,
  document_id        uuid references public.documents(id) on delete set null,  -- certificate
  report_document_id uuid references public.documents(id) on delete set null,  -- project report
  created_at         timestamptz not null default now(),
  updated_at         timestamptz not null default now()
);

create table public.projects (
  id                 uuid primary key default gen_random_uuid(),
  student_id         uuid not null default auth.uid() references public.profiles(id) on delete cascade,
  project_title      text not null check (char_length(project_title) between 1 and 200),
  domain             text,
  description        text check (char_length(description) <= 4000),
  technologies       text[] not null default '{}',
  github_url         text check (github_url is null or github_url ~* '^https://'),
  project_url        text check (project_url is null or project_url ~* '^https://'),
  document_id        uuid references public.documents(id) on delete set null,  -- certificate
  report_document_id uuid references public.documents(id) on delete set null,  -- project report
  created_at         timestamptz not null default now(),
  updated_at         timestamptz not null default now()
);

create table public.achievements (
  id           uuid primary key default gen_random_uuid(),
  student_id   uuid not null default auth.uid() references public.profiles(id) on delete cascade,
  title        text not null check (char_length(title) between 1 and 200),
  organization text,
  achieved_on  date,
  description  text check (char_length(description) <= 2000),
  document_id  uuid references public.documents(id) on delete set null,
  created_at   timestamptz not null default now(),
  updated_at   timestamptz not null default now()
);

-- ---------------------------------------------------------------------
-- AI metadata (written by the backend AI worker with the service role)
-- ---------------------------------------------------------------------
create table public.document_ai_metadata (
  document_id    uuid primary key references public.documents(id) on delete cascade,
  student_id     uuid not null references public.profiles(id) on delete cascade,
  status         text not null default 'pending'
                   check (status in ('pending', 'processing', 'done', 'failed')),
  provider       text,
  extracted_text text,
  classification jsonb not null default '{}'::jsonb,
  confidence     numeric(4,3) check (confidence between 0 and 1),
  processed_at   timestamptz,
  created_at     timestamptz not null default now()
);

-- ---------------------------------------------------------------------
-- Audit log (no IP/device data collected by default)
-- ---------------------------------------------------------------------
create table public.audit_logs (
  id            bigint generated always as identity primary key,
  user_id       uuid references auth.users(id) on delete set null,
  action        text not null,
  resource_type text,
  resource_id   text,
  metadata      jsonb not null default '{}'::jsonb,
  created_at    timestamptz not null default now()
);
create index idx_audit_user_time on public.audit_logs (user_id, created_at desc);

-- ---------------------------------------------------------------------
-- Generic: student_id indexes + updated_at triggers
-- ---------------------------------------------------------------------
do $$
declare t text;
begin
  foreach t in array array[
    'academic_records','semester_attendance','certifications','internships',
    'workshops','hackathons','projects','achievements','document_ai_metadata'
  ] loop
    execute format('create index idx_%1$s_student on public.%1$I (student_id)', t);
  end loop;

  foreach t in array array[
    'profiles','documents','academic_records','semester_attendance','certifications',
    'internships','workshops','hackathons','projects','achievements'
  ] loop
    execute format(
      'create trigger trg_%1$s_updated_at before update on public.%1$I
         for each row execute function public.set_updated_at()', t);
  end loop;
end $$;
