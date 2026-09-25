# EduVault AI

AI-ready student academic information & document management system.
Student sign-in is by **Register Number + Password**; each student's data and
files are isolated by PostgreSQL Row Level Security *and* by explicit
`student_id` filters in the API (defense in depth against admin RLS policies).

## What's implemented

- `database/schema.sql` — full schema: profiles, documents, academic records,
  certifications, internships, workshops, hackathons, projects, achievements,
  AI metadata, audit log, SGPA/CGPA views.
- `database/policies.sql` — Row Level Security for every table + private
  Supabase Storage bucket policies (`students/{student_id}/{category}/...`).
- `database/tests/rls_isolation.sql` — 86 automated checks that Student A
  cannot read/write/link to Student B's data, anon has no access, and admin
  has exactly the access it should (read + verify, not delete/impersonate).
- `backend/` — Express + TypeScript API: auth (register number → email →
  Supabase Auth), profile, document upload/list/preview/download/delete with
  magic-byte file validation, academic records (read-only for students),
  certifications/internships/workshops/hackathons/projects/achievements CRUD,
  analytics, audit logging, a demo-data seed script.
- `eduvault-preview.html` (repo root's sibling, also attached separately) —
  a clickable **frontend preview** with in-memory sample data. It is not yet
  wired to the backend above.

## Not yet built

- Global `/api/search` and `/api/admin/*` endpoints (the preview's search
  and admin screens currently run on local sample data only).
- The real React/Vite frontend wired to the Express API.
- The AI service layer (OCR, classification) — currently only mocked in the
  frontend preview via filename pattern-matching.
- API-level isolation tests (the SQL-level suite above is done).

## Running the backend

```bash
cd database   # run schema.sql then policies.sql against your Supabase project
cd ../backend
cp ../.env.example .env   # fill in Supabase URL + keys, set SEED_DEMO_PASSWORD
npm install
npm run seed   # creates 1 admin + 5 demo students with sample records
npm run dev
```

Run the RLS isolation suite (development database only):
```bash
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f database/tests/rls_isolation.sql
# or: npm run test:rls   (from backend/, using DATABASE_URL in .env)
```

See `.env.example` for every environment variable and where it's used
(backend-only vs frontend-safe).
