/**
 * Demo data seeder — DEVELOPMENT ONLY.
 * Creates 1 admin + 5 students through the Supabase Admin API (so passwords are
 * hashed by Supabase Auth), then inserts profiles, marks, attendance, typed
 * records and tiny placeholder PDFs into the private `students` bucket.
 *
 * Usage:  SEED_DEMO_PASSWORD='choose-a-strong-one' npm run seed
 * (or put SEED_DEMO_PASSWORD in backend/.env). The password is never stored in code.
 */
import { randomUUID } from 'node:crypto';
import { env } from '../config/env';
import { adminClient } from '../config/supabase';

if (env.NODE_ENV === 'production') {
  console.error('Refusing to seed demo data in production.');
  process.exit(1);
}
const DEMO_PASSWORD = process.env.SEED_DEMO_PASSWORD;
if (!DEMO_PASSWORD || DEMO_PASSWORD.length < 12) {
  console.error('Set SEED_DEMO_PASSWORD (min 12 characters) in backend/.env before seeding.');
  process.exit(1);
}

// Student 1 is the project owner's sample profile (spec section 1); the rest are fictional.
// Emails use the reserved example.com domain; phone numbers are placeholders.
const STUDENTS = [
  { reg: 'RA2411042050001', name: 'KANISKA P', email: 'kaniska.demo@example.com', phone: '+919000000001' },
  { reg: 'RA2411042050002', name: 'Aarav Demo', email: 'aarav.demo@example.com', phone: '+919000000002' },
  { reg: 'RA2411042050003', name: 'Meera Sample', email: 'meera.demo@example.com', phone: '+919000000003' },
  { reg: 'RA2411042050004', name: 'Rohan Test', email: 'rohan.demo@example.com', phone: '+919000000004' },
  { reg: 'RA2411042050005', name: 'Ananya Example', email: 'ananya.demo@example.com', phone: '+919000000005' },
];
const ADMIN = { reg: 'RA0000000000000', name: 'Demo Admin', email: 'admin.demo@example.com' };

const SUBJECTS: Record<number, Array<[string, number]>> = {
  1: [['Calculus and Linear Algebra', 4], ['Programming Fundamentals', 4], ['Engineering Physics', 3], ['Business Communication', 2], ['Digital Logic Basics', 3]],
  2: [['Discrete Mathematics', 4], ['Data Structures', 4], ['Object Oriented Programming', 3], ['Principles of Management', 3], ['Statistics for Business', 3]],
  3: [['Database Management Systems', 4], ['Computer Organization', 3], ['Design and Analysis of Algorithms', 4], ['Financial Accounting', 3], ['Probability and Random Processes', 3]],
  4: [['Operating Systems', 4], ['Computer Networks', 3], ['Software Engineering', 3], ['Business Analytics', 3], ['Microeconomics', 3]],
};

// Demo grade bands only — align with your institution's actual regulations.
const gradeFor = (m: number) => (m >= 91 ? 'O' : m >= 81 ? 'A+' : m >= 71 ? 'A' : m >= 61 ? 'B+' : m >= 56 ? 'B' : m >= 50 ? 'C' : 'F');

const CERTS = [
  ['Data Analytics Fundamentals (Demo)', 'Demo Learning Hub', 'Data Analytics'],
  ['Cloud Essentials Practitioner (Demo)', 'Sample Cloud Academy', 'Cloud Computing'],
  ['Python Programming Specialization (Demo)', 'Demo Learning Hub', 'Programming'],
  ['SQL for Data Science (Demo)', 'Sample Cloud Academy', 'Databases'],
] as const;

/** Minimal valid single-page PDF with an xref table (ASCII only, so string length = byte offsets). */
function demoPdf(text: string): Buffer {
  const safe = text.replace(/[^\x20-\x7E]/g, '').replace(/[()\\]/g, '');
  const stream = `BT /F1 14 Tf 20 60 Td (${safe}) Tj ET`;
  const objs = [
    '<< /Type /Catalog /Pages 2 0 R >>',
    '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
    '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 420 120] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>',
    `<< /Length ${stream.length} >>\nstream\n${stream}\nendstream`,
    '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>',
  ];
  let pdf = '%PDF-1.4\n';
  const offsets: number[] = [];
  objs.forEach((o, i) => {
    offsets.push(pdf.length);
    pdf += `${i + 1} 0 obj\n${o}\nendobj\n`;
  });
  const xrefPos = pdf.length;
  pdf += `xref\n0 ${objs.length + 1}\n0000000000 65535 f \n`;
  pdf += offsets.map((o) => `${String(o).padStart(10, '0')} 00000 n \n`).join('');
  pdf += `trailer\n<< /Size ${objs.length + 1} /Root 1 0 R >>\nstartxref\n${xrefPos}\n%%EOF\n`;
  return Buffer.from(pdf, 'latin1');
}

function must<T>(r: { data: T | null; error: { message?: string } | null }, what: string): T {
  if (r.error) throw new Error(`${what}: ${r.error.message ?? 'unknown error'}`);
  return r.data as T;
}

async function createUserWithProfile(
  reg: string,
  name: string,
  email: string,
  extra: Record<string, unknown>,
): Promise<string | null> {
  const existing = await adminClient.from('profiles').select('id').eq('register_number', reg).maybeSingle();
  if (existing.data) {
    console.log(`  skip ${reg} (already exists)`);
    return null;
  }
  const created = await adminClient.auth.admin.createUser({ email, password: DEMO_PASSWORD!, email_confirm: true });
  if (created.error || !created.data.user) throw new Error(`createUser ${reg}: ${created.error?.message}`);
  const id = created.data.user.id;

  const ins = await adminClient
    .from('profiles')
    .insert({ id, register_number: reg, full_name: name, email, ...extra });
  if (ins.error) {
    await adminClient.auth.admin.deleteUser(id); // avoid orphaned auth user
    throw new Error(`profile ${reg}: ${ins.error.message}`);
  }
  return id;
}

async function addDoc(
  studentId: string,
  category: string,
  folder: string,
  name: string,
  type: string,
  org: string | null,
  issueDate: string | null,
): Promise<string> {
  const id = randomUUID();
  const safeName = name.replace(/[^A-Za-z0-9._-]+/g, '_');
  const path = `${studentId}/${folder}/${id}_${safeName}.pdf`;
  const body = demoPdf(`DEMO DOCUMENT - ${name}`);

  const up = await adminClient.storage.from('students').upload(path, body, { contentType: 'application/pdf' });
  if (up.error) throw new Error(`upload ${name}: ${up.error.message}`);

  const row = await adminClient
    .from('documents')
    .insert({
      id,
      student_id: studentId,
      document_name: name,
      document_category: category,
      document_type: type,
      description: 'Placeholder document generated by the seed script.',
      organization: org,
      issue_date: issueDate,
      file_path: path,
      file_type: 'application/pdf',
      file_size: body.length,
      verification_status: 'verified',
    })
    .select('id')
    .single();
  return (must(row, `document ${name}`) as { id: string }).id;
}

async function seedStudent(idx: number, id: string) {
  const s = idx + 1;

  // Academic records (semesters 1-4 completed) + attendance
  const records: Record<string, unknown>[] = [];
  const attendance: Record<string, unknown>[] = [];
  for (const [semStr, subjects] of Object.entries(SUBJECTS)) {
    const sem = Number(semStr);
    subjects.forEach(([subjectName, credits], i) => {
      const marks = 55 + ((s * 17 + sem * 13 + i * 7) % 45); // deterministic 55..99
      records.push({
        student_id: id, semester: sem, subject_code: `DEMO-S${sem}-0${i + 1}`,
        subject_name: subjectName, marks, grade: gradeFor(marks), credits,
      });
    });
    attendance.push({ student_id: id, semester: sem, attendance_percent: 78 + ((s * 5 + sem * 3) % 20) });
  }
  must(await adminClient.from('academic_records').insert(records).select('id'), 'academic_records');
  must(await adminClient.from('semester_attendance').insert(attendance).select('id'), 'semester_attendance');

  // Marksheets (documents only — dedicated category, never mixed with certificates)
  for (let sem = 1; sem <= 4; sem++) {
    await addDoc(id, 'marksheet', 'marksheets', `Semester ${sem} Marksheet`, 'Marksheet', 'Demo University', `${2024 + Math.floor(sem / 2)}-${sem % 2 ? '12' : '05'}-20`);
  }

  // Certifications (2 per student)
  for (const k of [idx % CERTS.length, (idx + 1) % CERTS.length]) {
    const [name, org, domain] = CERTS[k]!;
    const docId = await addDoc(id, 'certification', 'certifications', name, 'Course Certificate', org, '2025-08-15');
    must(await adminClient.from('certifications').insert({
      student_id: id, certification_name: name, issuing_organization: org, issue_date: '2025-08-15',
      credential_id: `DEMO-${s}${k}-${domain.slice(0, 3).toUpperCase()}`, document_id: docId,
    }).select('id'), 'certifications');
  }

  // Internship
  const internDoc = await addDoc(id, 'internship', 'internships', 'Internship Certificate - Example Tech', 'Internship Certificate', 'Example Tech Pvt Ltd (Demo)', '2025-06-27');
  must(await adminClient.from('internships').insert({
    student_id: id, company_name: 'Example Tech Pvt Ltd (Demo)', role: 'Data Analyst Intern', domain: 'Data Analytics',
    start_date: '2025-05-05', end_date: '2025-06-27', description: 'Demo internship record.', document_id: internDoc,
  }).select('id'), 'internships');

  // Workshop
  const wsDoc = await addDoc(id, 'workshop', 'workshops', 'Python for Data Science Workshop', 'Participation Certificate', 'Demo University CSBS Dept', '2025-09-13');
  must(await adminClient.from('workshops').insert({
    student_id: id, workshop_name: 'Python for Data Science Workshop', organizer: 'Demo University CSBS Dept',
    domain: 'Data Science', workshop_date: '2025-09-13', description: 'Demo workshop record.', document_id: wsDoc,
  }).select('id'), 'workshops');

  // Hackathon
  const hackDoc = await addDoc(id, 'hackathon', 'hackathons', 'Demo Hack 2025 Certificate', 'Participation Certificate', 'Demo Tech Club', '2025-11-08');
  must(await adminClient.from('hackathons').insert({
    student_id: id, hackathon_name: 'Demo Hack 2025', organizer: 'Demo Tech Club', event_date: '2025-11-08',
    position: 'Finalist', project_name: 'Smart Campus Assistant', document_id: hackDoc,
  }).select('id'), 'hackathons');

  // Project + report
  const reportDoc = await addDoc(id, 'project', 'projects', 'Smart Campus Assistant - Project Report', 'Project Report', null, '2025-12-01');
  must(await adminClient.from('projects').insert({
    student_id: id, project_title: 'Smart Campus Assistant', domain: 'AI / Web',
    description: 'Demo project record.', technologies: ['React', 'Node.js', 'PostgreSQL'],
    github_url: 'https://github.com/example/smart-campus-assistant-demo', report_document_id: reportDoc,
  }).select('id'), 'projects');

  // Achievement
  must(await adminClient.from('achievements').insert({
    student_id: id, title: 'Dean\'s List (Demo)', organization: 'Demo University', achieved_on: '2025-06-30',
    description: 'Demo achievement record.',
  }).select('id'), 'achievements');
}

async function main() {
  console.log('Seeding EduVault demo data...');

  const adminId = await createUserWithProfile(ADMIN.reg, ADMIN.name, ADMIN.email, { department: 'ADMIN' });
  if (adminId) {
    must(await adminClient.from('user_roles').insert({ user_id: adminId, role: 'admin' }).select('user_id'), 'admin role');
    console.log(`  admin  ${ADMIN.reg}`);
  }

  for (const [idx, st] of STUDENTS.entries()) {
    const id = await createUserWithProfile(st.reg, st.name, st.email, {
      phone: st.phone, department: 'CSBS', course: 'B.Tech CSBS', year: 3, semester: 5, section: 'A',
      city: 'Demo City', state: 'Demo State', country: 'India',
    });
    if (!id) continue;
    await seedStudent(idx, id);
    console.log(`  student ${st.reg}  ${st.name}`);
  }

  console.log('\nDone. Log in with a register number above and the password you set in SEED_DEMO_PASSWORD.');
}

main().catch((e) => {
  console.error('Seed failed:', e instanceof Error ? e.message : e);
  process.exit(1);
});
