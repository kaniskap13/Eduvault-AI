import { z, type ZodTypeAny } from 'zod';
import { nonEmpty, optDate, optHttpsUrl, optStr, optUuid, ordered, reqStr } from './common';

export interface RecordEntity {
  table: string;
  /** PostgREST select incl. linked-document embeds (RLS applies to the embed too). */
  select: string;
  orderBy: { column: string; ascending: boolean };
  create: ZodTypeAny;
  update: ZodTypeAny;
}

const DOC = 'document:documents!document_id(id, document_name, file_type)';
const REPORT = 'report:documents!report_document_id(id, document_name, file_type)';

/** Build strict create (all required fields) + update (partial, non-empty) schemas. */
function entity(
  table: string,
  select: string,
  orderBy: RecordEntity['orderBy'],
  shape: z.ZodRawShape,
  dateOrder?: [string, string, string],
): RecordEntity {
  const base = z.object(shape);
  const msg = dateOrder ? { message: dateOrder[2], path: [dateOrder[1]] } : undefined;
  const check = (o: Record<string, string | null | undefined>) =>
    !dateOrder || ordered(dateOrder[0], dateOrder[1])(o);

  return {
    table,
    select,
    orderBy,
    create: base.strict().refine(check, msg),
    update: base.partial().strict().refine(nonEmpty, 'No fields to update').refine(check, msg),
  };
}

// student_id is never part of any schema: it comes from the verified session.
// Linked document ids are re-checked by RLS (owns_document) so they must belong to the caller.
export const RECORD_ENTITIES: Record<string, RecordEntity> = {
  certifications: entity(
    'certifications',
    `*, ${DOC}`,
    { column: 'issue_date', ascending: false },
    {
      certification_name: reqStr(200),
      issuing_organization: reqStr(200),
      issue_date: optDate,
      expiry_date: optDate,
      credential_id: optStr(100),
      document_id: optUuid,
    },
    ['issue_date', 'expiry_date', 'Expiry date must be on or after the issue date'],
  ),
  internships: entity(
    'internships',
    `*, ${DOC}`,
    { column: 'start_date', ascending: false },
    {
      company_name: reqStr(200),
      role: reqStr(200),
      domain: optStr(100),
      start_date: optDate,
      end_date: optDate,
      description: optStr(2000),
      document_id: optUuid,
    },
    ['start_date', 'end_date', 'End date must be on or after the start date'],
  ),
  workshops: entity(
    'workshops',
    `*, ${DOC}`,
    { column: 'workshop_date', ascending: false },
    {
      workshop_name: reqStr(200),
      organizer: optStr(200),
      domain: optStr(100),
      workshop_date: optDate,
      description: optStr(2000),
      document_id: optUuid,
    },
  ),
  hackathons: entity(
    'hackathons',
    `*, ${DOC}, ${REPORT}`,
    { column: 'event_date', ascending: false },
    {
      hackathon_name: reqStr(200),
      organizer: optStr(200),
      event_date: optDate,
      position: optStr(100),
      project_name: optStr(200),
      document_id: optUuid,
      report_document_id: optUuid,
    },
  ),
  projects: entity(
    'projects',
    `*, ${DOC}, ${REPORT}`,
    { column: 'created_at', ascending: false },
    {
      project_title: reqStr(200),
      domain: optStr(100),
      description: optStr(4000),
      technologies: z.array(reqStr(50)).max(30),
      github_url: optHttpsUrl,
      project_url: optHttpsUrl,
      document_id: optUuid,
      report_document_id: optUuid,
    },
  ),
  achievements: entity(
    'achievements',
    `*, ${DOC}`,
    { column: 'achieved_on', ascending: false },
    {
      title: reqStr(200),
      organization: optStr(200),
      achieved_on: optDate,
      description: optStr(2000),
      document_id: optUuid,
    },
  ),
};
