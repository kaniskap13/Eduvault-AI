import { AppError, MSG } from './errors';

export interface DetectedType {
  mime: string;
  exts: readonly string[];
}

const startsWith = (buf: Buffer, sig: number[]) =>
  buf.length >= sig.length && sig.every((b, i) => buf[i] === b);

/**
 * Identify a file by its CONTENT (magic bytes), never by the client-supplied
 * MIME type or extension. Returns null for anything not on the allow-list.
 * Note: legacy .doc shares its OLE header with .xls/.ppt; the extension check
 * plus the bucket MIME allow-list narrow this, and malware scanning is a
 * planned hardening step (see README "Future enhancements").
 */
export function detectFileType(buf: Buffer): DetectedType | null {
  if (startsWith(buf, [0x25, 0x50, 0x44, 0x46, 0x2d])) return { mime: 'application/pdf', exts: ['.pdf'] };
  if (startsWith(buf, [0xff, 0xd8, 0xff])) return { mime: 'image/jpeg', exts: ['.jpg', '.jpeg'] };
  if (startsWith(buf, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) return { mime: 'image/png', exts: ['.png'] };
  if (startsWith(buf, [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1])) return { mime: 'application/msword', exts: ['.doc'] };
  // DOCX is a ZIP container; require the Word part name to avoid accepting arbitrary zips.
  if (startsWith(buf, [0x50, 0x4b, 0x03, 0x04]) && buf.includes('word/')) {
    return {
      mime: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      exts: ['.docx'],
    };
  }
  return null;
}

export function fileExtension(original: string): string {
  const m = /\.[A-Za-z0-9]+$/.exec(original);
  return m ? m[0].toLowerCase() : '';
}

/** Storage-safe base name: no path parts, no extension, ASCII only. */
export function safeBaseName(original: string): string {
  const base = original.replace(/\\/g, '/').split('/').pop() ?? '';
  const noExt = base.replace(/\.[^.]*$/, '');
  const cleaned = noExt
    .normalize('NFKD')
    .replace(/[^A-Za-z0-9._-]+/g, '_')
    .replace(/^[._-]+|[._-]+$/g, '')
    .slice(0, 80);
  return cleaned || 'file';
}

/** Human-readable default document name derived from the uploaded file name. */
export function defaultDocumentName(original: string): string {
  const base = (original.replace(/\\/g, '/').split('/').pop() ?? '').replace(/\.[^.]*$/, '');
  // eslint-disable-next-line no-control-regex
  const cleaned = base.replace(/[\u0000-\u001f\u007f]/g, '').trim().slice(0, 200);
  return cleaned || 'Untitled document';
}

export function validateUpload(file: { buffer: Buffer; originalname: string }, maxBytes: number) {
  const size = file.buffer.length;
  if (size === 0) throw new AppError(400, 'EMPTY_FILE', MSG.invalidFile);
  if (size > maxBytes) throw new AppError(413, 'FILE_TOO_LARGE', MSG.fileTooLarge);

  const detected = detectFileType(file.buffer);
  const ext = fileExtension(file.originalname);
  // Content must match an allowed type AND the extension must agree with that content.
  if (!detected || !detected.exts.includes(ext)) {
    throw new AppError(400, 'UNSUPPORTED_FILE_TYPE', MSG.invalidFile);
  }
  return { mime: detected.mime, ext, size, safeBase: safeBaseName(file.originalname) };
}
