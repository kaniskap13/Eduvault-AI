import { describe, expect, it } from 'vitest';
import { detectFileType, safeBaseName, validateUpload } from '../utils/fileValidation';

const pdf = Buffer.from('%PDF-1.4\n1 0 obj\n<<>>\nendobj\n', 'latin1');
const png = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 0]);
const jpg = Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0, 0x10]);
const doc = Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1, 0, 0]);
const docx = Buffer.concat([Buffer.from([0x50, 0x4b, 0x03, 0x04]), Buffer.from('....word/document.xml....')]);
const plainZip = Buffer.concat([Buffer.from([0x50, 0x4b, 0x03, 0x04]), Buffer.from('....other/file.txt....')]);
const exe = Buffer.from('MZ\x90\x00\x03\x00', 'latin1');
const MAX = 10 * 1024 * 1024;

describe('detectFileType', () => {
  it('recognises allowed types by content', () => {
    expect(detectFileType(pdf)?.mime).toBe('application/pdf');
    expect(detectFileType(png)?.mime).toBe('image/png');
    expect(detectFileType(jpg)?.mime).toBe('image/jpeg');
    expect(detectFileType(doc)?.mime).toBe('application/msword');
    expect(detectFileType(docx)?.mime).toContain('wordprocessingml');
  });
  it('rejects executables and arbitrary zips', () => {
    expect(detectFileType(exe)).toBeNull();
    expect(detectFileType(plainZip)).toBeNull();
  });
});

describe('validateUpload', () => {
  it('accepts matching content and extension', () => {
    expect(validateUpload({ buffer: pdf, originalname: 'Cert.PDF' }, MAX).ext).toBe('.pdf');
  });
  it('rejects extension/content mismatch', () => {
    expect(() => validateUpload({ buffer: pdf, originalname: 'photo.jpg' }, MAX)).toThrow();
    expect(() => validateUpload({ buffer: exe, originalname: 'run.pdf' }, MAX)).toThrow();
  });
  it('rejects empty and oversized files', () => {
    expect(() => validateUpload({ buffer: Buffer.alloc(0), originalname: 'a.pdf' }, MAX)).toThrow();
    expect(() => validateUpload({ buffer: pdf, originalname: 'a.pdf' }, 5)).toThrow();
  });
});

describe('safeBaseName', () => {
  it('strips paths, extensions and unsafe characters', () => {
    expect(safeBaseName('../../etc/passwd.pdf')).toBe('passwd');
    expect(safeBaseName('My Cert (final) #1.pdf')).toBe('My_Cert_final_1');
    expect(safeBaseName('....')).toBe('file');
  });
});
