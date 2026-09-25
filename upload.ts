import type { RequestHandler } from 'express';
import multer from 'multer';
import { env } from '../config/env';
import { AppError, MSG } from '../utils/errors';

// Memory storage is fine at a 10 MB cap. Mounted AFTER requireAuth so
// unauthenticated callers can never stream a body into the server.
const uploader = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: env.MAX_UPLOAD_BYTES, files: 1, fields: 10, fieldSize: 10_000 },
});

export const uploadSingle: RequestHandler = (req, res, next) => {
  uploader.single('file')(req, res, (err: unknown) => {
    if (!err) return next();
    if (err instanceof multer.MulterError) {
      if (err.code === 'LIMIT_FILE_SIZE') return next(new AppError(413, 'FILE_TOO_LARGE', MSG.fileTooLarge));
      return next(new AppError(400, 'BAD_UPLOAD', MSG.validation));
    }
    next(err);
  });
};
