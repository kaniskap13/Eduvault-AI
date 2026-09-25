export class AppError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
    public details?: unknown,
  ) {
    super(message);
  }
}

/** User-facing messages. Never include DB errors, stack traces or internals. */
export const MSG = {
  invalidLogin: 'Invalid register number or password.',
  unauthenticated: 'Please sign in to continue.',
  forbidden: 'You do not have permission to perform this action.',
  forbiddenDocument: 'You do not have permission to access this document.',
  notFound: 'The requested item was not found.',
  invalidFile: 'Unsupported file type.',
  fileTooLarge: 'File exceeds the maximum allowed size.',
  network: 'Unable to connect. Please try again.',
  generic: 'Something went wrong. Please try again.',
  validation: 'Some fields are invalid.',
  tooMany: 'Too many attempts. Please try again later.',
  conflict: 'This record already exists.',
} as const;
