import { Router } from 'express';
import { getAcademicRecords } from '../controllers/academics.controller';

// Read-only for students by design: marks are written by admins only.
const router = Router();
router.get('/', getAcademicRecords);
export default router;
