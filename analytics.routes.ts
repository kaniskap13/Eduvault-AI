import { Router } from 'express';
import { getAnalytics } from '../controllers/academics.controller';

const router = Router();
router.get('/', getAnalytics);
export default router;
