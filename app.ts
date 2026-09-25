import cookieParser from 'cookie-parser';
import cors from 'cors';
import express from 'express';
import helmet from 'helmet';
import { env, isProd } from './config/env';
import { requireAuth } from './middleware/auth';
import { errorHandler, notFound } from './middleware/errorHandler';
import { apiLimiter } from './middleware/rateLimit';
import { requestId } from './middleware/requestId';
import { RECORD_ENTITIES } from './models/records.config';
import academicRoutes from './routes/academics.routes';
import analyticsRoutes from './routes/analytics.routes';
import authRoutes from './routes/auth.routes';
import documentRoutes from './routes/documents.routes';
import profileRoutes from './routes/profile.routes';
import { recordsRouter } from './routes/records.routes';

export const app = express();

app.disable('x-powered-by');
if (isProd) app.set('trust proxy', 1); // set to your real proxy hop count

app.use(helmet());
app.use(requestId);
app.use(
  cors({
    origin: env.CORS_ORIGIN, // single explicit origin — never '*' with credentials
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization'],
  }),
);
app.use(express.json({ limit: '100kb' }));
app.use(cookieParser());
app.use('/api', apiLimiter);

app.get('/api/health', (_req, res) => res.json({ status: 'ok' }));
app.use('/api/auth', authRoutes);

// Everything below requires a verified session.
app.use('/api/profile', requireAuth, profileRoutes);
app.use('/api/documents', requireAuth, documentRoutes);
app.use('/api/academic-records', requireAuth, academicRoutes);
app.use('/api/analytics', requireAuth, analyticsRoutes);
// certifications, internships, workshops, hackathons, projects, achievements
for (const [path, cfg] of Object.entries(RECORD_ENTITIES)) {
  app.use(`/api/${path}`, requireAuth, recordsRouter(cfg));
}
// Next: /api/search, /api/ai/*, /api/admin/*

app.use(notFound);
app.use(errorHandler);
