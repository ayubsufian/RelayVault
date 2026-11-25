import express from 'express';
import authRouter from './routes/auth.route.js';
import handoffRouter from './routes/handoff.route.js';
import cookieParser from 'cookie-parser';
import { notFound, errorHandler } from './middleware/error.middleware.js';
import { globalApiLimiter } from './middleware/rate-limit.middleware.js';
import { env } from './config/env.js';

const app = express();

app.set('trust proxy', env.trustProxy);

app.use(express.json());
app.use(cookieParser());
app.use('/api', globalApiLimiter);

app.use('/api/v1/auth', authRouter);
app.use('/api/v1/handoffs', handoffRouter);

app.use(notFound);
app.use(errorHandler);

export default app;
