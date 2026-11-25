import express from 'express';
import authRouter from './routes/auth.route.js';
import handoffRouter from './routes/handoff.route.js';
import cookieParser from 'cookie-parser';
import { notFound, errorHandler } from './middleware/error.middleware.js';

const app = express();

app.use(express.json());
app.use(cookieParser());

app.use('/api/v1/auth', authRouter);
app.use('/api/v1/handoffs', handoffRouter);

app.use(notFound);
app.use(errorHandler);

export default app;
