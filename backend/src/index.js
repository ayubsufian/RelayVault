import { env } from './config/env.js';
import connectDB from './config/database.js';
import { connectRedis } from './config/redis.js';
import app from './app.js';

const startServer = async () => {
  try {
    await connectDB();
    await connectRedis();

    const server = app.listen(env.port || 8000, () => {
      console.log(`Server is running on port: ${env.port || 8000}`);
    });

    server.on('error', (error) => {
      console.error('Server failed to start:', error);
      process.exit(1);
    });
  } catch (error) {
    console.error('Application startup failed', error);
    process.exit(1);
  }
};

startServer();
