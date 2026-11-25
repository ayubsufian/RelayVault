import { createClient } from 'redis';
import { env } from './env.js';

const redisClient = createClient({
  url: env.redisUrl,
});

redisClient.on('error', (error) => {
  console.error('Redis connection error', error);
});

export const connectRedis = async () => {
  if (!redisClient.isOpen) {
    await redisClient.connect();
  }
};

export default redisClient;
