import mongoose from 'mongoose';
import { env } from './env.js';

const connectDB = async () => {
  const connectionInstance = await mongoose.connect(env.mongodbUri);
  console.log(`MongoDB connected ${connectionInstance.connection.host}`);
};

export default connectDB;
