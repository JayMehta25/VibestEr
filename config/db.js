import mongoose from 'mongoose';
import dotenv from 'dotenv';

// Load environment variables from .env file
dotenv.config();

// Accept URI explicitly so callers can provide a fallback when env is missing
const connectDB = async (uri) => {
  try {
    const mongoUri = uri || process.env.MONGODB_URI;
    if (!mongoUri) {
      throw new Error('MONGODB_URI is not set. Provide it via .env or pass it to connectDB(uri).');
    }

    // Modern Mongoose (v6+) doesn't need the options
    await mongoose.connect(mongoUri);
    console.log('Connected to MongoDB');

    // Optional: Add connection event listeners
    mongoose.connection.on('connected', () => {
      console.log('Mongoose connected to DB');
    });

    mongoose.connection.on('error', (err) => {
      console.error('Mongoose connection error:', err);
    });

  } catch (error) {
    console.error('Initial MongoDB connection error:', error.message);
    process.exit(1);
  }
};

export default connectDB;