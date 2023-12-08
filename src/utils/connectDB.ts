import mongoose from 'mongoose';
import config from 'config';

const dbUrl = `${process.env.DB_URL}`;

const connectDB = async () => {
  try {
    console.log("dbUrl ",dbUrl)
    await mongoose.connect(dbUrl);
    console.log('Database connected...');
  } catch (error: any) {
    console.log(error.message);
    setTimeout(connectDB, 5000);
  }
};

export default connectDB;
