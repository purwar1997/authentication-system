import mongoose from 'mongoose';
import app from './app';
import config from './config/config';

(async () => {
  try {
    const res = await mongoose.connect(config.MONGODB_URL);

    app.on('error', err => {
      throw err;
    });

    console.log(`Database connection success: ${res.connection.host}`);

    app.listen(config.PORT, () =>
      console.log(`Server is running on http://localhost:${config.PORT}`)
    );
  } catch (err) {
    console.log('Database connection failure');
    console.log(`${err.name}: ${err.message}`);
    process.exit(1);
  }
})();
