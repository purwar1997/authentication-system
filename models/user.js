import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import JWT from 'jsonwebtoken';
import crypto from 'crypto';
import regexp from '../utils/regex';
import config from '../config/config';

const userSchema = new mongoose.Schema(
  {
    firstname: {
      type: String,
      required: [true, 'Firstname is required'],
      lowercase: true,
      trim: true,
    },
    lastname: {
      type: String,
      required: [true, 'Lastname is required'],
      lowercase: true,
      trim: true,
    },
    email: {
      type: String,
      required: [true, 'Email is required'],
      unique: true,
      lowercase: true,
      trim: true,
      validate: {
        validator: email => {
          const regex = new RegExp(regexp.email);
          return regex.test(email);
        },
        message: 'Please enter a valid email',
      },
    },
    phoneNo: {
      type: String,
      required: [true, 'Phone no. is required'],
      unique: true,
      trim: true,
      validate: {
        validator: phoneNo => {
          const regex = new RegExp(regexp.phoneNo);
          return regex.test(phoneNo);
        },
        message: 'Please enter a valid phone no.',
      },
    },
    password: {
      type: String,
      required: [true, 'Password is required'],
      minLength: [8, 'Password must be atleast 8 characters long'],
      maxLength: [20, 'Password must be less than 20 characters'],
      select: false,
    },
    forgotPasswordToken: {
      type: String,
    },
    forgotPasswordExpiry: {
      type: Date,
    },
  },
  {
    timestamps: true,
  }
);

userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) {
    return next();
  }

  this.password = await bcrypt.hash(this.password, 10);
  next();
});

userSchema.methods = {
  comparePassword: async function (password) {
    return await bcrypt.compare(this.password, password);
  },

  generateJWTtoken: function () {
    const token = JWT.sign({ userId: this._id }, config.JWT_SECRET, {
      expiresIn: config.JWT_EXPIRY,
    });

    return token;
  },

  generateForgotPasswordToken: function () {
    const token = crypto.randomBytes(32).toString('hex');
    this.forgotPasswordToken = crypto.createHash('sha256').update(token).digest('hex');
    this.forgotPasswordExpiry = new Date(Date.now() + 30 * 60 * 1000);

    return token;
  },
};

export default mongoose.model('User', userSchema);
