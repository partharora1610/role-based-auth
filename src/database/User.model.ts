import mongoose from "mongoose";
import bycrptjs from "bcryptjs";
import crypto from "crypto";
import { NextFunction } from "express";

export interface IUser extends mongoose.Document {
  name?: string;
  email: string;
  password: string;
  passwordChangedAt?: Date;
  passwordResetToken?: string;
  passwordResetExpires?: Date;
  active: boolean;

  correctPassword: (
    candidatePassword: string,
    userPassword: string
  ) => Promise<boolean>;

  changedPasswordAfter: (JWTTimestamp: number) => boolean;

  createPasswordResetToken: () => string;
}

const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  active: { type: Boolean, default: true },
  password: { type: String, required: true },
  passwordChangedAt: { type: Date },
  passwordResetToken: { type: String },
  passwordResetExpires: { type: Date },
});

// This is giving an error
// userSchema.pre(/^find/, function (next: NextFunction) {
//   this.find({ active: { $ne: false } });
//   next();
// });

userSchema.methods.correctPassword = async function (
  candidatePassword: string,
  userPassword: string
) {
  console.log({ candidatePassword, userPassword });
  return await bycrptjs.compare(candidatePassword, userPassword);
};

userSchema.methods.changedPasswordAfter = function (JWTTimestamp: number) {
  if (this.passwordChangedAt) {
    const changedTimestamp = parseInt(
      (this.passwordChangedAt.getTime() / 1000).toString(),
      10
    );

    return JWTTimestamp < changedTimestamp;
  }

  return false;
};

userSchema.methods.createPasswordResetToken = function () {
  const resetToken = crypto.randomBytes(32).toString("hex");

  this.passwordResetToken = crypto
    .createHash("sha256")
    .update(resetToken)
    .digest("hex");

  this.passwordResetExpires = Date.now() + 10 * 60 * 1000;

  return resetToken;
};

export const User = mongoose.model<IUser>("User", userSchema);
