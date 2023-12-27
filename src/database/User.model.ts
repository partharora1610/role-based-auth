import mongoose from "mongoose";
import bycrptjs from "bcryptjs";

export interface IUser extends mongoose.Document {
  email: string;
  password: string;
  passwordChangedAt?: Date;

  correctPassword: (
    candidatePassword: string,
    userPassword: string
  ) => Promise<boolean>;

  changedPasswordAfter: (JWTTimestamp: number) => boolean;
}

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  passwordChangedAt: { type: Date },
});

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

export const User = mongoose.model<IUser>("User", userSchema);
