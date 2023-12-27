import mongoose from "mongoose";
import bycrptjs from "bcryptjs";

export interface IUser extends mongoose.Document {
  email: string;
  password: string;

  correctPassword: (
    candidatePassword: string,
    userPassword: string
  ) => Promise<boolean>;
}

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});

userSchema.methods.correctPassword = async function (
  candidatePassword: string,
  userPassword: string
) {
  console.log({ candidatePassword, userPassword });
  return await bycrptjs.compare(candidatePassword, userPassword);
};

export const User = mongoose.model<IUser>("User", userSchema);
