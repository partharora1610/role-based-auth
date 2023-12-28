import { NextFunction, Request, Response } from "express";
import jwt from "jsonwebtoken";
import bycrptjs from "bcryptjs";
import crypto from "crypto";

import { User } from "../database/User.model";
import sendEmail from "../utils/emails";
import { signinSchema, signupSchema } from "../validations/zod";

export const Signup = async (req: Request, res: Response) => {
  try {
    signupSchema.parse(req.body);

    const { email, password, confirmPassword } = req.body;

    console.log({ email, password, confirmPassword });

    const existingUser = await User.findOne({ email });
    console.log(existingUser);

    if (existingUser)
      return res.status(400).json({ message: "User already exists" });

    if (password !== confirmPassword)
      return res.status(400).json({ message: "Passwords don't match" });

    // Hashing the password
    const hashedPassword = await bycrptjs.hash(password, 12);

    const newUser = new User({ email, password: hashedPassword });

    await newUser.save();

    const token = jwt.sign({ email }, process.env.JWT_SECRET!, {
      expiresIn: "1d",
    });

    res.status(200).json({
      token,
      message: "User created successfully",
      status: "success",
      user: newUser,
    });
  } catch (error) {
    res.status(500).json({ message: "Something went wrong" });
  }
};

export const Signin = async (req: Request, res: Response) => {
  try {
    signinSchema.parse(req.body);

    const { email, password } = req.body;

    const existingUser = await User.findOne({ email });

    if (!existingUser)
      return res.status(404).json({ message: "User not found" });

    // Verify password
    const correct = await existingUser.correctPassword(
      password,
      existingUser.password
    );

    if (!correct)
      return res
        .status(400)
        .json({ message: "Incorrect credentials entered by the user" });

    // Generate token
    const token = jwt.sign({ email }, process.env.JWT_SECRET!, {
      expiresIn: "1d",
    });

    res.status(200).json({
      token,
      message: "User signed in successfully",
      status: "success",
      user: existingUser,
    });
  } catch (error) {
    res.status(500).json({ message: "Something went wrong" });
  }
};

export const RefreshToken = async (req: Request, res: Response) => {};

export const ResetPassword = async (req: Request, res: Response) => {
  try {
    const token = req.params.token;
    const hashedToken = crypto.createHash("sha256").update(token).digest("hex");

    const user = await User.findOne({
      passwordResetToken: hashedToken,
      passwordResetExpires: { $gt: Date.now() },
    });

    if (!user) return res.status(400).json({ message: "Invalid token" });

    const password = req.body.password;
    const confirmPassword = req.body.confirmPassword;

    if (password !== confirmPassword)
      return res.status(400).json({ message: "Passwords don't match" });

    const hashedPassword = await bycrptjs.hash(password, 12);

    user.password = hashedPassword;
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    user.passwordChangedAt = new Date(Date.now() - 1000);

    await user.save();

    const newToken = jwt.sign({ email: user.email }, process.env.JWT_SECRET!, {
      expiresIn: "1d",
    });

    res.status(200).json({
      token: newToken,
      message: "Password reset successfully",
      status: "success",
      user,
    });
  } catch (error) {
    res.status(500).json({ message: "Something went wrong" });
  }
};

export const ForgotPassword = async (req: Request, res: Response) => {
  try {
    const email = req.body.email;

    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: "User not found" });

    const resetToken = user.createPasswordResetToken();

    await user.save({
      validateBeforeSave: false,
    });

    const resetURL = `${req.protocol}://${req.get(
      "host"
    )}/auth/reset-password/${resetToken}`;

    try {
      await sendEmail(email, resetURL);
      res.status(200).json({ message: "Reset token sent to email" });
    } catch (error) {
      user.passwordResetToken = undefined;
      user.passwordResetExpires = undefined;

      await user.save({
        validateBeforeSave: false,
      });

      res.status(500).json({ message: "Something went wrong" });
    }
  } catch (error) {}
};

export const updatePassword = async (req: Request, res: Response) => {
  try {
    const user = req.body.user;

    const { currentPassword, password, confirmPassword } = req.body;

    const correct = await user.correctPassword(currentPassword, user.password);

    if (!correct)
      return res.status(400).json({
        message:
          "Incorrect credentials entered by the user!! Forgot password ?",
      });

    if (password !== confirmPassword)
      return res.status(400).json({ message: "Passwords don't match" });

    const hashedPassword = await bycrptjs.hash(password, 12);

    user.password = hashedPassword;
    user.passwordChangedAt = new Date(Date.now() - 1000);

    await user.save();

    const newToken = jwt.sign({ email: user.email }, process.env.JWT_SECRET!, {
      expiresIn: "1d",
    });

    res.status(200).json({
      token: newToken,
      message: "Password updated successfully",
      status: "success",
      user,
    });
  } catch (error) {}
};

export const CurrentUser = async (req: Request, res: Response) => {
  try {
    const user = req.body.user;

    res.status(200).json({ message: "User found", user });
  } catch (error) {
    res.status(500).json({ message: "Something went wrong" });
  }
};

export const VerifyEmail = async (req: Request, res: Response) => {};

export const protect = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const token = req.headers.authorization?.split(" ")[1];

    if (!token) return res.status(401).json({ message: "Unauthorized" });

    const decoded: any = jwt.verify(token, process.env.JWT_SECRET!);

    const user = await User.findOne({ email: decoded.email });

    if (!user) return res.status(404).json({ message: "User not found" });

    if (user.changedPasswordAfter(decoded.iat)) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    req.body.user = user;
    next();
  } catch (error) {
    res.status(500).json({ message: "Something went wrong" });
  }
};

export const restrictTo = (...roles: string[]) => {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!roles.includes(req.body.user.role))
      return res.status(403).json({ message: "Forbidden" });

    next();
  };
};
