import { NextFunction, Request, Response } from "express";
import jwt from "jsonwebtoken";
import bycrptjs from "bcryptjs";

import { User } from "../database/User.model";
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

export const Logout = async (req: Request, res: Response) => {};

export const ResetPassword = async (req: Request, res: Response) => {};

export const CurrentUser = async (req: Request, res: Response) => {};

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