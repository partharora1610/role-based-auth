import zod from "zod";

export const signupSchema = zod.object({
  email: zod.string().email(),
  password: zod.string().min(6).max(100),
  confirmPassword: zod.string().min(6).max(100),
});

export const signinSchema = zod.object({
  email: zod.string().email(),
  password: zod.string().min(6).max(100),
});
