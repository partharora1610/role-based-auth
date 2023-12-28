import express from "express";
import {
  CurrentUser,
  ForgotPassword,
  RefreshToken,
  ResetPassword,
  Signin,
  Signup,
  VerifyEmail,
  protect,
} from "../controllers/auth.controller";

const authRouter = express.Router();

authRouter.post("/signup", Signup);
authRouter.post("/signin", Signin);

authRouter.post("/forgot-password", ForgotPassword);
authRouter.post("/refresh_token", RefreshToken);

authRouter.post("/reset-password", ResetPassword);
authRouter.get("/current-user", protect, CurrentUser);

authRouter.post("/verify-email", VerifyEmail);

export default authRouter;
