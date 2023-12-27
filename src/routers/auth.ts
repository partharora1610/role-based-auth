import express from "express";
import {
  CurrentUser,
  Logout,
  RefreshToken,
  ResetPassword,
  Signin,
  Signup,
  VerifyEmail,
} from "../controllers/auth.controller";

const authRouter = express.Router();

authRouter.post("/signup", Signup);
authRouter.post("/signin", Signin);

authRouter.post("/refresh_token", RefreshToken);
authRouter.post("/logout", Logout);
authRouter.post("/reset-password", ResetPassword);
authRouter.get("/current-user", CurrentUser);

authRouter.post("/verify-email", VerifyEmail);

export default authRouter;
