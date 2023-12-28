import mongoose from "mongoose";
import express from "express";
import rateLimit from "express-rate-limit";
import authRouter from "./routers/auth";
import cors from "cors";
import connectDB from "./utils/mongoose";
import { protect } from "./controllers/auth.controller";

const app = express();

app.use(cors());
app.use(express.json());

const limiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 100,
  message: "Too many requests from this IP, please try again in an hour",
});

app.use("/", limiter);

app.use("/auth", authRouter);

app.get("/greet", protect, (req, res) => {
  res.send("Hello");
});

// Connecting to the DB
connectDB();

app.listen(5000, () => console.log("Server running on port 5000"));
