import mongoose from "mongoose";
import express from "express";
import authRouter from "./routers/auth";
import cors from "cors";
import connectDB from "./utils/mongoose";
import { protect } from "./controllers/auth.controller";

const app = express();

app.use(cors());
app.use(express.json());

app.use("/auth", authRouter);

app.get("/greet", protect, (req, res) => {
  res.send("Hello");
});

// Connecting to the DB
connectDB();

app.listen(5000, () => console.log("Server running on port 5000"));
