import express from "express";
import type { Request, Response } from "express";
import authRoutes from "./modules/auth/auth.routes";
import { errorHandler } from "./middlewares/error.middleware";

const app = express();

app.use(express.json());
app.use("/auth", authRoutes);

app.get("/health", (_req: Request, res: Response) => {
  res.status(200).json({
    success: true,
    message: "ResQNet API is running"
  });
});
app.use(errorHandler);
export default app;