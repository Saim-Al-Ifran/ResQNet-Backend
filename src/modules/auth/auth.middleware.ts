import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";

export interface AuthRequest extends Request {
  userId?: string;
}

export const authenticate = (
  req: AuthRequest,
  res: Response,
  next: NextFunction
) => {
  try {
    const authHeader = req.headers.authorization;
    let token = req.cookies.accessToken || (authHeader && authHeader.split(' ')[1]);
    if (!token) {
      return res.status(401).json({
        success: false,
        message: "Authentication required",
      });
    }

    const accessSecret = process.env.JWT_ACCESS_SECRET;

    if (!accessSecret) {
      throw new Error("JWT_ACCESS_SECRET is not configured");
    }

    const decoded = jwt.verify(token, accessSecret);

    if (typeof decoded === "string" || !decoded.sub) {
      return res.status(401).json({
        success: false,
        message: "Invalid access token",
      });
    }

    req.userId = decoded.sub;

    next();
  } catch (error) {
    if (error instanceof jwt.JsonWebTokenError) {
      return res.status(401).json({
        success: false,
        message: "Invalid or expired access token",
      });
    }

    next(error);
  }
};