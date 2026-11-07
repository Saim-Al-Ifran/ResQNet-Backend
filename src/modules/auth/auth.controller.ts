import { Request, Response, NextFunction } from "express";
import { registerUser } from "./auth.service";
import { RegisterInput } from "./auth.validation";
import { loginUser } from "./auth.service";
import { LoginInput } from "./auth.validation";

const cookieOptions = {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: "lax" as const,
  path: "/api/v1/auth",
};
export const login = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const data = req.body as LoginInput;

    const result = await loginUser(data);

    // Set access token cookie
    res.cookie("accessToken", result.accessToken, {
      ...cookieOptions,
      maxAge: result.accessTokenMaxAge,
    });

    // Set refresh token cookie
    res.cookie("refreshToken", result.refreshToken, {
      ...cookieOptions,
      maxAge: result.refreshTokenMaxAge,
    });

    return res.status(200).json({
      success: true,
      message: "Login successful",
      data: {
        user: result.user,
      },
    });
  } catch (error) {
    next(error);
  }
};

export const register = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const data = req.body as RegisterInput;

    const user = await registerUser(data);

    return res.status(201).json({
      success: true,
      message: "Registration successful",
      data: {
        user,
      },
    });
  } catch (error) {
    next(error);
  }
};