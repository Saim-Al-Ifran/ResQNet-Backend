import { Request, Response, NextFunction } from "express";
import { getCurrentUser, logoutService, registerUser } from "./auth.service";
import { RegisterInput } from "./auth.validation";
import { loginUser } from "./auth.service";
import { LoginInput } from "./auth.validation";
import { AuthRequest } from "./auth.middleware";

const cookieOptions = {
  httpOnly: true,
  secure: false,
  sameSite: "none" as const,
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

export const me = async (
  req: AuthRequest,
  res: Response,
  next: NextFunction
) => {
  try {
    const userId = req.userId;

    if (!userId) {
      return res.status(401).json({
        success: false,
        message: "Authentication required",
      });
    }

    const user = await getCurrentUser(userId);

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "User no longer exists",
      });
    }

    return res.status(200).json({
      success: true,
      message: "User retrieved successfully",
      data: {
        user,
      },
    });
  } catch (error) {
    next(error);
  }
};
export const logout = async (
  req: Request,
  res: Response,
  _next: NextFunction
): Promise<void> => {
  try {
    const refreshToken = req.cookies?.refreshToken;

    if (refreshToken) {
      await logoutService(refreshToken);
    }

    res.clearCookie("accessToken", {
      httpOnly: true,
      secure: true,
      sameSite: "none",
    });

    res.clearCookie("refreshToken", {
      httpOnly: true,
      secure: true,
      sameSite: "none",
    });

    res.status(200).json({
      success: true,
      message: "Logged out successfully",
    });
  } catch (error) {
    console.error("Logout error:", error);

    res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
};