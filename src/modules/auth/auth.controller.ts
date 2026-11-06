import { Request, Response, NextFunction } from "express";
import { registerUser } from "./auth.service";
import { RegisterInput } from "./auth.validation";

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