import { Router } from "express";
import { login, logout, me, refreshToken, register } from "./auth.controller";
import { loginSchema, registerSchema } from "./auth.validation";
import { validate } from "../../middlewares/validate.middleware";
import { authenticate } from "./auth.middleware";

const router = Router();

router.post("/register",validate(registerSchema),register);
router.post("/login",validate(loginSchema),login);
router.get("/me", authenticate, me);
router.post("/logout", logout);
router.post("/refresh_token", refreshToken);
export default router;