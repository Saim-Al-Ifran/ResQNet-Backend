import { Router } from "express";
import { login, logout, me, register } from "./auth.controller";
import { loginSchema, registerSchema } from "./auth.validation";
import { validate } from "../../middlewares/validate.middleware";
import { authenticate } from "./auth.middleware";

const router = Router();

router.post("/register",validate(registerSchema),register);
router.post("/login",validate(loginSchema),login);
router.get("/me", authenticate, me);
router.post("/logout", logout);
export default router;