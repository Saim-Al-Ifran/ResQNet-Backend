import { Router } from "express";
import { register } from "./auth.controller";
import { registerSchema } from "./auth.validation";
import { validate } from "../../middlewares/validate.middleware";

const router = Router();

router.post("/register",validate(registerSchema),register);

export default router;