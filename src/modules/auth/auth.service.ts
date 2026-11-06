 import bcrypt from "bcrypt";
import { prisma } from "../../lib/prisma";
import { RegisterInput } from "./auth.validation";
import { AppError } from "../../utils/app-error";

export const registerUser = async (data: RegisterInput) => {
  const { name, email, password, phoneNumber } = data;

  // 1. Check whether email already exists
  const existingUser = await prisma.user.findUnique({
    where: { email },
  });

  if (existingUser) {
    throw new AppError(409, "Email is already registered");
  }

  // 2. Hash password
  const passwordHash = await bcrypt.hash(password, 12);

  // 3. Create user
  const user = await prisma.user.create({
    data: {
      name,
      email,
      passwordHash,
      phoneNumber,
    },
    select: {
      id: true,
      name: true,
      email: true,
      phoneNumber: true,
      imgUrl: true,
      role: true,
      createdAt: true,
    },
  });

  return user;
};