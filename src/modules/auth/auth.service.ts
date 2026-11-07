import bcrypt from "bcrypt";
import { prisma } from "../../lib/prisma";
import { RegisterInput } from "./auth.validation";
import { LoginInput } from "./auth.validation";
import { AppError } from "../../utils/app-error";
import { createHash } from "crypto";
import jwt from "jsonwebtoken";

const ACCESS_TOKEN_EXPIRES_IN = "1h";
const REFRESH_TOKEN_EXPIRES_IN = "7d";

const ACCESS_TOKEN_MAX_AGE = 60 * 60 * 1000;
const REFRESH_TOKEN_MAX_AGE = 7 * 24 * 60 * 60 * 1000;

const getJwtSecrets = () => {
  const accessSecret = process.env.JWT_ACCESS_SECRET;
  const refreshSecret = process.env.JWT_REFRESH_SECRET;

  if (!accessSecret || !refreshSecret) {
    throw new Error("JWT secrets are not configured");
  }

  return { accessSecret, refreshSecret };
};

const hashToken = (token: string) => {
  return createHash("sha256").update(token).digest("hex");
};

export const loginUser = async (data: LoginInput) => {
  const { email, password } = data;

  // 1. Find user
  const user = await prisma.user.findUnique({
    where: { email },
  });

  if (!user) {
    throw new AppError(401, "Invalid email or password");
  }

  // 2. Compare password
  const isPasswordValid = await bcrypt.compare(
    password,
    user.passwordHash
  );

  if (!isPasswordValid) {
    throw new AppError(401, "Invalid email or password");
  }

  // 3. Generate JWT tokens
  const { accessSecret, refreshSecret } = getJwtSecrets();

  const accessToken = jwt.sign(
    {
      sub: user.id,
      role: user.role,
    },
    accessSecret,
    {
      expiresIn: ACCESS_TOKEN_EXPIRES_IN,
    }
  );

  const refreshToken = jwt.sign(
    {
      sub: user.id,
    },
    refreshSecret,
    {
      expiresIn: REFRESH_TOKEN_EXPIRES_IN,
    }
  );

  // 4. Hash refresh token
  const tokenHash = hashToken(refreshToken);

  // 5. Save refresh token in database
  await prisma.refreshToken.create({
    data: {
      tokenHash,
      userId: user.id,
      expiresAt: new Date(Date.now() + REFRESH_TOKEN_MAX_AGE),
    },
  });

  // 6. Return necessary data
  return {
    user: {
      id: user.id,
      name: user.name,
      email: user.email,
      phoneNumber: user.phoneNumber,
      imgUrl: user.imgUrl,
      role: user.role,
    },
    accessToken,
    refreshToken,
    accessTokenMaxAge: ACCESS_TOKEN_MAX_AGE,
    refreshTokenMaxAge: REFRESH_TOKEN_MAX_AGE,
  };
};

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

export const getCurrentUser = async (userId: string) => {
  const user = await prisma.user.findUnique({
    where: {
      id: userId,
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