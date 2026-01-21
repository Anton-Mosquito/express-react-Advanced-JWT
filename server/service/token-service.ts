import jwt from "jsonwebtoken";
import prisma from "../db";
import { env } from "../config/env";

class TokenService {
  generateTokens(payload: any) {
    const accessToken = jwt.sign(payload, env.JWT_ACCESS_SECRET, {
      expiresIn: "30m",
      algorithm: "HS256",
    });

    const refreshToken = jwt.sign(payload, env.JWT_REFRESH_SECRET, {
      expiresIn: "30d",
      algorithm: "HS256",
    });

    return {
      accessToken,
      refreshToken,
    };
  }

  validateAccessToken(token: string) {
    try {
      const userData = jwt.verify(token, env.JWT_ACCESS_SECRET as string | jwt.Secret);
      return userData;
    } catch (error) {
      return null;
    }
  }

  validateRefreshToken(token: string) {
    try {
      const userData = jwt.verify(token, env.JWT_REFRESH_SECRET as string | jwt.Secret);
      return userData;
    } catch (error) {
      return null;
    }
  }

  async saveToken(userId: string, refreshToken: string) {
    const tokenData = await prisma.token.findUnique({ where: { userId } });

    if (tokenData) {
      return await prisma.token.update({
        where: { userId },
        data: { refreshToken },
      });
    }

    const token = await prisma.token.create({
      data: { userId, refreshToken },
    });
    return token;
  }

  async removeToken(refreshToken: string) {
    const tokenData = await prisma.token.deleteMany({
      where: { refreshToken },
    });
    return tokenData;
  }

  async findToken(refreshToken: string) {
    const tokenData = await prisma.token.findFirst({
      where: { refreshToken },
    });
    return tokenData;
  }
}

export default new TokenService();
