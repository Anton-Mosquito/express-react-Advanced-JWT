import { Request, Response, NextFunction } from 'express';
import ApiError from '../exceptions/api-error.js';
import tokenService from '../service/token-service.js';

export interface UserJwtPayload {
  id: string;
  email: string;
  isActivated: boolean;
}

export interface AuthRequest extends Request {
  user?: UserJwtPayload;
}

export default function (req: AuthRequest, res: Response, next: NextFunction) {
  const authorizationHeader = req.headers.authorization;

  if (!authorizationHeader) {
    return next(ApiError.UnauthorizedError());
  }

  const accessToken = authorizationHeader.split(' ')[1];

  if (!accessToken) {
    return next(ApiError.UnauthorizedError());
  }

  const userData = tokenService.validateAccessToken(accessToken);

  if (!userData) {
    return next(ApiError.UnauthorizedError());
  }

  req.user = userData as UserJwtPayload;
  next();
}
