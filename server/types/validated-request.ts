import { Request, Response, NextFunction } from 'express';

export interface ValidatedRequest<T> extends Request {
  body: T;
}

export type ValidatedRequestHandler<T> = (
  req: ValidatedRequest<T>,
  res: Response,
  next: NextFunction,
) => unknown;
