import { Request, Response, NextFunction } from 'express';
import { ZodType } from 'zod';
import ApiError from '../exceptions/api-error.js';

export default function validateMiddleware<T extends ZodType>(schema: T) {
  return (req: Request, res: Response, next: NextFunction) => {
    const result = schema.safeParse(req.body);

    if (!result.success) {
      const formattedErrors = result.error.issues.map((issue) => ({
        msg: issue.message,
        param: issue.path.length ? issue.path.join('.') : undefined,
      }));

      return next(ApiError.BadRequest('Validation error', formattedErrors));
    }

    req.body = result.data;
    next();
  };
}
