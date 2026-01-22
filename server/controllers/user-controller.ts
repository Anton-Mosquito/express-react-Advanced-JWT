import { Request, Response, NextFunction } from 'express';
import userService from '../service/user-service.js';
import ApiError from '../exceptions/api-error.js';
import { env } from '../config/env.js';
import { RegistrationDto, LoginDto } from '../dtos/auth.schema.js';

class UserController {
  registration = async (
    req: Request<unknown, unknown, RegistrationDto>,
    res: Response,
  ) => {
    const { email, password } = req.body;

    const userData = await userService.registration(email, password);
    res.cookie('refreshToken', userData.refreshToken, {
      maxAge: 30 * 24 * 60 * 60 * 1000,
      httpOnly: true,
    });

    return res.json(userData);
  };

  login = async (req: Request<unknown, unknown, LoginDto>, res: Response) => {
    const { email, password } = req.body;

    const userData = await userService.login(email, password);

    res.cookie('refreshToken', userData.refreshToken, {
      maxAge: 30 * 24 * 60 * 60 * 1000,
      httpOnly: true,
    });

    return res.json(userData);
  };

  logout = async (
    req: Request & { cookies: { refreshToken?: string } },
    res: Response,
    next: NextFunction,
  ) => {
    const { refreshToken } = req.cookies;
    if (!refreshToken) return next(ApiError.UnauthorizedError());
    const token = await userService.logout(refreshToken);
    res.clearCookie('refreshToken');
    return res.json(token);
  };

  activate = async (req: Request, res: Response) => {
    const activationLink = req.params.link as string;
    await userService.activate(activationLink);

    return res.redirect(env.CLIENT_URL);
  };

  refresh = async (
    req: Request & { cookies: { refreshToken?: string } },
    res: Response,
    next: NextFunction,
  ) => {
    const { refreshToken } = req.cookies;
    if (!refreshToken) return next(ApiError.UnauthorizedError());
    const userData = await userService.refresh(refreshToken);

    res.cookie('refreshToken', userData.refreshToken, {
      maxAge: 30 * 24 * 60 * 60 * 1000,
      httpOnly: true,
    }); //{ s : true} for https

    return res.json(userData);
  };

  getUser = async (req: Request, res: Response) => {
    const users = await userService.getAllUsers();
    return res.json(users);
  };
}

export default new UserController();
