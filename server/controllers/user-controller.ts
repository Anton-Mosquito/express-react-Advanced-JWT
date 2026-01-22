import { RequestHandler } from 'express';
import userService from '../service/user-service.js';
import { env } from '../config/env.js';
import { ValidatedRequestHandler } from '../types/validated-request.js';
import { RegistrationDto, LoginDto } from '../dtos/auth.schema.js';

class UserController {
  registration: ValidatedRequestHandler<RegistrationDto> = async (
    req,
    res,
    next,
  ) => {
    try {
      const { email, password }: RegistrationDto = req.body;

      const userData = await userService.registration(email, password);
      res.cookie('refreshToken', userData.refreshToken, {
        maxAge: 30 * 24 * 60 * 60 * 1000,
        httpOnly: true,
      }); //{ s : true} for https

      return res.json(userData);
    } catch (error) {
      next(error);
    }
  };

  login: ValidatedRequestHandler<LoginDto> = async (req, res, next) => {
    try {
      const { email, password }: LoginDto = req.body;

      const userData = await userService.login(email, password);

      res.cookie('refreshToken', userData.refreshToken, {
        maxAge: 30 * 24 * 60 * 60 * 1000,
        httpOnly: true,
      }); //{ s : true} for https

      return res.json(userData);
    } catch (error) {
      next(error);
    }
  };

  logout: RequestHandler = async (req, res, next) => {
    try {
      const { refreshToken } = req.cookies;
      const token = await userService.logout(refreshToken);
      res.clearCookie('refreshToken');
      return res.json(token);
    } catch (error) {
      next(error);
    }
  };

  activate: RequestHandler = async (req, res, next) => {
    try {
      const activationLink = req.params.link as string;
      await userService.activate(activationLink);

      return res.redirect(env.CLIENT_URL);
    } catch (error) {
      next(error);
    }
  };

  refresh: RequestHandler = async (req, res, next) => {
    try {
      const { refreshToken } = req.cookies;
      const userData = await userService.refresh(refreshToken);

      res.cookie('refreshToken', userData.refreshToken, {
        maxAge: 30 * 24 * 60 * 60 * 1000,
        httpOnly: true,
      }); //{ s : true} for https

      return res.json(userData);
    } catch (error) {
      next(error);
    }
  };

  getUser: RequestHandler = async (req, res, next) => {
    try {
      const users = await userService.getAllUsers();
      return res.json(users);
    } catch (error) {
      next(error);
    }
  };
}

export default new UserController();
