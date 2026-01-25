**Overview**

This document describes the server-side architecture of the project (contents of the `server/` folder), plus the key environment files (`.env`, `.env.example`) and Docker Compose manifests (`docker-compose.development.yml`, `docker-compose.yml`). It is a descriptive (no-code-snippet) reference intended to give full context for analysis, debugging and extension.

- Primary responsibilities: REST API for authentication and user management, WebSocket server for real-time drawing collaboration, PostgreSQL via Prisma for persistence, Nodemailer (OAuth2) for activation emails, JWT-based authentication with refresh-token rotation.
- Entrypoint: `server/index.ts` (Express app with `express-ws` integration).

**Table of contents**

- **Overview**
- **Files** (per-file detailed descriptions)
- **Auth Flow** (registration → activate → login → refresh → logout)
- **WebSocket Flow** (message model, connection lifecycle and broadcasting)
- **Prisma models & DB usage**
- **Environment variables** (where each is used)
- **Docker Compose** (development and production summaries)
- **Security / Caveats**
- **Recommended quick fixes**

**Files**

Each entry lists: Purpose; Main logic/flow; Exports or externally visible role; Env variables referenced; External services; Key relationships to other files.

- `server/index.ts`
  - Purpose: Application entrypoint. Creates Express app, integrates `express-ws` for WebSocket support, mounts middleware and routes, and starts listening on `env.PORT`.
  - Main logic: sets up `ws` instance, applies `express.json()`, `cookie-parser`, CORS (origin from `env.CLIENT_URL`), mounts `/api` router, sets global error middleware, and registers a root WebSocket endpoint that delegates to `WebSocketController`.
  - Exports: none (runs server). Other files import `config/env.ts`; `route/index.ts` is mounted here.
  - Env: `PORT`, `CLIENT_URL`.
  - External services: WebSocket (internal), HTTP server.

  - File contents (`server/index.ts`):

```typescript
import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import router from './route/index.js';
import errorMiddleware from './middleware/error-middleware.js';
import expressWs, { Application as WebSocketApplication } from 'express-ws';
import WebSocketController from './controllers/websocket-controller.js';
import { ExtendedWebSocket } from './types/websocket.types.js';
import { env } from './config/env.js';

const PORT: number = env.PORT;

const app = express();
const wsInstance = expressWs(app);
const wsApp = wsInstance.app as WebSocketApplication;
const wss = wsInstance.getWss();

const wsController = new WebSocketController(wss);

wsApp.use(express.json());
wsApp.use(cookieParser());
wsApp.use(
  cors({
    credentials: true,
    origin: env.CLIENT_URL,
  }),
);
wsApp.use('/api', router);
wsApp.use(errorMiddleware);

wsApp.ws('/', (ws: ExtendedWebSocket) => {
  wsController.handleConnection(ws);
});

const start = async () => {
  try {
    wsApp.listen(PORT, () => console.log(`Server work on PORT ${PORT}`));
  } catch (error) {
    console.log(error);
  }
};

start();

```

- `server/db.ts`
  - Purpose: Initialize and export Prisma client configured to use a Postgres connection pool.
  - Main logic: builds a `pg.Pool` from `DATABASE_URL`, wraps it with `@prisma/adapter-pg`, and constructs `new PrismaClient({ adapter })` which is exported as default.
  - Exports: default Prisma client instance used across services (`prisma`).
  - Env: `DATABASE_URL`.
  - External services: PostgreSQL.
  - Relationships: imported by services such as `user-service.ts` and `token-service.ts`.

  - File contents (`server/db.ts`):

```typescript
import { PrismaClient } from '@prisma/client';
import { PrismaPg } from '@prisma/adapter-pg';
import pg from 'pg';
import { env } from './config/env.js';

const connectionString = env.DATABASE_URL;

const pool = new pg.Pool({ connectionString });
const adapter = new PrismaPg(pool);

const prisma = new PrismaClient({
  adapter,
});

export default prisma;

```

- `server/prisma/schema.prisma`
  - Purpose: Database schema (Prisma) that defines `User` and `Token` models and relations.
  - Main contents: `User` model (id, email unique, password hash, isActivated, activationLink, optional relation to Token) and `Token` model (id, refreshToken, user relation, unique userId).
  - Role: Basis for Prisma client generation and runtime DB mapping.
  - External services: PostgreSQL.

  - File contents (`server/prisma/schema.prisma`):

```prisma
// This is your Prisma schema file,
// learn more about it in the docs: https://pris.ly/d/prisma-schema

// Looking for ways to speed up your queries, or scale easily with your serverless or edge functions?
// Try Prisma Accelerate: https://pris.ly/cli/accelerate-init

generator client {
  provider = "prisma-client-js"
}

datasource db {
  provider = "postgresql"
}

model User {
  id             String  @id @default(uuid())
  email          String  @unique
  password       String
  isActivated    Boolean @default(false)
  activationLink String?
  token          Token?
}

model Token {
  id           String @id @default(uuid())
  refreshToken String
  user         User   @relation(fields: [userId], references: [id])
  userId       String @unique
}

```

- `server/prisma.config.ts`
  - Purpose: Prisma CLI/runtime configuration referencing `prisma/schema.prisma` and `DATABASE_URL`.
  - Role: Used when running Prisma commands in dev and CI (e.g., `prisma generate`, migrations/push).
  - Env: `DATABASE_URL`.

  - File contents (`server/prisma.config.ts`):

```typescript
import 'dotenv/config';
import { defineConfig, env } from 'prisma/config';

export default defineConfig({
  schema: 'prisma/schema.prisma',
  migrations: {
    path: 'prisma/migrations',
  },
  datasource: {
    url: env('DATABASE_URL'),
  },
});

```

- `server/config/env.ts`
  - Purpose: Centralized environment validation and typed accessor using `envalid`.
  - Main logic: declares required/validated env variables and exports typed `env` object used across the app.
  - Exports: `env` typed object.
  - Env variables defined: `PORT`, `DATABASE_URL`, `CLIENT_URL`, `API_URL`, `SMTP_SERVICE`, `GOOGLE_CLIENT`, `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `GOOGLE_REFRESH_TOKEN`, `JWT_ACCESS_SECRET`, `JWT_REFRESH_SECRET`.

  - File contents (`server/config/env.ts`):

```typescript
import { cleanEnv, str, num } from 'envalid';

export type Env = {
  PORT: number;
  DATABASE_URL: string;
  CLIENT_URL: string;
  API_URL: string;
  SMTP_SERVICE: string;
  GOOGLE_CLIENT: string;
  GOOGLE_CLIENT_ID: string;
  GOOGLE_CLIENT_SECRET: string;
  GOOGLE_REFRESH_TOKEN: string;
  JWT_ACCESS_SECRET: string;
  JWT_REFRESH_SECRET: string;
};

const env = cleanEnv(process.env, {
  PORT: num({ default: 5001 }),
  DATABASE_URL: str(),
  CLIENT_URL: str(),
  API_URL: str(),
  SMTP_SERVICE: str(),
  GOOGLE_CLIENT: str(),
  GOOGLE_CLIENT_ID: str(),
  GOOGLE_CLIENT_SECRET: str(),
  GOOGLE_REFRESH_TOKEN: str(),
  JWT_ACCESS_SECRET: str(),
  JWT_REFRESH_SECRET: str(),
}) as unknown as Env;

export { env };
export default env;

```

- `server/route/index.ts`
  - Purpose: API router; defines endpoints and wires middleware.
  - Main routes: `POST /registration`, `POST /login`, `POST /logout`, `GET /activate/:link`, `GET /refresh`, `GET /users` (protected with auth middleware).
  - Relationships: uses `validate-middleware` with `dtos/auth.schema.ts`, `auth-middleware` for protected routes, and `controllers/user-controller.ts` for handlers.

  - File contents (`server/route/index.ts`):

```typescript
import { Router } from 'express';
import userController from '../controllers/user-controller.js';
import validateMiddleware from '../middleware/validate-middleware.js';
import { registrationSchema, loginSchema } from '../dtos/auth.schema.js';
import authMiddleware from '../middleware/auth-middleware.js';

const router = Router();

router.post(
  '/registration',
  validateMiddleware(registrationSchema),
  userController.registration,
);
router.post('/login', validateMiddleware(loginSchema), userController.login);
router.post('/logout', userController.logout);
router.get('/activate/:link', userController.activate);
router.get('/refresh', userController.refresh);
router.get('/users', authMiddleware, userController.getUser);

export default router;

```

- `server/controllers/user-controller.ts`
  - Purpose: Translate HTTP requests to service calls for user/auth flows.
  - Main logic: call `userService` methods, set/clear `refreshToken` cookie (`httpOnly`, `maxAge`), redirect on activation to `env.CLIENT_URL`, and return JSON results to clients.
  - Exports: default `UserController` instance with handlers for registration, login, logout, activate, refresh, and getUser.
  - Env: `CLIENT_URL`.
  - Relationships: calls `user-service.ts`.

  - File contents (`server/controllers/user-controller.ts`):

```typescript
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

```

- `server/controllers/websocket-controller.ts`
  - Purpose: Handle WebSocket connections, message validation, per-socket metadata, and broadcasting.
  - Main logic: on connection send welcome text; on message parse JSON and validate with Zod schemas from `types/websocket.types.ts`; handle `connection` messages (set socket metadata and broadcast connection event) and `draw` messages (broadcast drawing payload to clients in same room); handle `close` and `error` events.
  - Exports: `WebSocketController` class (constructed with the server-side WebSocket `wss` instance in `index.ts`).
  - Env: none.
  - External services: none.
  - Relationships: uses `types/websocket.types.ts` for runtime validation and typing.

  - File contents (`server/controllers/websocket-controller.ts`):

```typescript
import { Server as WebSocketServer } from 'ws';
import {
  ExtendedWebSocket,
  WsMessage,
  WsMessageSchema,
  ConnectionMessage,
} from '../types/websocket.types.js';

class WebSocketController {
  private wss: WebSocketServer;

  constructor(wss: WebSocketServer) {
    this.wss = wss;
  }

  handleConnection = (ws: ExtendedWebSocket): void => {
    console.log('Connection established');
    ws.send('You are successfully connected');

    ws.on('message', (data: string) => {
      try {
        const parsed: unknown = JSON.parse(data.toString());
        const parseResult = WsMessageSchema.safeParse(parsed);
        if (!parseResult.success) {
          console.error('Invalid WS message received:', parseResult.error);
          return;
        }

        const msg = parseResult.data as WsMessage;

        switch (msg.method) {
          case 'connection': {
            // msg is narrowed to ConnectionMessage here by discriminated union
            this.connectionHandler(ws, msg as ConnectionMessage);
            break;
          }
          case 'draw': {
            this.broadcastMessage(ws, msg);
            break;
          }
          default: {
            console.warn(`Unknown method: ${(msg as any).method}`);
          }
        }
      } catch (error) {
        console.error('Error parsing WebSocket message:', error);
      }
    });

    ws.on('close', () => {
      console.log('Connection closed');
    });

    ws.on('error', (error) => {
      console.error('WebSocket error:', error);
    });
  };

  private connectionHandler = (
    ws: ExtendedWebSocket,
    msg: ConnectionMessage,
  ): void => {
    ws.id = msg.id;
    ws.username = msg.username;

    // Broadcast to all clients in the same room that a user connected
    const broadcastPayload: ConnectionMessage = {
      method: 'connection',
      id: msg.id,
      username: msg.username,
    };

    this.broadcastMessage(ws, broadcastPayload);
  };

  private broadcastMessage = (ws: ExtendedWebSocket, msg: WsMessage): void => {
    const READY_STATE_OPEN = 1;

    this.wss.clients.forEach((client) => {
      const extendedClient = client as ExtendedWebSocket;
      if (
        extendedClient.id === msg.id &&
        client.readyState === READY_STATE_OPEN
      ) {
        client.send(JSON.stringify(msg));
      }
    });
  };
}

export default WebSocketController;

```

- `server/service/user-service.ts`
  - Purpose: Business logic for users: registration, activation, login, refresh, logout, getAllUsers.
  - Main logic: uses `prisma` for DB operations; registration checks for existing email, hashes password (bcrypt with saltRounds 3), creates user with activationLink (uuid), sends activation mail via `mail-service`, creates DTO and tokens via `token-service`, and saves refresh token; login verifies password and issues tokens; refresh validates refresh token and rotates tokens; logout removes token record from DB.
  - Exports: default `UserService` instance.
  - Env: `API_URL` (used to construct activation link sent via email).
  - External services: PostgreSQL (via Prisma), SMTP (indirect via `mail-service`).

  - File contents (`server/service/user-service.ts`):

```typescript
import prisma from '../db.js';
import bcrypt from 'bcrypt';
import { v4 as uuidv4 } from 'uuid';
import mailService from './mail-service.js';
import tokenService from '../service/token-service.js';
import UserDto from '../dtos/user-dto.js';
import ApiError from '../exceptions/api-error.js';
import { env } from '../config/env.js';

class UserService {
  async registration(email: string, password: string) {
    const candidate = await prisma.user.findUnique({ where: { email } });

    if (candidate) {
      throw ApiError.BadRequest(`User with email ${email} have already exists`);
    }

    const hashPassword = await bcrypt.hash(password, 3);
    const activationLink = uuidv4();

    const user = await prisma.user.create({
      data: {
        email,
        password: hashPassword,
        activationLink,
      },
    });

    await mailService.sendActivationMail(
      email,
      `${env.API_URL}/api/activate/${activationLink}`,
    );

    const userDto = new UserDto(user); // ? id, email, isActivated
    const tokens = tokenService.generateTokens({ ...userDto });

    await tokenService.saveToken(userDto.id, tokens.refreshToken);

    return {
      ...tokens,
      user: userDto,
    };
  }

  async activate(activationLink: string) {
    const user = await prisma.user.findFirst({ where: { activationLink } });

    if (!user) {
      throw ApiError.BadRequest(`Unccorect activation link`);
    }

    await prisma.user.update({
      where: { id: user.id },
      data: { isActivated: true },
    });
  }

  async login(email: string, password: string) {
    const user = await prisma.user.findUnique({ where: { email } });

    if (!user) {
      throw ApiError.BadRequest(`User with email ${email} can not be found`);
    }

    const isPassEqual = await bcrypt.compare(password, user.password);

    if (!isPassEqual) {
      throw ApiError.BadRequest(`Incorrect password`);
    }

    const userDto = new UserDto(user);
    const tokens = tokenService.generateTokens({ ...userDto });

    await tokenService.saveToken(userDto.id, tokens.refreshToken);

    return {
      ...tokens,
      user: userDto,
    };
  }

  async logout(refreshToken: string) {
    const token = await tokenService.removeToken(refreshToken);
    return token;
  }

  async refresh(refreshToken: string) {
    if (!refreshToken) {
      throw ApiError.UnauthorizedError();
    }

    const userData = tokenService.validateRefreshToken(refreshToken) as any;
    const tokenFromDb = await tokenService.findToken(refreshToken);

    if (!userData || !tokenFromDb) {
      throw ApiError.UnauthorizedError();
    }

    const user = await prisma.user.findUnique({ where: { id: userData.id } });
    if (!user) {
      throw ApiError.UnauthorizedError();
    }
    const userDto = new UserDto(user); // ? id, email, isActivated
    const tokens = tokenService.generateTokens({ ...userDto });

    await tokenService.saveToken(userDto.id, tokens.refreshToken);

    return {
      ...tokens,
      user: userDto,
    };
  }

  async getAllUsers() {
    const users = await prisma.user.findMany();
    return users;
  }
}

export default new UserService();

```

- `server/service/token-service.ts`
  - Purpose: JWT generation/validation and refresh token persistence.
  - Main logic: sign access and refresh tokens (HS256) using `env.JWT_ACCESS_SECRET` and `env.JWT_REFRESH_SECRET`; validate tokens; save refresh tokens to `Token` model (create or update per user); remove tokens; find tokens.
  - Exports: default `TokenService` instance.
  - Env: `JWT_ACCESS_SECRET`, `JWT_REFRESH_SECRET`.
  - External services: PostgreSQL (via Prisma).

  - File contents (`server/service/token-service.ts`):

```typescript
import jwt from 'jsonwebtoken';
import prisma from '../db.js';
import { env } from '../config/env.js';

class TokenService {
  generateTokens(payload: any) {
    const accessToken = jwt.sign(payload, env.JWT_ACCESS_SECRET, {
      expiresIn: '30m',
      algorithm: 'HS256',
    });

    const refreshToken = jwt.sign(payload, env.JWT_REFRESH_SECRET, {
      expiresIn: '30d',
      algorithm: 'HS256',
    });

    return {
      accessToken,
      refreshToken,
    };
  }

  validateAccessToken(token: string) {
    try {
      const userData = jwt.verify(
        token,
        env.JWT_ACCESS_SECRET as string | jwt.Secret,
      );
      return userData;
    } catch (error) {
      return null;
    }
  }

  validateRefreshToken(token: string) {
    try {
      const userData = jwt.verify(
        token,
        env.JWT_REFRESH_SECRET as string | jwt.Secret,
      );
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

```

- `server/service/mail-service.ts`
  - Purpose: Configure Nodemailer with OAuth2 credentials and send activation emails.
  - Main logic: create transporter using OAuth2 (service: `env.SMTP_SERVICE`, `env.GOOGLE_CLIENT*` creds), expose `sendActivationMail(to, link)` that composes an HTML/text activation email and logs errors if sending fails.
  - Exports: default `MailService` instance.
  - Env: `SMTP_SERVICE`, `GOOGLE_CLIENT`, `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `GOOGLE_REFRESH_TOKEN`, `API_URL`.
  - External services: SMTP provider (Gmail via OAuth2 credentials).

  - File contents (`server/service/mail-service.ts`):

```typescript
import nodemailer from 'nodemailer';
import { env } from '../config/env.js';

class MailService {
  transporter: nodemailer.Transporter;

  constructor() {
    this.transporter = nodemailer.createTransport({
      service: env.SMTP_SERVICE,
      auth: {
        type: 'OAuth2',
        user: env.GOOGLE_CLIENT,
        clientId: env.GOOGLE_CLIENT_ID,
        clientSecret: env.GOOGLE_CLIENT_SECRET,
        refreshToken: env.GOOGLE_REFRESH_TOKEN,
      },
    });
  }

  async sendActivationMail(to: string, link: string) {
    try {
      await this.transporter.sendMail({
        from: env.GOOGLE_CLIENT,
        to,
        subject: `Account activation ${env.API_URL}`,
        text: `Activate: ${link}`,
        html: `
        <div>
            <h1>For activation go to the link</h1>
            <a href="${link}">${link}</a>
        </div>
      `,
      });
    } catch (err) {
      console.error('Failed to send activation email:', err);
    }
  }
}

export default new MailService();

```

- `server/dtos/auth.schema.ts`
  - Purpose: Request-body validation schemas for registration and login using Zod.
  - Main logic: `registrationSchema` (email + password length constraints) and `loginSchema` (email + password). Types `RegistrationDto` and `LoginDto` are inferred from schemas and used in controllers.

  - File contents (`server/dtos/auth.schema.ts`):

```typescript
import { z } from 'zod';

export const registrationSchema = z.object({
  email: z.email(),
  password: z.string().min(3).max(32),
});

export const loginSchema = z.object({
  email: z.email(),
  password: z.string(),
});

export type RegistrationDto = z.infer<typeof registrationSchema>;
export type LoginDto = z.infer<typeof loginSchema>;

// const emailSchema = z
//   .string()
//   .email('Невірний формат email')
//   .trim()
//   .toLowerCase();
//
// const passwordSchema = z
//   .string()
//   .min(8, 'Пароль має бути не менше 8 символів')
//   .max(32, 'Пароль занадто довгий')
//   .regex(/[A-Z]/, 'Має містити хоча б одну велику літеру')
//   .regex(/[0-9]/, 'Має містити хоча б одну цифру');
//
// export const registrationSchema = z.object({
//   email: emailSchema,
//   password: passwordSchema,
//   confirmPassword: z.string(),
// }).refine((data) => data.password === data.confirmPassword, {
//   message: "Паролі не збігаються",
//   path: ["confirmPassword"],
// });
//
// export const loginSchema = z.object({
//   email: emailSchema,
//   password: z.string().min(1, 'Пароль обов’язковий'),
// });
//
// export type RegistrationDto = z.infer<typeof registrationSchema>;
// export type LoginDto = z.infer<typeof loginSchema>;

```

- `server/dtos/user-dto.ts`
  - Purpose: Sanitize DB user model to DTO shape returned to clients and embedded in tokens (contains id, email, isActivated).

  - File contents (`server/dtos/user-dto.ts`):

```typescript
export default class UserDto {
  email: string;
  id: string;
  isActivated: boolean;

  constructor(model: any) {
    this.email = model.email;
    this.id = model.id;
    this.isActivated = model.isActivated;
  }
}

```

- `server/exceptions/api-error.ts`
  - Purpose: Domain Error class carrying HTTP status and details; provides helpers such as `BadRequest` and `UnauthorizedError` used throughout the app.

  - File contents (`server/exceptions/api-error.ts`):

```typescript
export default class ApiError extends Error {
  status: number;
  errors: any[];

  constructor(status: number, message: string, errors: any[] = []) {
    super(message);
    this.status = status;
    this.errors = errors;
  }

  static UnauthorizedError() {
    return new ApiError(401, 'User has not authorized');
  }

  static BadRequest(message: string, errors: any[] = []) {
    return new ApiError(400, message, errors);
  }
}

```

- `server/middleware/validate-middleware.ts`
  - Purpose: Factory returning middleware that validates `req.body` with a Zod schema, normalizes data on success and forwards validation errors using `ApiError.BadRequest` on failure.

  - File contents (`server/middleware/validate-middleware.ts`):

```typescript
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

```

- `server/middleware/auth-middleware.ts`
  - Purpose: Protect endpoints by validating Bearer access tokens (via `token-service.validateAccessToken`) and populating `req.user` with the decoded payload; on failure call `next(ApiError.UnauthorizedError())`.

  - File contents (`server/middleware/auth-middleware.ts`):

```typescript
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

```

- `server/middleware/error-middleware.ts`
  - Purpose: Global error handler that maps `ApiError` instances to HTTP responses; logs unknown errors and returns a 500 generic message otherwise.

  - File contents (`server/middleware/error-middleware.ts`):

```typescript
import { Request, Response, NextFunction } from 'express';
import ApiError from '../exceptions/api-error.js';

export default function (
  err: unknown,
  req: Request,
  res: Response,
  next: NextFunction,
) {
  console.log(err);

  if (err instanceof ApiError) {
    return res
      .status(err.status)
      .json({ message: err.message, errors: err.errors });
  }

  return res.status(500).json({ message: 'Unexpected error' });
}

```

- `server/types/websocket.types.ts`
  - Purpose: TypeScript interfaces (Figure, Point, ConnectionMessage, DrawMessage, ExtendedWebSocket) and Zod runtime schemas for WS message validation (PointSchema, FigureSchema, ConnectionMessageSchema, DrawMessageSchema, WsMessageSchema).
  - Role: Definitive runtime contract for WebSocket payloads used by the `WebSocketController`.

  - File contents (`server/types/websocket.types.ts`):

```typescript
import WebSocket from 'ws';
import { z } from 'zod';

export type FigureType = 'brush' | 'rect' | 'circle' | 'eraser';

export interface Point {
  x: number;
  y: number;
}

export interface Figure {
  type: FigureType;
  x: number;
  y: number;
  width?: number;
  height?: number;
  radius?: number;
  color?: string;
  strokeWidth?: number;
  points?: Point[];
}

export interface ConnectionMessage {
  method: 'connection';
  id: string; // room/session id
  username: string;
}

export interface DrawMessage {
  method: 'draw';
  id: string; // room/session id
  figure: Figure;
}

export type WsMessage = ConnectionMessage | DrawMessage;

export interface ExtendedWebSocket extends WebSocket {
  id?: string; // room id
  username?: string;
}

// Zod schemas for runtime validation
export const PointSchema = z.object({
  x: z.number(),
  y: z.number(),
});

export const FigureSchema = z.object({
  type: z.enum(['brush', 'rect', 'circle', 'eraser']),
  x: z.number(),
  y: z.number(),
  width: z.number().optional(),
  height: z.number().optional(),
  radius: z.number().optional(),
  color: z.string().optional(),
  strokeWidth: z.number().optional(),
  points: z.array(PointSchema).optional(),
});

export const ConnectionMessageSchema = z.object({
  method: z.literal('connection'),
  id: z.string(),
  username: z.string(),
});

export const DrawMessageSchema = z.object({
  method: z.literal('draw'),
  id: z.string(),
  figure: FigureSchema,
});

export const WsMessageSchema = z.discriminatedUnion('method', [
  ConnectionMessageSchema,
  DrawMessageSchema,
]);

export type WsMessageSchemaType = z.infer<typeof WsMessageSchema>;

```

- `server/types/validated-request.ts`
  - Purpose: Type helper to represent Express `Request` with a typed `body` after validation.

  - File contents (`server/types/validated-request.ts`):

```typescript
import { Request, Response, NextFunction } from 'express';

export interface ValidatedRequest<T> extends Request {
  body: T;
}

export type ValidatedRequestHandler<T> = (
  req: ValidatedRequest<T>,
  res: Response,
  next: NextFunction,
) => unknown;

```

- `server/request.http`
  - Purpose: Collections of example REST requests to exercise the API endpoints during manual testing (registration, login, logout, get users).

- `server/Dockerfile`
  - Purpose: Docker image build instructions for the server. It installs dependencies and runs `npm run dev` in the container (note: currently configured to run a development command in the final image).

- `server/package.json` and `server/tsconfig.json`
  - Purpose: `package.json` defines scripts (`dev`, `start`, `build`) and dependencies used at runtime; `tsconfig.json` configures TypeScript compilation settings used by `tsc` for production builds and dev workflows.

- Top-level files included in this doc:
  - `.env` (developer-provided runtime values; not stored in repo): expected to contain JWT secrets, DB URL, Google OAuth credentials, etc.
  - `.env.example`: lists required env keys for dev and production.
  - `docker-compose.development.yml`: local development stack (Postgres + server dev mount + client dev server) relying on `.env` via `env_file` and templated values.
    - File contents (`docker-compose.development.yml`):

  ```yaml
  services:
    db:
      image: postgres:15
      environment:
        POSTGRES_DB: appdb
        POSTGRES_USER: dev
        POSTGRES_PASSWORD: dev
      ports:
        - "5432:5432"
      networks:
        - prisma-network
      healthcheck:
        test: ["CMD-SHELL", "pg_isready -U dev -d appdb"]
        interval: 5s
        timeout: 2s
        retries: 20
      volumes:
        - postgres_data:/var/lib/postgresql/data
      command: postgres -c listen_addresses='*'
      logging:
        options:
          max-size: "10m"
          max-file: "3"

    server:
      build: 
        context: ./server
        dockerfile: Dockerfile
      command: sh -c "npx prisma db push && npm run dev"
      volumes:
        - ./server:/usr/src/app
        - /usr/src/app/node_modules
      depends_on:
        db:
          condition: service_healthy
      networks:
        - prisma-network
      env_file:
        - .env
      environment:
        - PORT=${PORT}
        - DATABASE_URL=postgres://${POSTGRES_USER:-dev}:${POSTGRES_PASSWORD:-dev}@db:5432/${POSTGRES_DB:-appdb}
      ports:
        - "${PORT}:${PORT}"

  networks:
    prisma-network:

  volumes:
    postgres_data:
  ```
  - `docker-compose.yml`: production-focused composition (postgres with volume, server build, client build step, nginx serving built client).


**Auth Flow (detailed sequence)**

This section explains authentication / account lifecycle and which files/models are involved.

- Registration (`POST /api/registration`)
  - Controller: `user-controller.registration` receives `RegistrationDto` validated by `validate-middleware(registrationSchema)`.
  - Service: `user-service.registration` logic:
    - Check `prisma.user.findUnique({ where: { email } })` for an existing user.
    - If user exists -> throw `ApiError.BadRequest`.
    - Hash provided password with `bcrypt` (saltRounds = 3 in code) and create a unique `activationLink` (UUID).
    - Create user record via `prisma.user.create({ data: { ... } })`.
    - Send activation link email using `mail-service.sendActivationMail(to, ${env.API_URL}/api/activate/${activationLink})`.
    - Create `UserDto` and generate access/refresh tokens via `token-service.generateTokens(payload)`.
    - Persist refresh token via `token-service.saveToken(userDto.id, refreshToken)`.
  - Controller sets `refreshToken` cookie (httpOnly, long maxAge) and returns tokens and `user` DTO.
  - DB: `User` row created; `Token` created with refresh token.

- Activation (`GET /api/activate/:link`)
  - Controller: `user-controller.activate` receives activation link param.
  - Service: `user-service.activate` finds user by `activationLink` via Prisma; if not found throw `BadRequest`; otherwise update `isActivated: true` using `prisma.user.update`.
  - Controller redirects to `env.CLIENT_URL` after activation.

- Login (`POST /api/login`)
  - Controller: `user-controller.login` receives `LoginDto` validated by `validate-middleware(loginSchema)`.
  - Service: `user-service.login` finds user by email, verifies password with `bcrypt.compare`, throws `BadRequest` on failure, generates tokens, saves refresh token, returns tokens + user DTO.
  - Controller sets `refreshToken` cookie and returns JSON response.

- Refresh (`GET /api/refresh`)
  - Controller: `user-controller.refresh` reads `refreshToken` cookie; if missing -> `UnauthorizedError`.
  - Service: `user-service.refresh` validates refresh token using `token-service.validateRefreshToken`, checks existence in DB via `tokenService.findToken`, finds associated `User`, generates new tokens, saves refresh token (rotates), returns new tokens + user DTO.
  - Controller sets new `refreshToken` cookie and returns JSON.

- Logout (`POST /api/logout`)
  - Controller: `user-controller.logout` reads refresh cookie; if missing -> `Unauthorized`; calls `user-service.logout` which deletes token DB entry via `tokenService.removeToken(refreshToken)`. Controller clears cookie and returns deletion info.

Notes about tokens and cookies:
- Access token: short-lived JWT (30m) signed with `JWT_ACCESS_SECRET`; delivered in `Authorization: Bearer <token>` header for protected requests.
- Refresh token: long-lived JWT (30d) signed with `JWT_REFRESH_SECRET`; persisted in DB `Token` table and also placed in a `HttpOnly` cookie by the server. Cookie is not set with `secure: true` in current code (comment notes `//{ s : true} for https`).

**WebSocket Flow**

- Entry: client connects to root WebSocket endpoint registered at `wsApp.ws('/', ...)` in `server/index.ts`. The `WebSocketController` instance is created with the `wss` server and `handleConnection(ws)` is called for each connect.
- Message model: defined in `server/types/websocket.types.ts` with Zod runtime validation. Two message discriminants are used: `connection` (carries `id` and `username`) and `draw` (carries `id` and `figure` payload describing drawing primitives).
- On connection: controller sends a welcome message, then listens for `message` events. Each message is JSON-parsed and validated against `WsMessageSchema`.
- `connection` messages: controller sets `ws.id` and `ws.username`, then broadcasts a `connection` event to other clients that match the same `id` (interpreted as a room/session id).
- `draw` messages: controller broadcasts the drawing payload to clients where `extendedClient.id === msg.id` and socket is open, allowing multiple clients in the same room to receive drawing updates in real-time.
- Error handling: malformed messages log validation errors and are ignored; runtime errors in message parsing are caught and logged.

**Prisma models & DB usage**

- Models (from `prisma/schema.prisma`):
  - `User`:
    - Fields: `id: uuid`, `email: unique string`, `password: string`, `isActivated: boolean` (default false), `activationLink: string?`, `token: Token?` relation.
    - Role: store user credentials and activation state.
  - `Token`:
    - Fields: `id: uuid`, `refreshToken: string`, `user` relation (fields: `userId` unique).
    - Role: persist the current refresh token per user for rotation/revocation.
- Runtime instantiation: `server/db.ts` constructs a `pg.Pool` then uses `@prisma/adapter-pg` to create a `PrismaClient` connected to the provided `DATABASE_URL`. Services import the `prisma` instance for all DB operations.

**Environment variables (summary & where used)**

- `PORT` — server listen port (`server/index.ts`, `config/env.ts`); used in docker-compose templating.
- `DATABASE_URL` — Postgres connection string used by `server/db.ts`, `prisma.config.ts`, and Docker compose templates.
- `CLIENT_URL` — used in CORS configuration and to redirect after account activation (`server/index.ts`, `controllers/user-controller.ts`).
- `API_URL` — used when composing activation link sent via email (`service/mail-service.ts` and `service/user-service.ts`).
- `REACT_APP_API_URL` — used by client dev container (docker-compose.development.yml) to target API.
- `SMTP_SERVICE`, `GOOGLE_CLIENT`, `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `GOOGLE_REFRESH_TOKEN` — used by `service/mail-service.ts` to configure Nodemailer OAuth2 transporter.
- `JWT_ACCESS_SECRET`, `JWT_REFRESH_SECRET` — used by `service/token-service.ts` to sign/verify access and refresh tokens.
- Additional (present in `.env.example`): `DISABLE_EMAILS` (hinted but not strictly enforced in code), and Postgres container credentials (`POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB`) referenced in compose files.

**Docker Compose**

- Development (`docker-compose.development.yml`):
  - Services: `db` (Postgres 15) with healthcheck and mounted volume; `server` (build context `./server`, runs `npx prisma db push && npm run dev`, mounts `./server` into container for live edits); `client` (React dev server with hot reload).
  - Env: uses `env_file: .env` so `.env` must be present for env interpolation; templates `DATABASE_URL` to point at `db` service.
  - Networking: single `prisma-network` connecting services.

- Production (`docker-compose.yml`):
  - Services: `db` (persistent volume), `server` (build from `./server`), `client` (build assets then write to shared volume), `nginx` (serves built client and proxies to server when required).
  - Volumes: `db-data-prod`, `build_data` to persist DB and share client build artifacts.

**Security / Caveats**

- `.env` is not committed (good), but the provided `.env` attachment contains real secrets (JWT secrets and Google OAuth tokens). Treat any checked `.env` contents as sensitive — rotate if they are real values.
- Bcrypt cost factor: code uses `bcrypt.hash(password, 3)` — `3` is a low work factor for production; increase (e.g., 10+) depending on performance/security trade-offs.
- Cookies: `refreshToken` cookie is set with `httpOnly` but `secure` is not set in code; a comment notes `//{ s : true} for https`. In production behind HTTPS the cookie should be set with `secure: true` and appropriate `sameSite` attributes.
- Dockerfile: the server `Dockerfile` runs `npm run dev` which uses development tooling; verify that production images run `npm start` or a proper production command.
- Token storage: `Token` records don't include expiration metadata — rotation is enforced but DB cleanup policy for stale tokens is not implemented.
- Error/logging: errors are logged to console; consider structured logging and masking of sensitive info for production.
- Prisma adapter+pool: using a `pg.Pool` with `PrismaPg` adapter is fine for local/monolithic deployments but requires connection tuning and proper lifecycle handling for scaled deployments.

**Recommended quick fixes**

- Increase bcrypt cost (salt rounds) from `3` to at least `10` in `user-service.ts`.
- Set `secure: true` on `res.cookie('refreshToken', ...)` in production (use environment check or `env.NODE_ENV`) and add `sameSite` policy.
- Ensure `.env` containing credentials is not committed and manage secrets via a secrets manager (Vault, AWS Secrets Manager, etc.) in production.
- Modify `server/Dockerfile` to run a production command in production builds (e.g., `npm run build` then `npm start`) and reserve `npm run dev` only for development images.
- Add token expiry metadata or a background cleanup job for the `Token` table to avoid indefinite DB growth over time.
- Centralize and enhance logging (replace console logs with a structured logger and avoid printing secrets).

**References**

- Key files referenced in this doc: `server/index.ts`, `server/db.ts`, `server/prisma/schema.prisma`, `server/config/env.ts`, `server/service/user-service.ts`, `server/service/token-service.ts`, `server/service/mail-service.ts`, `server/controllers/websocket-controller.ts`, `server/route/index.ts`, `docker-compose.development.yml`, `docker-compose.yml`, `.env.example`.
