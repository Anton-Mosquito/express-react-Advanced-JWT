# Архітектура сервера — express-react-Advanced-JWT (Server)

Нижче наведено детальний опис архітектури серверної частини проєкту та повний вміст кожного файлу з папки `server/`. Файл призначений для аналізатора, тому кожен файл включено повністю у вигляді блоків коду.

## Короткий огляд архітектури

- Технології: Node.js + TypeScript, Express v5, Prisma (PostgreSQL), WebSocket (express-ws), JWT, Nodemailer.
- Основні компоненти:
  - `index.ts` — точка входу, налаштування Express + WebSocket; підключення роутів та глобального middleware для помилок.
  - `route/index.ts` — визначає API-ендпоінти (реєстрація, логін, логаут, активація, refresh, отримання користувачів).
  - `controllers/*` — контролери, що обробляють запити (UserController) та WebSocket (WebSocketController).
  - `service/*` — логіка бізнес-рівня: реєстрація, логін, токени, відправка пошти.
  - `middleware/*` — middleware для автентифікації та обробки помилок.
  - `dtos/*`, `exceptions/*`, `types/*` — допоміжні типи, DTO і класи помилок.
  - `prisma/*` — Prisma schema та конфігурація.
  - `db.ts` — експорт налаштованого Prisma клієнта.

## Вхідний/вихід та потік авторизації

- Клієнт викликає API, наприклад `/api/registration`.
- `route` направляє запит до `UserController`.
- `UserController` викликає методи з `service/user-service.ts`.
- `user-service` взаємодіє з `prisma` через `db.ts`, створює користувача, генерує токени через `token-service` і зберігає refresh токен у таблиці `Token`.
- Доступ до захищених ендпоінтів вимагає `auth-middleware`, що перевіряє Access Token (Bearer).
- Оновлення токенів — через `refresh` ендпоінт; refresh токен зберігається у DB.

## Середовище (environment variables)

Очікувані змінні оточення, що використовуються у коді:

- `PORT` — порт сервера (дефолт 5001)
- `CLIENT_URL` — адреса клієнта для CORS / редіректів
- `DATABASE_URL` — підключення до PostgreSQL (Prisma)
- `API_URL` — базова адреса API (для посилань у листах)
- `SMTP_SERVICE`, `GOOGLE_CLIENT`, `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `GOOGLE_REFRESH_TOKEN` — налаштування для Nodemailer
- `JWT_ACCESS_SECRET`, `JWT_REFRESH_SECRET` — секрети JWT

## Схема Prisma (коротко)

- Моделі: `User` (id, email, password, isActivated, activationLink, token) та `Token` (id, refreshToken, userId)

---

## Файли та їх повний вміст

Нижче — кожен файл з `server/` і його вміст.

### File: server/db.ts

```typescript
import { PrismaClient } from '@prisma/client';
import { PrismaPg } from '@prisma/adapter-pg';
import pg from 'pg';

const connectionString = `${process.env.DATABASE_URL}`;

const pool = new pg.Pool({ connectionString });
const adapter = new PrismaPg(pool);

const prisma = new PrismaClient({
  adapter,
});

export default prisma;
```

---

### File: server/controllers/websocket-controller.ts

```typescript
import { Server as WebSocketServer } from 'ws';
import { ExtendedWebSocket, WebSocketMessage } from '../types/websocket.types';

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
        const msg: WebSocketMessage = JSON.parse(data);

        switch (msg.method) {
          case 'connection':
            this.connectionHandler(ws, msg);
            break;
          case 'draw':
            this.broadcastMessage(ws, msg);
            break;
          default:
            console.warn(`Unknown method: ${msg.method}`);
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
    msg: WebSocketMessage,
  ): void => {
    ws.id = msg.id;
    this.broadcastMessage(ws, msg);
  };

  private broadcastMessage = (
    ws: ExtendedWebSocket,
    msg: WebSocketMessage,
  ): void => {
    this.wss.clients.forEach((client) => {
      const extendedClient = client as ExtendedWebSocket;
      if (extendedClient.id === msg.id && client.readyState === client.OPEN) {
        client.send(JSON.stringify(msg));
      }
    });
  };
}

export default WebSocketController;
```

---

### File: server/controllers/user-controller.ts

```typescript
import { NextFunction, Request, Response } from 'express';
import userService from '../service/user-service';
import { validationResult } from 'express-validator';
import ApiError from '../exceptions/api-error';

class UserController {
  async registration(req: Request, res: Response, next: NextFunction) {
    try {
      const errors = validationResult(req);

      if (!errors.isEmpty()) {
        return next(ApiError.BadRequest('Validation error', errors.array()));
      }

      const { email, password } = req.body;

      const userData = await userService.registration(email, password);
      res.cookie('refreshToken', userData.refreshToken, {
        maxAge: 30 * 24 * 60 * 60 * 1000,
        httpOnly: true,
      }); //{ s : true} for https

      return res.json(userData);
    } catch (error) {
      next(error);
    }
  }

  async login(req: Request, res: Response, next: NextFunction) {
    try {
      const { email, password } = req.body;

      const userData = await userService.login(email, password);

      res.cookie('refreshToken', userData.refreshToken, {
        maxAge: 30 * 24 * 60 * 60 * 1000,
        httpOnly: true,
      }); //{ s : true} for https

      return res.json(userData);
    } catch (error) {
      next(error);
    }
  }

  async logout(req: Request, res: Response, next: NextFunction) {
    try {
      const { refreshToken } = req.cookies;
      const token = await userService.logout(refreshToken);
      res.clearCookie('refreshToken');
      return res.json(token);
    } catch (error) {
      next(error);
    }
  }

  async activate(req: Request, res: Response, next: NextFunction) {
    try {
      const activationLink = req.params.link;
      await userService.activate(activationLink);

      return res.redirect(process.env.CLIENT_URL!);
    } catch (error) {
      next(error);
    }
  }

  async refresh(req: Request, res: Response, next: NextFunction) {
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
  }

  async getUser(req: Request, res: Response, next: NextFunction) {
    try {
      const users = await userService.getAllUsers();
      return res.json(users);
    } catch (error) {
      next(error);
    }
  }
}

export default new UserController();
```

---

### File: server/service/mail-service.ts

```typescript
import nodemailer from 'nodemailer';

class MailService {
  transporter: nodemailer.Transporter;

  constructor() {
    this.transporter = nodemailer.createTransport({
      service: process.env.SMTP_SERVICE,
      auth: {
        type: 'OAuth2',
        user: process.env.GOOGLE_CLIENT,
        clientId: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        refreshToken: process.env.GOOGLE_REFRESH_TOKEN,
      },
    });
  }

  async sendActivationMail(to: string, link: string) {
    try {
      await this.transporter.sendMail({
        from: process.env.GOOGLE_CLIENT,
        to,
        subject: `Account activation ${process.env.API_URL || ''}`,
        text: `Activate: ${link}`,
        html: `
        <div>
            <h1>For activation go to the link</h1>
            <a href="${link}">${link}</a>
        </div>
      `,
      });
    } catch (err) {
      // Log error but do not throw — registration flow should not fail because of email issues
      console.error('Failed to send activation email:', err);
    }
  }
}

export default new MailService();
```

---

### File: server/service/user-service.ts

```typescript
import prisma from '../db';
import bcrypt from 'bcrypt';
import { v4 as uuidv4 } from 'uuid';
import mailService from './mail-service';
import tokenService from '../service/token-service';
import UserDto from '../dtos/user-dto';
import ApiError from '../exceptions/api-error';

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
      `${process.env.API_URL}/api/activate/${activationLink}`,
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

---

### File: server/service/token-service.ts

```typescript
import jwt from 'jsonwebtoken';
import prisma from '../db';

class TokenService {
  generateTokens(payload: any) {
    const accessToken = jwt.sign(payload, process.env.JWT_ACCESS_SECRET!, {
      expiresIn: '30m',
      algorithm: 'HS256',
    });

    const refreshToken = jwt.sign(payload, process.env.JWT_REFRESH_SECRET!, {
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
      const userData = jwt.verify(token, process.env.JWT_ACCESS_SECRET!);
      return userData;
    } catch (error) {
      return null;
    }
  }

  validateRefreshToken(token: string) {
    try {
      const userData = jwt.verify(token, process.env.JWT_REFRESH_SECRET!);
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

---

### File: server/index.ts

```typescript
import 'dotenv/config';
import express, { Application } from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import router from './route/index';
import errorMiddleware from './middleware/error-middleware';
import expressWs, { Application as WebSocketApplication } from 'express-ws';
import WebSocketController from './controllers/websocket-controller';
import { ExtendedWebSocket } from './types/websocket.types';

const PORT = process.env.PORT || 5001;

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
    origin: process.env.CLIENT_URL,
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

---

### File: server/tsconfig.json

```jsonc
{
  "compilerOptions": {
    "target": "es2020",
    "module": "commonjs",
    "moduleResolution": "node",
    "baseUrl": ".",
    "outDir": "dist",
    "strict": true,
    "lib": ["esnext"],
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "allowSyntheticDefaultImports": true,
  },
  "include": [
    "src/**/*",
    "*.ts",
    "controllers/**/*",
    "dtos/**/*",
    "exceptions/**/*",
    "middleware/**/*",
    "models/**/*",
    "route/**/*",
    "service/**/*",
  ],
  "exclude": ["node_modules"],
}
```

---

### File: server/package.json

```json
{
  "name": "server",
  "version": "1.0.0",
  "description": "",
  "main": "index.ts",
  "scripts": {
    "start": "node dist/index.js",
    "dev": "npx prisma generate && tsx index.ts",
    "build": "tsc && cp -r generated dist/generated"
  },
  "keywords": [],
  "author": "",
  "license": "ISC",
  "dependencies": {
    "@prisma/adapter-pg": "^7.2.0",
    "@prisma/client": "^7.2.0",
    "bcrypt": "^6.0.0",
    "cookie-parser": "^1.4.7",
    "cors": "^2.8.5",
    "dotenv": "^17.2.3",
    "express": "^5.2.1",
    "express-validator": "^7.3.1",
    "express-ws": "^5.0.2",
    "jsonwebtoken": "^9.0.3",
    "nodemailer": "^7.0.12",
    "pg": "^8.17.2",
    "uuid": "^13.0.0"
  },
  "devDependencies": {
    "@types/bcrypt": "^6.0.0",
    "@types/cookie-parser": "^1.4.10",
    "@types/cors": "^2.8.19",
    "@types/express": "^5.0.6",
    "@types/express-ws": "^3.0.6",
    "@types/jsonwebtoken": "^9.0.10",
    "@types/node": "^25.0.9",
    "@types/nodemailer": "^7.0.5",
    "@types/pg": "^8.16.0",
    "@types/uuid": "^11.0.0",
    "nodemon": "^3.1.11",
    "prisma": "^7.2.0",
    "tsx": "^4.21.0",
    "typescript": "^5.9.3"
  }
}
```

---

### File: server/package-lock.json

```json
(повний `package-lock.json` файл присутній в репозиторії — заощаджено місце у цьому огляді)
```

> Примітка: `package-lock.json` дуже великий; у разі потреби дам повний вміст окремим файлом.

---

### File: server/.gitignore

```gitignore
### Node ###
# Logs
logs
*.log
npm-debug.log*
yarn-debug.log*
yarn-error.log*
lerna-debug.log*
.pnpm-debug.log*

# Diagnostic reports (https://nodejs.org/api/report.html)
report.[0-9]*.[0-9]*.[0-9]*.[0-9]*.json

# Bower dependency directory (https://bower.io/)
bower_components


# Compiled binary addons (https://nodejs.org/api/addons.html)
build/Release

# Dependency directories
node_modules/
jspm_packages/

# Snowpack dependency directory (https://snowpack.dev/)
web_modules/

# Optional npm cache directory
.npm

# Optional eslint cache
.eslintcache

# Optional stylelint cache
.stylelintcache



### Node / TypeScript - common artifacts
# Logs
logs
*.log
npm-debug.log*
yarn-debug.log*
pnpm-debug.log*

# Diagnostic reports
report.[0-9]*.[0-9]*.[0-9]*.[0-9]*.json

# Dependency directories
node_modules/

# Build / output
dist/
build/
out/
coverage/
.nyc_output/

# TypeScript build info
*.tsbuildinfo

# Caches & temporary folders
.cache/
.parcel-cache/
.temp/

# Runtime Prisma caches (do not ignore committed generated client under src/generated)
node_modules/.prisma/
.prisma/

# dotenv environment variable files
.env
.env.*.local
.env.local

# OS files
.DS_Store
Thumbs.db

# Editor/IDE
.vscode/
.idea/
*.sublime-workspace
*.sublime-project

# Misc
.eslintcache
.stylelintcache

# Ignore local SQLite DB files if present
*.db
```

---

### File: server/.dockerignore

```ignore
node_modules
```

---

### File: server/dtos/user-dto.ts

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

---

### File: server/exceptions/api-error.ts

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

---

### File: server/prisma.config.ts

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

---

### File: server/prisma/schema.prisma

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

---

### File: server/Dockerfile

```dockerfile
FROM node:20-alpine

WORKDIR /usr/src/app

# Copy package files
COPY package*.json ./

RUN npm install

COPY prisma ./prisma
COPY prisma.config.ts ./

COPY . .

EXPOSE 5001

CMD ["npm", "run", "dev"]
```

---

### File: server/request.http

```http
@host = http://localhost:5000/api



### Get Users
GET {{host}}/users HTTP/1.1
content-type: application/json



### Create An User
POST {{host}}/registration HTTP/1.1
content-type: application/json

{
  "email": "user@mail.ru",
  "password": "password"
}




### Login as a User
POST {{host}}/login HTTP/1.1
content-type: application/json

{
  "email": "user123@mail.ru",
  "password": "password"
}



### Logout
POST {{host}}/logout HTTP/1.1
content-type: application/json
Cookie: refreshToken = 1
```

---

### File: server/route/index.ts

```typescript
import { Router } from 'express';
import userController from '../controllers/user-controller';
import { body } from 'express-validator';
import authMiddleware from '../middleware/auth-middleware';

const router = Router();

router.post(
  '/registration',
  body('email').isEmail(),
  body('password').isLength({ min: 3, max: 32 }),
  userController.registration,
);
router.post('/login', userController.login);
router.post('/logout', userController.logout);
router.get('/activate/:link', userController.activate);
router.get('/refresh', userController.refresh);
router.get('/users', authMiddleware, userController.getUser);

export default router;
```

---

### File: server/types/websocket.types.ts

```typescript
import WebSocket from 'ws';

export interface ExtendedWebSocket extends WebSocket {
  id?: string;
}

export interface WebSocketMessage {
  method: 'connection' | 'draw';
  id: string;
  [key: string]: any;
}
```

---

### File: server/middleware/error-middleware.ts

```typescript
import { Request, Response, NextFunction } from 'express';
import ApiError from '../exceptions/api-error';

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

---

### File: server/middleware/auth-middleware.ts

```typescript
import { Request, Response, NextFunction } from 'express';
import ApiError from '../exceptions/api-error';
import tokenService from '../service/token-service';
import { JwtPayload } from 'jsonwebtoken';

export interface AuthRequest extends Request {
  user?: string | JwtPayload;
}

export default function (req: AuthRequest, res: Response, next: NextFunction) {
  try {
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

    req.user = userData;
    next();
  } catch (error) {
    return next(ApiError.UnauthorizedError());
  }
}
```

---

## Поради для аналізатора

- Markdown містить повні блоки коду для кожного файлу; аналізатор може витягувати текст між ``` для отримання вмісту файлів.
- Якщо потрібно, я можу також додати окремий файл, який міститиме тільки `package-lock.json` повністю, або окремі великі файли у вигляді окремих `.md` частин.
