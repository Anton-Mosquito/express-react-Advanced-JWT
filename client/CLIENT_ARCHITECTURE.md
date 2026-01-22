# CLIENT_ARCHITECTURE

Документ містить детальний опис архітектури клієнтської частини проекту (React + TypeScript + MobX) українською з паралельним перекладом англійською. Також файл включає повні вмісти ключових файлів з папки `client/src` та конфігураційних файлів для полегшення аналізу.

---

## Огляд / Overview

- UA: Клієнт — це SPA на React + TypeScript, що використовує `mobx` для стану, `axios` для HTTP-запитів та просту авторизацію через access/refresh токени. Вхідна точка — `src/index.tsx`, головний компонент — `src/App.tsx`.
- EN: The client is a React + TypeScript SPA using `mobx` for state management, `axios` for HTTP calls and an access/refresh token-based auth flow. Entry point is `src/index.tsx`, main component is `src/App.tsx`.

---

## Архітектура додатку / Application architecture

- UA: Основні підсистеми:
  - UI: компоненти у `src/components` (зокрема `LoginForm.tsx`).
  - HTTP-шар: `src/http/index.ts` — axios-інстанс з інтерсепторами (додає токен, виконує refresh при 401).
  - Сервіси: `src/services` — обгортки для HTTP ендпоїнтів (`AuthService`, `UserService`).
  - Моделі: `src/models` — типи TypeScript (`IUser`, `AuthResponse`).
  - Сховище: `src/store/store.ts` — MobX store з методами авторизації (login, registration, logout, checkAuth).

- EN: Major subsystems:
  - UI: components in `src/components` (notably `LoginForm.tsx`).
  - HTTP layer: `src/http/index.ts` — axios instance with interceptors (adds token, performs refresh on 401).
  - Services: `src/services` — HTTP wrappers (`AuthService`, `UserService`).
  - Models: `src/models` — TypeScript interfaces (`IUser`, `AuthResponse`).
  - Store: `src/store/store.ts` — MobX store with auth flow methods (login, registration, logout, checkAuth).

---

## Boot / Entry flow (UA / EN)

- UA: `src/index.tsx` створює `Store` і передає його через `Context`. `App.tsx` підключається до `Context` і при завантаженні (useEffect) викликає `store.checkAuth()` якщо в `localStorage` є `token`.
- EN: `src/index.tsx` instantiates `Store` and provides it via `Context`. `App.tsx` consumes the `Context` and on mount calls `store.checkAuth()` if there is a `token` in `localStorage`.

---

## HTTP / Authorization (UA / EN)

- UA: HTTP-інстанс налаштований у `src/http/index.ts`. Коротка логіка:
  - `API_URL` задається через `REACT_APP_API_URL` або дефолт `http://localhost:5001/api`.
  - Інтерсептор request додає заголовок `Authorization: Barer <token>` з `localStorage`.
  - Інтерсептор response ловить помилку 401, виконує GET `${API_URL}/refresh` (з `withCredentials: true`) для отримання нового accessToken, зберігає його в `localStorage` і повторює початковий запит.

- EN: The axios instance (`src/http/index.ts`) implements:
  - `API_URL` from `REACT_APP_API_URL` or default `http://localhost:5001/api`.
  - Request interceptor adds `Authorization: Barer <token>` from `localStorage`.
  - Response interceptor catches 401, calls `${API_URL}/refresh` (withCredentials) to get a new accessToken, stores it in `localStorage`, and retries the original request.

### Код: `src/http/index.ts`

```typescript
import axios, { AxiosResponse } from 'axios';
import { AxiosRequestConfig } from "axios";
import { AuthResponse } from '../models/response/AuthResponse';

export const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:5001/api';

const $api = axios.create({
    withCredentials:true,
    baseURL: API_URL
})

$api.interceptors.request.use((config: AxiosRequestConfig ) => {
    config.headers = {
        Authorization: `Barer ${localStorage.getItem('token')}`,
    };
    return config;
});

$api.interceptors.response.use((config: AxiosResponse ) => {
    return config;
}, async (error) => {
    const originalRequest = error.config;
    if(error.response.status === 401 && error.config && !error.config?._isRetry) {
        originalRequest._isRetry = true;
        try {
            const response = await axios.get<AuthResponse>(`${API_URL}/refresh`, { withCredentials:true });
            localStorage.setItem('token', response.data.accessToken);
            return $api.request(originalRequest);
        } catch (error) {
            console.log('Not authorized',error);
        }
    }
    throw error;
});

export default $api;
```

---

## MobX Store (UA / EN)

- UA: `src/store/store.ts` містить поля `user`, `isAuth`, `isLoading` та методи `login`, `registration`, `logout`, `checkAuth`. Методи використовують `AuthService` і `axios` для `checkAuth`. Після успішного логіну/реєстрації/refresh зберігають `accessToken` у `localStorage` і встановлюють `isAuth=true` та `user`.
- EN: `src/store/store.ts` provides `user`, `isAuth`, `isLoading` and methods `login`, `registration`, `logout`, `checkAuth`. Methods call `AuthService` and `axios` (for checkAuth). On success they store `accessToken` in `localStorage` and set `isAuth=true` and `user`.

### Код: `src/store/store.ts`

```typescript
import { IUser } from "../models/IUser";
import { makeAutoObservable } from "mobx";
import AuthService from "../services/AuthService";
import axios from "axios";
import { AuthResponse } from "../models/response/AuthResponse";
import { API_URL } from "../http";

export default class Store {
    user = {} as IUser;
    isAuth = false;
    isLoading = false;

    constructor() {
        makeAutoObservable(this)
    }
    
    setAuth(bool: boolean) {
        this.isAuth = bool;
    }

    setUser(user:IUser) {
        this.user = user;
    }

    setLoading(bool: boolean) {
        this.isLoading = bool;
    }

    async login(email: string, password: string) {
        try {
            const response = await AuthService.login(email, password);
            console.log("🚀 ~ file: store.ts ~ line 24 ~ Store ~ login ~ response", response)
            localStorage.setItem('token', response.data.accessToken);
            this.setAuth(true);
            this.setUser(response.data.user)
        } catch (error) {
            //console.log(error.response?.data?.message);
        }
    }

    async registration(email: string, password: string) {
        try {
            const response = await AuthService.registration(email, password);
            console.log("🚀 ~ file: store.ts ~ line 35 ~ Store ~ registration ~ response", response)
            localStorage.setItem('token', response.data.accessToken);
            this.setAuth(true);
            this.setUser(response.data.user)
        } catch (error) {
            //console.log(error.response?.data?.message);
        }
    }

    async logout() {
        try {
            const response = await AuthService.logout();
            localStorage.removeItem('token');
            this.setAuth(false);
            this.setUser({} as IUser)
        } catch (error) {
            //console.log(error.response?.data?.message);
        }
    }

    async checkAuth() {
        this.setLoading(true);
        try {
            const response = await axios.get<AuthResponse>(`${API_URL}/refresh`, { withCredentials:true });
            console.log("🚀 ~ file: store.ts ~ line 62 ~ Store ~ chackAuth ~ response", response)
            localStorage.setItem('token', response.data.accessToken);
            this.setAuth(true);
            this.setUser(response.data.user)
        } catch (error) {
            //console.log(error.response?.data?.message);
        } finally {
            this.setLoading(false)
        }
    }
}
```

---

## Services (UA / EN)

- UA: `src/services/AuthService.ts` та `src/services/UserService.ts` — прості обгортки над `$api` (axios інстанс). Виклики: `/login`, `/registration`, `/logout`, `/users`.
- EN: `src/services/AuthService.ts` and `src/services/UserService.ts` are simple wrappers over `$api` (axios instance). Calls: `/login`, `/registration`, `/logout`, `/users`.

### Код: `src/services/AuthService.ts`

```typescript
import $api from "../http";
import { AxiosResponse } from "axios";
import { AuthResponse } from "../models/response/AuthResponse";

export default class AuthService {
    static async login(email:string, password:string): Promise<AxiosResponse<AuthResponse>> {
        return $api.post<AuthResponse>('/login', {email, password});
    }

    static async registration(email:string, password:string): Promise<AxiosResponse<AuthResponse>> {
        return $api.post<AuthResponse>('/registration', {email, password});
    }

    static async logout(): Promise<void> {
        return $api.post('/logout');
    }
}
```

### Код: `src/services/UserService.ts`

```typescript
import { AxiosResponse } from "axios";
import $api from "../http";
import { IUser } from "../models/IUser";

export default class UserService {
    static async fetchUsers(): Promise<AxiosResponse<IUser[]>> {
        return $api.get<IUser[]>('/users');
    }
}
```

---

## Models (UA / EN)

- UA: `src/models/IUser.ts` та `src/models/response/AuthResponse.ts` описують структуру користувача та відповіді авторизації.
- EN: `src/models/IUser.ts` and `src/models/response/AuthResponse.ts` define the user structure and auth response.

### Код: `src/models/IUser.ts`

```typescript
export interface IUser {
    email: string;
    isActivated: boolean;
    id: string;
}
```

### Код: `src/models/response/AuthResponse.ts`

```typescript
import { IUser } from "../IUser";

export interface AuthResponse {
    accessToken: string;
    refreshToken: string;
    user: IUser
}
```

---

## UI Components (UA / EN)

- UA: `src/components/LoginForm.tsx` — проста форма з полями `email` та `password`. Викликає `store.login` та `store.registration`.
- EN: `src/components/LoginForm.tsx` — simple form with `email` and `password` fields. Calls `store.login` and `store.registration`.

### Код: `src/components/LoginForm.tsx`

```tsx
import { observer } from "mobx-react-lite";
import React, { FC, useContext, useState } from "react";
import { Context } from "../index";

const LoginForm: FC = () => {
    const [email, setEmail] = useState<string>('');
    const [password, setPassword] = useState<string>('');
    const { store } = useContext(Context)
    return (
        <div>
            <input type="text" placeholder="Email" value={email} onChange={(e)=> setEmail(e.target.value)}/>
            <input type="password" placeholder="Password" value={password} onChange={(e)=> setPassword(e.target.value)}/>
            <button onClick={() => store.login(email, password)}>Login</button>
            <button onClick={() => store.registration(email, password)}>Registration</button>
        </div>
    );
};

export default observer(LoginForm);
```

---

## Entry files & config (UA / EN)

- UA: нижче — конфігураційні та стартові файли для контексту збірки і запуску.
- EN: below are configuration and startup files for build/run context.

### `Dockerfile.dev`

```dockerfile
FROM node:20-alpine

WORKDIR /usr/src/app

COPY package*.json ./

RUN npm install

COPY . .

CMD ["npm", "start"]
```

### `Dockerfile.prod`

```dockerfile
FROM node:16.16.0-alpine3.16

WORKDIR /usr/src/app

COPY package*.json ./

RUN npm install

COPY . .

RUN npm run build

RUN npm install -g serve
```

### `package.json` (повний)

```json
{
  "name": "client",
  "version": "0.1.0",
  "private": true,
  "dependencies": {
    "@testing-library/jest-dom": "^5.16.1",
    "@testing-library/react": "^12.1.2",
    "@testing-library/user-event": "^13.5.0",
    "@types/axios": "^0.14.0",
    "@types/jest": "^27.4.0",
    "@types/node": "^16.11.19",
    "@types/react": "^17.0.38",
    "@types/react-dom": "^17.0.11",
    "axios": "^0.24.0",
    "mobx": "^6.3.12",
    "mobx-react-lite": "^3.2.3",
    "react": "^17.0.2",
    "react-dom": "^17.0.2",
    "react-scripts": "5.0.0",
    "typescript": "^4.5.4",
    "web-vitals": "^2.1.3"
  },
  "scripts": {
    "start": "react-scripts start",
    "build": "react-scripts build",
    "test": "react-scripts test",
    "eject": "react-scripts eject"
  },
  "eslintConfig": {
    "extends": [
      "react-app",
      "react-app/jest"
    ]
  },
  "browserslist": {
    "production": [
      ">0.2%",
      "not dead",
      "not op_mini all"
    ],
    "development": [
      "last 1 chrome version",
      "last 1 firefox version",
      "last 1 safari version"
    ]
  }
}
```

### `tsconfig.json`

```jsonc
{
  "compilerOptions": {
    "target": "es5",
    "lib": [
      "dom",
      "dom.iterable",
      "esnext"
    ],
    "allowJs": true,
    "skipLibCheck": true,
    "esModuleInterop": true,
    "allowSyntheticDefaultImports": true,
    "strict": true,
    "forceConsistentCasingInFileNames": true,
    "noFallthroughCasesInSwitch": true,
    "module": "esnext",
    "moduleResolution": "node",
    "resolveJsonModule": true,
    "isolatedModules": true,
    "noEmit": true,
    "jsx": "react-jsx"
  },
  "include": [
    "src"
  ]
}
```

### `README.md` (повний)

```markdown
# Getting Started with Create React App

This project was bootstrapped with [Create React App](https://github.com/facebook/create-react-app).

## Available Scripts

In the project directory, you can run:

### `npm start`

Runs the app in the development mode.\
Open [http://localhost:3000](http://localhost:3000) to view it in the browser.

The page will reload if you make edits.\
You will also see any lint errors in the console.

### `npm test`

Launches the test runner in the interactive watch mode.\
See the section about [running tests](https://facebook.github.io/create-react-app/docs/running-tests) for more information.

### `npm run build`

Builds the app for production to the `build` folder.\
It correctly bundles React in production mode and optimizes the build for the best performance.

The build is minified and the filenames include the hashes.\
Your app is ready to be deployed!

See the section about [deployment](https://facebook.github.io/create-react-app/docs/deployment) for more information.

### `npm run eject`

**Note: this is a one-way operation. Once you `eject`, you can’t go back!**

If you aren’t satisfied with the build tool and configuration choices, you can `eject` at any time. This command will remove the single build dependency from your project.

Instead, it will copy all the configuration files and the transitive dependencies (webpack, Babel, ESLint, etc) right into your project so you have full control over them. All of the commands except `eject` will still work, but they will point to the copied scripts so you can tweak them. At this point you’re on your own.

You don’t have to ever use `eject`. The curated feature set is suitable for small and middle deployments, and you shouldn’t feel obligated to use this feature. However we understand that this tool wouldn’t be useful if you couldn’t customize it when you are ready for it.

## Learn More

You can learn more in the [Create React App documentation](https://facebook.github.io/create-react-app/docs/getting-started).

To learn React, check out the [React documentation](https://reactjs.org/).
```

---

## How to analyze / Де шукати ключі для аналізу

- UA:
  1. Токен зберігається в `localStorage` під ключем `token`. Перевірити `localStorage` при тестуванні auth-flow.
  2. Перехоплювач запитів (`src/http/index.ts`) додає заголовок `Authorization: Barer <token>` — перевірити, що токен додається коректно.
  3. Рефреш здійснюється на ендпоїнт `${API_URL}/refresh`. Перевірити відповідь сервера: очікується `AuthResponse` з `accessToken` і `user`.
  4. `Store.checkAuth()` викликає axios GET без використання `$api` (щоб уникнути циклів інтерсепторів) — див. `src/store/store.ts`.
  5. Методи `login` і `registration` обробляють відповідь `AuthResponse` та зберігають токен у `localStorage`.

- EN:
  1. Token is stored in `localStorage` under `token`. Check `localStorage` when testing auth flow.
  2. Request interceptor (`src/http/index.ts`) adds `Authorization: Barer <token>` — verify token is attached correctly.
  3. Refresh hits `${API_URL}/refresh`. Verify server returns an `AuthResponse` containing `accessToken` and `user`.
  4. `Store.checkAuth()` calls axios GET directly (not `$api`) to avoid interceptor loops — see `src/store/store.ts`.
  5. `login` and `registration` process `AuthResponse` and store token in `localStorage`.

---

## Exclusions / Виключення

- UA: Не включено `node_modules`, вміст папки `public` та `.gitignore`.
- EN: Excluded `node_modules`, the `public` folder contents and `.gitignore`.

---

## Next steps / Наступні кроки

- UA: Перевірте документ та скажіть, чи потрібно додати номери рядків поруч із вставленими файлами або додаткові коментарі у коді.
- EN: Review the document and tell me if you want line numbers added to the embedded files or extra inline comments.
