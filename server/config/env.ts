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

const isProd = process.env.NODE_ENV === 'production';

const env = cleanEnv(process.env, {
  PORT: num({ default: 5001 }),
  // In production DATABASE_URL must be present; in development allow empty string to avoid
  // failing startup when running without a DB (local frontend/dev flows).
  DATABASE_URL: isProd ? str() : str({ default: '' }),
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
