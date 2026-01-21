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
