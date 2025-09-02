import 'dotenv/config';
export const env = {
  PORT: parseInt(process.env.PORT || '3000', 10),
  JWT_SECRET: process.env.JWT_SECRET || 'dev-secret',
  JWT_EXPIRES: process.env.JWT_EXPIRES || '15m',
  REFRESH_EXPIRES: process.env.REFRESH_EXPIRES || '7d',
  DATABASE_URL: process.env.DATABASE_URL!,
  CORS_ORIGIN: process.env.CORS_ORIGIN || '*'
};