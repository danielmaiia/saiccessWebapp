import { Router } from 'express';
import { LoginSchema } from './types.js';
import { login } from './service.js';

export const authRouter = Router();

authRouter.post('/login', async (req, res, next) => {
  try { const body = LoginSchema.parse(req.body); res.json(await login(body.email, body.password)); }
  catch (e) { next(e); }
});