import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { env } from '../env.js';

export function requireAuth(req: Request, res: Response, next: NextFunction) {
  const header = req.header('authorization');
  if (!header) return res.status(401).json({ error: 'missing token' });
  const token = header.replace('Bearer ', '');
  try {
    const payload = jwt.verify(token, env.JWT_SECRET) as any;
    (req as any).user = payload;
    return next();
  } catch {
    return res.status(401).json({ error: 'invalid token' });
  }
}