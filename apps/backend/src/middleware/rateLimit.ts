import { RateLimiterMemory } from 'rate-limiter-flexible';
import { Request, Response, NextFunction } from 'express';
const limiter = new RateLimiterMemory({ points: 200, duration: 60 });
export async function rateLimit(req: Request, res: Response, next: NextFunction) {
  try {
    await limiter.consume(`${req.ip}:${req.path}`);
    next();
  } catch {
    res.status(429).json({ error: 'too many requests' });
  }
}