import { Request, Response, NextFunction } from 'express';
import { PrismaClient } from '@prisma/client';
const prisma = new PrismaClient();

export function authorize(resource: string, action: string) {
  return async (req: Request, res: Response, next: NextFunction) => {
    const user = (req as any).user;
    const tenantSlug = (req as any).tenantSlug;
    if (!user) return res.status(401).json({ error: 'unauthenticated' });

    const tenant = await prisma.tenant.findUnique({ where: { slug: tenantSlug } });
    if (!tenant) return res.status(404).json({ error: 'tenant not found' });

    const roles = await prisma.assignment.findMany({
      where: { userId: user.sub }, include: { role: { include: { grants: true } } }
    });

    const allowed = roles.some(r => r.role.grants.some(g => g.resource === resource && g.action === action && g.effect === 'allow'));
    if (!allowed) return res.status(403).json({ error: 'forbidden' });
    next();
  };
}