import { Request, Response, NextFunction } from 'express';

// Multitenancy por header (X-Tenant) ou subdomínio (ex: acme.saiccess.app)
export function tenantResolver(req: Request, res: Response, next: NextFunction) {
  const headerTenant = req.header('x-tenant');
  const host = req.hostname;
  const sub = host?.split('.')?.[0];
  (req as any).tenantSlug = headerTenant || sub || 'default';
  next();
}