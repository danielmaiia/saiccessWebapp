
# SAIccess Webapp (MVP)

Este repositório foi gerado a partir do arquivo markdown fornecido.
Os arquivos foram materializados conforme as seções com blocos de código.

Pastas principais:
- apps/backend
- apps/frontend

Consulte o README original abaixo para arquitetura e instruções.
---

# SAIccess Webapp (MVP)

Arquitetura e implementação inicial (backend + frontend) alinhada ao projeto SAIccess: multi-tenant, RBAC, SoD, auditoria, orquestração de revisão de acesso e motor de sugestões (stub de IA) com conectores simulados para AD/Entra ID.

> Stack sugerida

- **Backend**: Node 20 + TypeScript, Express, Prisma (PostgreSQL), Zod, JWT, bcrypt, rate-limit, Winston, UUID, Helmet, CORS
- **Frontend**: React + Vite + TypeScript, Tailwind, shadcn/ui, Zustand, React Query, React Router, Lucide icons
- **Infra**: Postgres, Docker Compose, Migrations Prisma, Seeds
- **Segurança**: JWT + Refresh, RBAC no backend, SoD checks, MFA (hook para TOTP/WebAuthn), validação de entrada (Zod), rate limit por IP/tenant, logs imutáveis (WORM) via tabela append-only

---

## Monorepo

```
saiccess/
  apps/
    backend/
      src/
        index.ts
        env.ts
        server.ts
        logger.ts
        middleware/
          tenant.ts
          auth.ts
          rbac.ts
          error.ts
          rateLimit.ts
        modules/
          auth/
            routes.ts
            service.ts
            types.ts
          tenants/
            routes.ts
            service.ts
          users/
            routes.ts
            service.ts
          roles/
            routes.ts
            service.ts
          policies/
            routes.ts
            service.ts
          reviews/
            routes.ts
            service.ts
          connectors/
            ad.ts
            entra.ts
          suggestions/
            routes.ts
            service.ts
            model.ts
          audit/
            routes.ts
            service.ts
      prisma/
        schema.prisma
        seed.ts
      package.json
      tsconfig.json
      .env.example
      docker-compose.yml
    frontend/
      src/
        main.tsx
        App.tsx
        lib/api.ts
        lib/store.ts
        lib/auth.ts
        components/
          Shell.tsx
          Sidebar.tsx
          Topbar.tsx
          DataCard.tsx
        pages/
          Dashboard.tsx
          Tenants.tsx
          Users.tsx
          Roles.tsx
          Policies.tsx
          Reviews.tsx
          Suggestions.tsx
          Settings.tsx
          Login.tsx
      index.html
      package.json
      tsconfig.json
      tailwind.config.js
      postcss.config.js
      vite.config.ts
```

---

## Backend — package.json

```json
{
  "name": "saiccess-backend",
  "version": "0.1.0",
  "type": "module",
  "scripts": {
    "dev": "tsx src/index.ts",
    "build": "tsc -p .",
    "start": "node dist/index.js",
    "prisma:generate": "prisma generate",
    "prisma:migrate": "prisma migrate dev",
    "prisma:deploy": "prisma migrate deploy",
    "seed": "tsx prisma/seed.ts"
  },
  "dependencies": {
    "@prisma/client": "^5.16.1",
    "bcrypt": "^5.1.1",
    "cors": "^2.8.5",
    "dotenv": "^16.4.5",
    "express": "^4.19.2",
    "helmet": "^7.1.0",
    "jsonwebtoken": "^9.0.2",
    "rate-limiter-flexible": "^5.0.2",
    "uuid": "^9.0.1",
    "winston": "^3.13.0",
    "zod": "^3.23.8"
  },
  "devDependencies": {
    "@types/bcrypt": "^5.0.2",
    "@types/cors": "^2.8.17",
    "@types/express": "^4.17.21",
    "@types/jsonwebtoken": "^9.0.6",
    "@types/node": "^20.12.12",
    "prisma": "^5.16.1",
    "ts-node": "^10.9.2",
    "tslib": "^2.6.3",
    "tsx": "^4.16.2",
    "typescript": "^5.5.4"
  }
}
```

### prisma/schema.prisma

```prisma
generator client {
  provider = "prisma-client-js"
}

datasource db {
  provider = "postgresql"
  url      = env("DATABASE_URL")
}

model Tenant {
  id        String   @id @default(uuid())
  name      String
  slug      String   @unique
  createdAt DateTime @default(now())
  updatedAt DateTime @updatedAt
  users     User[]
  roles     Role[]
  policies  Policy[]
}

model User {
  id           String   @id @default(uuid())
  email        String   @unique
  name         String
  passwordHash String
  mfaEnabled   Boolean  @default(false)
  tenantId     String
  tenant       Tenant   @relation(fields: [tenantId], references: [id])
  assignments  Assignment[]
  createdAt    DateTime @default(now())
}

model Role {
  id        String   @id @default(uuid())
  name      String
  key       String
  tenantId  String
  tenant    Tenant   @relation(fields: [tenantId], references: [id])
  grants    Grant[]
  createdAt DateTime @default(now())
}

model Grant {
  id        String   @id @default(uuid())
  resource  String   // ex: "app:sap:invoice" ou "api:reports"
  action    String   // ex: "read", "write", "approve"
  effect    String   // "allow" | "deny"
  roleId    String
  role      Role     @relation(fields: [roleId], references: [id])
}

model Assignment {
  id        String   @id @default(uuid())
  userId    String
  user      User     @relation(fields: [userId], references: [id])
  roleId    String
  role      Role     @relation(fields: [roleId], references: [id])
  createdAt DateTime @default(now())
}

model Policy { // SoD e regras de conflito
  id        String   @id @default(uuid())
  tenantId  String
  tenant    Tenant   @relation(fields: [tenantId], references: [id])
  name      String
  type      String   // "SOD" | "CONSTRAINT"
  rule      Json     // ex: {"conflicts":[["FIN_APPR","FIN_PAY"]]}
  enabled   Boolean  @default(true)
}

model AccessReview { // campanha de revisão de acessos
  id        String   @id @default(uuid())
  tenantId  String
  name      String
  status    String   // "DRAFT" | "RUNNING" | "CLOSED"
  createdAt DateTime @default(now())
  items     ReviewItem[]
}

model ReviewItem {
  id           String   @id @default(uuid())
  reviewId     String
  review       AccessReview @relation(fields: [reviewId], references: [id])
  userId       String
  user         User     @relation(fields: [userId], references: [id])
  roleId       String
  role         Role     @relation(fields: [roleId], references: [id])
  decision     String?  // "KEEP" | "REVOKE"
  decidedBy    String?
  decidedAt    DateTime?
}

model AuditLog { // WORM: sem update/delete via app
  id        String   @id @default(uuid())
  ts        DateTime @default(now())
  tenantId  String
  actorId   String?
  action    String
  target    String?
  payload   Json
  ip        String?
}
```

### src/env.ts

```ts
import 'dotenv/config';
export const env = {
  PORT: parseInt(process.env.PORT || '3000', 10),
  JWT_SECRET: process.env.JWT_SECRET || 'dev-secret',
  JWT_EXPIRES: process.env.JWT_EXPIRES || '15m',
  REFRESH_EXPIRES: process.env.REFRESH_EXPIRES || '7d',
  DATABASE_URL: process.env.DATABASE_URL!,
  CORS_ORIGIN: process.env.CORS_ORIGIN || '*'
};
```

### src/logger.ts

```ts
import winston from 'winston';
export const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  transports: [new winston.transports.Console({ format: winston.format.simple() })]
});
```

### src/middleware/tenant.ts

```ts
import { Request, Response, NextFunction } from 'express';

// Multitenancy por header (X-Tenant) ou subdomínio (ex: acme.saiccess.app)
export function tenantResolver(req: Request, res: Response, next: NextFunction) {
  const headerTenant = req.header('x-tenant');
  const host = req.hostname;
  const sub = host?.split('.')?.[0];
  (req as any).tenantSlug = headerTenant || sub || 'default';
  next();
}
```

### src/middleware/auth.ts

```ts
import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { env } from '../env';

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
```

### src/middleware/rbac.ts

```ts
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
```

### src/middleware/error.ts

```ts
import { Request, Response, NextFunction } from 'express';
export function errorHandler(err: any, _req: Request, res: Response, _next: NextFunction) {
  console.error(err);
  res.status(err.status || 500).json({ error: err.message || 'internal error' });
}
```

### src/middleware/rateLimit.ts

```ts
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
```

### src/modules/auth/types.ts

```ts
import { z } from 'zod';
export const LoginSchema = z.object({ email: z.string().email(), password: z.string().min(6) });
export type LoginInput = z.infer<typeof LoginSchema>;
```

### src/modules/auth/service.ts

```ts
import { PrismaClient } from '@prisma/client';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import { env } from '../../env';
const prisma = new PrismaClient();

export async function login(email: string, password: string) {
  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) throw new Error('invalid credentials');
  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) throw new Error('invalid credentials');
  const access = jwt.sign({ sub: user.id, tenantId: user.tenantId }, env.JWT_SECRET, { expiresIn: env.JWT_EXPIRES });
  const refresh = jwt.sign({ sub: user.id, type: 'refresh' }, env.JWT_SECRET, { expiresIn: env.REFRESH_EXPIRES });
  return { access, refresh, user: { id: user.id, email: user.email, name: user.name } };
}
```

### src/modules/auth/routes.ts

```ts
import { Router } from 'express';
import { LoginSchema } from './types';
import { login } from './service';

export const authRouter = Router();

authRouter.post('/login', async (req, res, next) => {
  try { const body = LoginSchema.parse(req.body); res.json(await login(body.email, body.password)); }
  catch (e) { next(e); }
});
```

### src/modules/tenants/service.ts

```ts
import { PrismaClient } from '@prisma/client';
const prisma = new PrismaClient();
export const Tenants = {
  bySlug: (slug: string) => prisma.tenant.findUnique({ where: { slug } }),
  list: () => prisma.tenant.findMany(),
  create: (name: string, slug: string) => prisma.tenant.create({ data: { name, slug } })
};
```

### src/modules/tenants/routes.ts

```ts
import { Router } from 'express';
import { Tenants } from './service';
import { authorize } from '../../middleware/rbac';
import { requireAuth } from '../../middleware/auth';

export const tenantsRouter = Router();

tenantsRouter.get('/', requireAuth, authorize('tenant', 'read'), async (_req, res) => res.json(await Tenants.list()));
```

### src/modules/users/service.ts

```ts
import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcrypt';
const prisma = new PrismaClient();
export const Users = {
  list: (tenantId: string) => prisma.user.findMany({ where: { tenantId } }),
  create: async (tenantId: string, email: string, name: string, password: string) => {
    const passwordHash = await bcrypt.hash(password, 10);
    return prisma.user.create({ data: { tenantId, email, name, passwordHash } });
  }
};
```

### src/modules/users/routes.ts

```ts
import { Router } from 'express';
import { Users } from './service';
import { requireAuth } from '../../middleware/auth';
import { authorize } from '../../middleware/rbac';

export const usersRouter = Router();

usersRouter.get('/', requireAuth, authorize('user', 'read'), async (req, res) => {
  const tenantId = (req as any).user.tenantId;
  res.json(await Users.list(tenantId));
});

usersRouter.post('/', requireAuth, authorize('user', 'write'), async (req, res, next) => {
  try {
    const { email, name, password } = req.body;
    const tenantId = (req as any).user.tenantId;
    res.json(await Users.create(tenantId, email, name, password));
  } catch (e) { next(e); }
});
```

### src/modules/roles/service.ts

```ts
import { PrismaClient } from '@prisma/client';
const prisma = new PrismaClient();
export const Roles = {
  list: (tenantId: string) => prisma.role.findMany({ where: { tenantId }, include: { grants: true } }),
  create: (tenantId: string, name: string, key: string, grants: {resource:string,action:string,effect:string}[]) =>
    prisma.role.create({ data: { tenantId, name, key, grants: { create: grants } } }),
  assign: (userId: string, roleId: string) => prisma.assignment.create({ data: { userId, roleId } })
};
```

### src/modules/roles/routes.ts

```ts
import { Router } from 'express';
import { Roles } from './service';
import { requireAuth } from '../../middleware/auth';
import { authorize } from '../../middleware/rbac';

export const rolesRouter = Router();

rolesRouter.get('/', requireAuth, authorize('role', 'read'), async (req, res) => {
  const tenantId = (req as any).user.tenantId; res.json(await Roles.list(tenantId));
});

rolesRouter.post('/', requireAuth, authorize('role', 'write'), async (req, res, next) => {
  try {
    const tenantId = (req as any).user.tenantId;
    const { name, key, grants } = req.body; res.json(await Roles.create(tenantId, name, key, grants));
  } catch (e) { next(e); }
});

rolesRouter.post('/assign', requireAuth, authorize('role', 'write'), async (req, res, next) => {
  try { const { userId, roleId } = req.body; res.json(await Roles.assign(userId, roleId)); }
  catch (e) { next(e); }
});
```

### src/modules/policies/service.ts (SoD)

```ts
import { PrismaClient } from '@prisma/client';
const prisma = new PrismaClient();
export const Policies = {
  list: (tenantId: string) => prisma.policy.findMany({ where: { tenantId } }),
  createSod: (tenantId: string, name: string, conflicts: string[][]) =>
    prisma.policy.create({ data: { tenantId, name, type: 'SOD', rule: { conflicts } } }),
  // verificação SoD para um user com roles propostas
  checkSod: async (tenantId: string, roleKeys: string[]) => {
    const sod = await prisma.policy.findMany({ where: { tenantId, type: 'SOD', enabled: true } });
    const conflicts = sod.flatMap(p => (p.rule as any).conflicts as string[][]);
    const violations = conflicts.filter(([a,b]) => roleKeys.includes(a) && roleKeys.includes(b));
    return { ok: violations.length === 0, violations };
  }
};
```

### src/modules/policies/routes.ts

```ts
import { Router } from 'express';
import { Policies } from './service';
import { requireAuth } from '../../middleware/auth';
import { authorize } from '../../middleware/rbac';

export const policiesRouter = Router();

policiesRouter.get('/', requireAuth, authorize('policy', 'read'), async (req, res) => {
  const tenantId = (req as any).user.tenantId; res.json(await Policies.list(tenantId));
});

policiesRouter.post('/sod', requireAuth, authorize('policy', 'write'), async (req, res, next) => {
  try { const tenantId = (req as any).user.tenantId; const { name, conflicts } = req.body; res.json(await Policies.createSod(tenantId, name, conflicts)); }
  catch (e) { next(e); }
});

policiesRouter.post('/sod/check', requireAuth, authorize('policy', 'read'), async (req, res, next) => {
  try { const tenantId = (req as any).user.tenantId; const { roleKeys } = req.body; res.json(await Policies.checkSod(tenantId, roleKeys)); }
  catch (e) { next(e); }
});
```

### src/modules/suggestions/model.ts (stub IA)

```ts
// Modelo simplificado baseado em frequência de uso e similaridade de perfis
export function suggestRoles(inputs: { userFeatures: string[]; knownBundles: Record<string,string[]>; topN?: number }) {
  const { userFeatures, knownBundles, topN = 5 } = inputs;
  const scored = Object.entries(knownBundles).map(([roleKey, feats]) => {
    const intersect = feats.filter(f => userFeatures.includes(f)).length;
    const score = intersect / Math.max(feats.length, 1);
    return { roleKey, score };
  }).sort((a,b)=>b.score - a.score);
  return scored.filter(s => s.score > 0).slice(0, topN);
}
```

### src/modules/suggestions/service.ts

```ts
import { PrismaClient } from '@prisma/client';
import { suggestRoles } from './model';
const prisma = new PrismaClient();

export const Suggestions = {
  forUser: async (tenantId: string, userId: string) => {
    // features simuladas: apps usados nos últimos 30 dias (futuro: logs reais)
    const used = ['app:erp:read','app:erp:invoice','app:drive:read'];
    const roles = await prisma.role.findMany({ where: { tenantId }, include: { grants: true } });
    const bundles = Object.fromEntries(roles.map(r => [r.key, r.grants.map(g => `${g.resource}:${g.action}`)]));
    const ranked = suggestRoles({ userFeatures: used, knownBundles: bundles });
    return ranked;
  }
};
```

### src/modules/suggestions/routes.ts

```ts
import { Router } from 'express';
import { requireAuth } from '../../middleware/auth';
import { authorize } from '../../middleware/rbac';
import { Suggestions } from './service';

export const suggestionsRouter = Router();

suggestionsRouter.get('/user/:userId', requireAuth, authorize('suggestion', 'read'), async (req, res, next) => {
  try { const tenantId = (req as any).user.tenantId; const { userId } = req.params; res.json(await Suggestions.forUser(tenantId, userId)); }
  catch (e) { next(e); }
});
```

### src/modules/reviews/service.ts (campanhas de revisão)

```ts
import { PrismaClient } from '@prisma/client';
const prisma = new PrismaClient();
export const Reviews = {
  create: (tenantId: string, name: string) => prisma.accessReview.create({ data: { tenantId, name, status: 'DRAFT' } }),
  launch: async (reviewId: string) => {
    const review = await prisma.accessReview.update({ where: { id: reviewId }, data: { status: 'RUNNING' } });
    return review;
  },
  list: (tenantId: string) => prisma.accessReview.findMany({ where: { tenantId }, include: { items: true } })
};
```

### src/modules/reviews/routes.ts

```ts
import { Router } from 'express';
import { requireAuth } from '../../middleware/auth';
import { authorize } from '../../middleware/rbac';
import { Reviews } from './service';

export const reviewsRouter = Router();

reviewsRouter.get('/', requireAuth, authorize('review', 'read'), async (req, res) => {
  const tenantId = (req as any).user.tenantId; res.json(await Reviews.list(tenantId));
});

reviewsRouter.post('/', requireAuth, authorize('review', 'write'), async (req, res, next) => {
  try { const tenantId = (req as any).user.tenantId; const { name } = req.body; res.json(await Reviews.create(tenantId, name)); }
  catch (e) { next(e); }
});
```

### src/modules/audit/service.ts

```ts
import { PrismaClient } from '@prisma/client';
const prisma = new PrismaClient();
export const Audit = {
  log: (tenantId: string, actorId: string | null, action: string, target: string | null, payload: any, ip?: string) =>
    prisma.auditLog.create({ data: { tenantId, actorId: actorId || undefined, action, target: target || undefined, payload, ip } })
};
```

### src/server.ts

```ts
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { rateLimit } from './middleware/rateLimit';
import { tenantResolver } from './middleware/tenant';
import { errorHandler } from './middleware/error';
import { authRouter } from './modules/auth/routes';
import { tenantsRouter } from './modules/tenants/routes';
import { usersRouter } from './modules/users/routes';
import { rolesRouter } from './modules/roles/routes';
import { policiesRouter } from './modules/policies/routes';
import { suggestionsRouter } from './modules/suggestions/routes';
import { reviewsRouter } from './modules/reviews/routes';

export function buildServer() {
  const app = express();
  app.use(express.json());
  app.use(cors());
  app.use(helmet());
  app.use(rateLimit);
  app.use(tenantResolver);

  app.get('/health', (_req, res) => res.json({ ok: true }));
  app.use('/auth', authRouter);
  app.use('/tenants', tenantsRouter);
  app.use('/users', usersRouter);
  app.use('/roles', rolesRouter);
  app.use('/policies', policiesRouter);
  app.use('/suggestions', suggestionsRouter);
  app.use('/reviews', reviewsRouter);

  app.use(errorHandler);
  return app;
}
```

### src/index.ts

```ts
import { buildServer } from './server';
import { env } from './env';
const app = buildServer();
app.listen(env.PORT, () => console.log(`SAIccess API running on :${env.PORT}`));
```

### docker-compose.yml

```yml
version: '3.8'
services:
  db:
    image: postgres:16
    environment:
      POSTGRES_USER: saiccess
      POSTGRES_PASSWORD: saiccess
      POSTGRES_DB: saiccess
    ports: ["5432:5432"]
    volumes:
      - dbdata:/var/lib/postgresql/data
volumes:
  dbdata: {}
```

### .env.example

```
DATABASE_URL=postgresql://saiccess:saiccess@localhost:5432/saiccess
JWT_SECRET=please-change
CORS_ORIGIN=http://localhost:5173
```

### prisma/seed.ts (amostra)

```ts
import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcrypt';
const prisma = new PrismaClient();

async function main() {
  const tenant = await prisma.tenant.upsert({
    where: { slug: 'acme' },
    update: {},
    create: { name: 'ACME Corp', slug: 'acme' }
  });

  const adminPass = await bcrypt.hash('Admin@123', 10);
  const admin = await prisma.user.upsert({
    where: { email: 'admin@acme.test' },
    update: {},
    create: { email: 'admin@acme.test', name: 'Admin', passwordHash: adminPass, tenantId: tenant.id }
  });

  const adminRole = await prisma.role.create({
    data: {
      tenantId: tenant.id, name: 'Administrator', key: 'ADMIN',
      grants: { create: [
        { resource: 'tenant', action: 'read', effect: 'allow' },
        { resource: 'user', action: 'read', effect: 'allow' },
        { resource: 'user', action: 'write', effect: 'allow' },
        { resource: 'role', action: 'read', effect: 'allow' },
        { resource: 'role', action: 'write', effect: 'allow' },
        { resource: 'policy', action: 'read', effect: 'allow' },
        { resource: 'policy', action: 'write', effect: 'allow' },
        { resource: 'review', action: 'read', effect: 'allow' },
        { resource: 'review', action: 'write', effect: 'allow' },
        { resource: 'suggestion', action: 'read', effect: 'allow' }
      ] }
    }
  });

  await prisma.assignment.create({ data: { userId: admin.id, roleId: adminRole.id } });

  await prisma.policy.create({ data: {
    tenantId: tenant.id,
    name: 'SoD Financeiro',
    type: 'SOD',
    rule: { conflicts: [[ 'FIN_APPR', 'FIN_PAY' ], [ 'HR_HIRE', 'HR_PAY' ]] }
  }});
}

main().finally(()=>process.exit());
```

---

## Frontend — package.json

```json
{
  "name": "saiccess-frontend",
  "version": "0.1.0",
  "private": true,
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "vite build",
    "preview": "vite preview"
  },
  "dependencies": {
    "@radix-ui/react-scroll-area": "^1.0.5",
    "@tanstack/react-query": "^5.50.0",
    "lucide-react": "^0.441.0",
    "react": "^18.3.1",
    "react-dom": "^18.3.1",
    "react-hook-form": "^7.51.5",
    "react-router-dom": "^6.26.1",
    "zustand": "^4.5.2"
  },
  "devDependencies": {
    "@types/react": "^18.3.3",
    "@types/react-dom": "^18.3.0",
    "autoprefixer": "^10.4.19",
    "postcss": "^8.4.39",
    "tailwindcss": "^3.4.7",
    "typescript": "^5.5.4",
    "vite": "^5.3.3"
  }
}
```

### tailwind.config.js

```js
/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html','./src/**/*.{ts,tsx}'],
  theme: { extend: {} },
  plugins: []
};
```

### src/lib/api.ts

```ts
export const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:3000';

export async function api(path: string, opts: RequestInit = {}) {
  const token = localStorage.getItem('token');
  const headers = new Headers(opts.headers);
  headers.set('Content-Type','application/json');
  if (token) headers.set('Authorization', `Bearer ${token}`);
  headers.set('X-Tenant', localStorage.getItem('tenant') || 'acme');
  const res = await fetch(`${API_URL}${path}`, { ...opts, headers });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}
```

### src/lib/store.ts (auth + UI state)

```ts
import { create } from 'zustand';

type AuthState = {
  user: { id:string; email:string; name:string } | null;
  token: string | null;
  setSession: (u:any, t:string)=>void;
  clear: ()=>void;
};

export const useAuth = create<AuthState>((set)=>({
  user: null, token: null,
  setSession: (user, token)=>{ localStorage.setItem('token', token); set({ user, token }); },
  clear: ()=>{ localStorage.removeItem('token'); set({ user: null, token: null }); }
}));
```

### src/main.tsx

```tsx
import React from 'react';
import ReactDOM from 'react-dom/client';
import { createBrowserRouter, RouterProvider } from 'react-router-dom';
import './index.css';
import App from './App';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import Tenants from './pages/Tenants';
import Users from './pages/Users';
import Roles from './pages/Roles';
import Policies from './pages/Policies';
import Reviews from './pages/Reviews';
import Suggestions from './pages/Suggestions';
import Settings from './pages/Settings';

const router = createBrowserRouter([
  { path: '/login', element: <Login /> },
  { path: '/', element: <App />,
    children: [
      { index: true, element: <Dashboard /> },
      { path: 'tenants', element: <Tenants /> },
      { path: 'users', element: <Users /> },
      { path: 'roles', element: <Roles /> },
      { path: 'policies', element: <Policies /> },
      { path: 'reviews', element: <Reviews /> },
      { path: 'suggestions', element: <Suggestions /> },
      { path: 'settings', element: <Settings /> }
    ] }
]);

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <RouterProvider router={router} />
  </React.StrictMode>
);
```

### src/App.tsx

```tsx
import { Outlet, useNavigate } from 'react-router-dom';
import Shell from './components/Shell';
import { useEffect } from 'react';
import { useAuth } from './lib/store';

export default function App() {
  const nav = useNavigate();
  const { token } = useAuth();
  useEffect(()=>{ if(!localStorage.getItem('token')) nav('/login'); },[token]);
  return <Shell><Outlet/></Shell>;
}
```

### src/components/Shell.tsx

```tsx
import Sidebar from './Sidebar';
import Topbar from './Topbar';

export default function Shell({ children }: { children: React.ReactNode }){
  return (
    <div className="min-h-screen bg-gray-50 text-gray-900">
      <Topbar />
      <div className="flex">
        <Sidebar />
        <main className="flex-1 p-6">{children}</main>
      </div>
    </div>
  );
}
```

### src/components/Sidebar.tsx

```tsx
import { Link, useLocation } from 'react-router-dom';
import { Shield, Users, KeyRound, GitBranch, ClipboardList, Wand2, Settings } from 'lucide-react';

const items = [
  { to:'/', label:'Dashboard', icon: Shield },
  { to:'/users', label:'Usuários', icon: Users },
  { to:'/roles', label:'Papéis (RBAC)', icon: KeyRound },
  { to:'/policies', label:'Políticas (SoD)', icon: GitBranch },
  { to:'/reviews', label:'Revisões de Acesso', icon: ClipboardList },
  { to:'/suggestions', label:'Sugestões (IA)', icon: Wand2 },
  { to:'/settings', label:'Configurações', icon: Settings }
];

export default function Sidebar(){
  const loc = useLocation();
  return (
    <aside className="w-64 border-r bg-white h-[calc(100vh-56px)] sticky top-14">
      <nav className="p-3 space-y-1">
        {items.map(({to,label,icon:Icon})=> (
          <Link key={to} to={to} className={`flex items-center gap-2 px-3 py-2 rounded-lg hover:bg-gray-100 ${loc.pathname===to? 'bg-gray-100 font-medium':''}`}>
            <Icon size={18}/> {label}
          </Link>
        ))}
      </nav>
    </aside>
  );
}
```

### src/components/Topbar.tsx

```tsx
export default function Topbar(){
  return (
    <header className="h-14 border-b bg-white flex items-center px-4 justify-between sticky top-0 z-10">
      <div className="font-semibold">SAIccess</div>
      <div className="text-sm text-gray-500">Multi-tenant • Zero Trust • RBAC</div>
    </header>
  );
}
```

### src/pages/Login.tsx

```tsx
import { useState } from 'react';
import { api } from '../lib/api';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../lib/store';

export default function Login(){
  const [email,setEmail] = useState('admin@acme.test');
  const [password,setPassword] = useState('Admin@123');
  const [err,setErr] = useState<string|null>(null);
  const nav = useNavigate();
  const { setSession } = useAuth();

  async function submit(e: React.FormEvent){
    e.preventDefault();
    try{
      const res = await api('/auth/login',{ method:'POST', body: JSON.stringify({ email, password }) });
      setSession(res.user, res.access);
      localStorage.setItem('tenant','acme');
      nav('/');
    }catch(ex:any){ setErr(ex.message||'erro'); }
  }

  return (
    <div className="min-h-screen grid place-items-center bg-gray-50">
      <form onSubmit={submit} className="bg-white border rounded-2xl shadow p-6 w-96 space-y-4">
        <h1 className="text-xl font-semibold">Entrar</h1>
        {err && <div className="text-red-600 text-sm">{err}</div>}
        <input className="w-full border rounded px-3 py-2" value={email} onChange={e=>setEmail(e.target.value)} placeholder="email"/>
        <input type="password" className="w-full border rounded px-3 py-2" value={password} onChange={e=>setPassword(e.target.value)} placeholder="senha"/>
        <button className="w-full bg-black text-white rounded px-3 py-2">Acessar</button>
      </form>
    </div>
  );
}
```

### Exemplos de páginas (resumidas)

#### src/pages/Dashboard.tsx

```tsx
export default function Dashboard(){
  return (
    <div className="grid md:grid-cols-3 gap-4">
      <Card title="Usuários Ativos" value="42"/>
      <Card title="Papéis" value="12"/>
      <Card title="Alertas SoD" value="3"/>
    </div>
  );
}

function Card({title,value}:{title:string;value:string}){
  return (
    <div className="bg-white border rounded-2xl p-4 shadow-sm">
      <div className="text-sm text-gray-500">{title}</div>
      <div className="text-3xl font-semibold">{value}</div>
    </div>
  );
}
```

#### src/pages/Users.tsx

```tsx
import { useEffect, useState } from 'react';
import { api } from '../lib/api';

export default function Users(){
  const [users,setUsers] = useState<any[]>([]);
  useEffect(()=>{ api('/users').then(setUsers).catch(console.error); },[]);
  return (
    <div>
      <h2 className="text-lg font-semibold mb-3">Usuários</h2>
      <table className="w-full bg-white border rounded-2xl overflow-hidden">
        <thead className="bg-gray-50">
          <tr><th className="text-left p-2">Nome</th><th className="text-left p-2">Email</th></tr>
        </thead>
        <tbody>
          {users.map(u=> (
            <tr key={u.id} className="border-t">
              <td className="p-2">{u.name}</td><td className="p-2">{u.email}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
```

#### src/pages/Roles.tsx

```tsx
import { useEffect, useState } from 'react';
import { api } from '../lib/api';

export default function Roles(){
  const [roles,setRoles] = useState<any[]>([]);
  useEffect(()=>{ api('/roles').then(setRoles); },[]);
  return (
    <div>
      <h2 className="text-lg font-semibold mb-3">Papéis (RBAC)</h2>
      <div className="grid md:grid-cols-2 gap-3">
        {roles.map(r=> (
          <div key={r.id} className="bg-white border rounded-2xl p-4">
            <div className="font-medium">{r.name}</div>
            <div className="text-xs text-gray-500">{r.key}</div>
            <ul className="mt-2 text-sm list-disc list-inside">
              {r.grants.map((g:any)=> <li key={g.id}>{g.effect}:{g.action}@{g.resource}</li>)}
            </ul>
          </div>
        ))}
      </div>
    </div>
  );
}
```

#### src/pages/Policies.tsx

```tsx
import { useEffect, useState } from 'react';
import { api } from '../lib/api';

export default function Policies(){
  const [policies,setPolicies] = useState<any[]>([]);
  useEffect(()=>{ api('/policies').then(setPolicies); },[]);
  return (
    <div>
      <h2 className="text-lg font-semibold mb-3">Políticas (SoD)</h2>
      <ul className="space-y-2">
        {policies.map(p=> (
          <li key={p.id} className="bg-white border rounded-2xl p-3">
            <div className="font-medium">{p.name}</div>
            <pre className="text-xs text-gray-500 mt-1">{JSON.stringify(p.rule,null,2)}</pre>
          </li>
        ))}
      </ul>
    </div>
  );
}
```

#### src/pages/Suggestions.tsx

```tsx
import { useEffect, useState } from 'react';
import { api } from '../lib/api';

export default function Suggestions(){
  const [items,setItems] = useState<any[]>([]);
  // Exemplo: consulta de sugestões para o admin seedado
  useEffect(()=>{ api('/suggestions/user/seed').then(setItems).catch(()=>setItems([])); },[]);
  return (
    <div>
      <h2 className="text-lg font-semibold mb-3">Sugestões (IA)</h2>
      {items.length===0? <div className="text-sm text-gray-500">Sem dados suficientes.</div> : (
        <ul className="space-y-2">
          {items.map(i=> (
            <li key={i.roleKey} className="bg-white border rounded-2xl p-3 flex items-center justify-between">
              <div>{i.roleKey}</div>
              <div className="text-xs text-gray-500">score {(i.score*100).toFixed(0)}%</div>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
```

---

## Como rodar (dev)

1. **Banco**: `docker compose up -d` na pasta `apps/backend`.
2. **Prisma**: `pnpm i` (ou `npm i`) no backend, depois `pnpm prisma:generate && pnpm prisma:migrate && pnpm seed`.
3. **API**: `pnpm dev` (porta 3000). Ajuste `.env` se necessário.
4. **Frontend**: na pasta `apps/frontend`, `pnpm i && pnpm dev` (porta 5173). Configure `VITE_API_URL` se for diferente.

Login de teste: `admin@acme.test` / `Admin@123` • Tenant: `acme`.

---

## Próximos passos sugeridos

- Conector real para **AD/Entra ID** via SCIM/Graph: ingest de grupos/atributos → normalização.
- **MFA/WebAuthn** (passkeys) para admins, fluxo de recuperação seguro.
- **Journey de aprovação** para solicitações e revogações (workflow com etapas, SLA, delegação).
- **Motor de SoD avançado** (catálogo de funções, conflitos, exceções temporárias com expiração).
- **Camada de observabilidade** (OpenTelemetry) + correlação de auditoria.
- **Hardening**: CSP estrita, secure cookies para refresh, rotação de chaves, backup imutável.
- **Testes**: e2e (Playwright), API (Vitest), lint/CI.

Este MVP cobre o básico de autenticação, multitenancy, RBAC, SoD, revisão de acesso e sugestões iniciais — pronto para evoluir em cima dos conectores e fluxos de governança que definimos no projeto.

