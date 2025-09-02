import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { rateLimit } from './middleware/rateLimit.js';
import { tenantResolver } from './middleware/tenant.js';
import { errorHandler } from './middleware/error.js';
import { authRouter } from './modules/auth/routes.js';
import { tenantsRouter } from './modules/tenants/routes.js';
import { usersRouter } from './modules/users/routes.js';
import { rolesRouter } from './modules/roles/routes.js';
import { policiesRouter } from './modules/policies/routes.js';
import { suggestionsRouter } from './modules/suggestions/routes.js';
import { reviewsRouter } from './modules/reviews/routes.js';

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