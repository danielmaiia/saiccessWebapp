import { Router } from 'express';
import { Tenants } from './service.js';
import { authorize } from '../../middleware/rbac.js';
import { requireAuth } from '../../middleware/auth.js';

export const tenantsRouter = Router();

tenantsRouter.get('/', requireAuth, authorize('tenant', 'read'), async (_req, res) => res.json(await Tenants.list()));