import { Router } from 'express';
import { Policies } from './service.js';
import { requireAuth } from '../../middleware/auth.js';
import { authorize } from '../../middleware/rbac.js';

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