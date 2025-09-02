import { Router } from 'express';
import { Roles } from './service.js';
import { requireAuth } from '../../middleware/auth.js';
import { authorize } from '../../middleware/rbac.js';

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