import { Router } from 'express';
import { Users } from './service.js';
import { requireAuth } from '../../middleware/auth.js';
import { authorize } from '../../middleware/rbac.js';

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