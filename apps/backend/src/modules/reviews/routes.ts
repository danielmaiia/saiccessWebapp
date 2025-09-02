import { Router } from 'express';
import { requireAuth } from '../../middleware/auth.js';
import { authorize } from '../../middleware/rbac.js';
import { Reviews } from './service.js';

export const reviewsRouter = Router();

reviewsRouter.get('/', requireAuth, authorize('review', 'read'), async (req, res) => {
  const tenantId = (req as any).user.tenantId; res.json(await Reviews.list(tenantId));
});

reviewsRouter.post('/', requireAuth, authorize('review', 'write'), async (req, res, next) => {
  try { const tenantId = (req as any).user.tenantId; const { name } = req.body; res.json(await Reviews.create(tenantId, name)); }
  catch (e) { next(e); }
});