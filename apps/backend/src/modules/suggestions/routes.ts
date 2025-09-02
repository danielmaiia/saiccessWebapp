import { Router } from 'express';
import { requireAuth } from '../../middleware/auth.js';
import { authorize } from '../../middleware/rbac.js';
import { Suggestions } from './service.js';

export const suggestionsRouter = Router();

suggestionsRouter.get('/user/:userId', requireAuth, authorize('suggestion', 'read'), async (req, res, next) => {
  try { const tenantId = (req as any).user.tenantId; const { userId } = req.params; res.json(await Suggestions.forUser(tenantId, userId)); }
  catch (e) { next(e); }
});