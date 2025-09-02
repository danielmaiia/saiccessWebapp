import { PrismaClient } from '@prisma/client';
import { suggestRoles } from './model.js';
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