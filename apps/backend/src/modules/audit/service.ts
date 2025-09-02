import { PrismaClient } from '@prisma/client';
const prisma = new PrismaClient();
export const Audit = {
  log: (tenantId: string, actorId: string | null, action: string, target: string | null, payload: any, ip?: string) =>
    prisma.auditLog.create({ data: { tenantId, actorId: actorId || undefined, action, target: target || undefined, payload, ip } })
};