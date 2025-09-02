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