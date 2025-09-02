import { PrismaClient } from '@prisma/client';
const prisma = new PrismaClient();
export const Roles = {
  list: (tenantId: string) => prisma.role.findMany({ where: { tenantId }, include: { grants: true } }),
  create: (tenantId: string, name: string, key: string, grants: {resource:string,action:string,effect:string}[]) =>
    prisma.role.create({ data: { tenantId, name, key, grants: { create: grants } } }),
  assign: (userId: string, roleId: string) => prisma.assignment.create({ data: { userId, roleId } })
};