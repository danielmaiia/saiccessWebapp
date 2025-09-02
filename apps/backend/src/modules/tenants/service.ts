import { PrismaClient } from '@prisma/client';
const prisma = new PrismaClient();
export const Tenants = {
  bySlug: (slug: string) => prisma.tenant.findUnique({ where: { slug } }),
  list: () => prisma.tenant.findMany(),
  create: (name: string, slug: string) => prisma.tenant.create({ data: { name, slug } })
};