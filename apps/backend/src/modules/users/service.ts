import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcrypt';
const prisma = new PrismaClient();
export const Users = {
  list: (tenantId: string) => prisma.user.findMany({ where: { tenantId } }),
  create: async (tenantId: string, email: string, name: string, password: string) => {
    const passwordHash = await bcrypt.hash(password, 10);
    return prisma.user.create({ data: { tenantId, email, name, passwordHash } });
  }
};