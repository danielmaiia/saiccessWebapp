import { PrismaClient } from '@prisma/client';
const prisma = new PrismaClient();
export const Reviews = {
  create: (tenantId: string, name: string) => prisma.accessReview.create({ data: { tenantId, name, status: 'DRAFT' } }),
  launch: async (reviewId: string) => {
    const review = await prisma.accessReview.update({ where: { id: reviewId }, data: { status: 'RUNNING' } });
    return review;
  },
  list: (tenantId: string) => prisma.accessReview.findMany({ where: { tenantId }, include: { items: true } })
};