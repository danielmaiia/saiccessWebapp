import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcrypt';
const prisma = new PrismaClient();

async function main() {
  const tenant = await prisma.tenant.upsert({
    where: { slug: 'acme' },
    update: {},
    create: { name: 'ACME Corp', slug: 'acme' }
  });

  const adminPass = await bcrypt.hash('Admin@123', 10);
  const admin = await prisma.user.upsert({
    where: { email: 'admin@acme.test' },
    update: {},
    create: { email: 'admin@acme.test', name: 'Admin', passwordHash: adminPass, tenantId: tenant.id }
  });

  const adminRole = await prisma.role.create({
    data: {
      tenantId: tenant.id, name: 'Administrator', key: 'ADMIN',
      grants: { create: [
        { resource: 'tenant', action: 'read', effect: 'allow' },
        { resource: 'user', action: 'read', effect: 'allow' },
        { resource: 'user', action: 'write', effect: 'allow' },
        { resource: 'role', action: 'read', effect: 'allow' },
        { resource: 'role', action: 'write', effect: 'allow' },
        { resource: 'policy', action: 'read', effect: 'allow' },
        { resource: 'policy', action: 'write', effect: 'allow' },
        { resource: 'review', action: 'read', effect: 'allow' },
        { resource: 'review', action: 'write', effect: 'allow' },
        { resource: 'suggestion', action: 'read', effect: 'allow' }
      ] }
    }
  });

  await prisma.assignment.create({ data: { userId: admin.id, roleId: adminRole.id } });

  await prisma.policy.create({ data: {
    tenantId: tenant.id,
    name: 'SoD Financeiro',
    type: 'SOD',
    rule: { conflicts: [[ 'FIN_APPR', 'FIN_PAY' ], [ 'HR_HIRE', 'HR_PAY' ]] }
  }});
}

main().finally(()=>process.exit());