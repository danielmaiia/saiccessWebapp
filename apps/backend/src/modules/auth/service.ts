import { PrismaClient } from '@prisma/client';
import jwt, { type Secret, type SignOptions } from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import { env } from '../../env.js';
const prisma = new PrismaClient();

export async function login(email: string, password: string) {
  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) throw new Error('invalid credentials');
  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) throw new Error('invalid credentials');
  const secret: Secret = env.JWT_SECRET as Secret;
  const access = jwt.sign({ sub: user.id, tenantId: user.tenantId }, secret, { expiresIn: env.JWT_EXPIRES } as SignOptions);
  const refresh = jwt.sign({ sub: user.id, type: 'refresh' }, secret, { expiresIn: env.REFRESH_EXPIRES } as SignOptions);
  return { access, refresh, user: { id: user.id, email: user.email, name: user.name } };
}