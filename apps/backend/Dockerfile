
# Backend (Node + Prisma)
FROM node:20-bookworm-slim AS build
WORKDIR /app

# Install deps
COPY package.json package-lock.json* pnpm-lock.yaml* yarn.lock* ./
RUN if [ -f pnpm-lock.yaml ]; then npm i -g pnpm && pnpm i --frozen-lockfile;     elif [ -f yarn.lock ]; then yarn --frozen-lockfile;     elif [ -f package-lock.json ]; then npm ci;     else npm i; fi

# Copy source
COPY prisma ./prisma
COPY tsconfig.json ./tsconfig.json
COPY src ./src

# Generate Prisma client and build
RUN npx prisma generate
RUN npm run build

# --- Runtime ---
FROM node:20-bookworm-slim
WORKDIR /app
ENV NODE_ENV=production
RUN apt-get update -y \
 && apt-get install -y --no-install-recommends openssl \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/prisma ./prisma
COPY --from=build /app/dist ./dist

EXPOSE 3000
# Run migrations on start, then launch API
CMD sh -c "npx prisma migrate deploy && node dist/index.js"
