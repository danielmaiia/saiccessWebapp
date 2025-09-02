
# Frontend (Vite + React)
FROM node:20-alpine AS build
WORKDIR /app

COPY package.json package-lock.json* pnpm-lock.yaml* yarn.lock* ./
RUN if [ -f pnpm-lock.yaml ]; then npm i -g pnpm && pnpm i --frozen-lockfile;     elif [ -f yarn.lock ]; then yarn --frozen-lockfile;     elif [ -f package-lock.json ]; then npm ci;     else npm i; fi

COPY . .
RUN npm run build

# Serve with Vite preview (simple) or use nginx in a separate stage if desired
EXPOSE 5173
CMD ["npm","run","preview","--","--host","0.0.0.0","--port","5173"]
