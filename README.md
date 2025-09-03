
# SAIccess Webapp (MVP)

Este repositório foi gerado a partir do arquivo markdown fornecido.
Os arquivos foram materializados conforme as seções com blocos de código.

Pastas principais:
- apps/backend
- apps/frontend

Consulte o README original abaixo para arquitetura e instruções.
---

# SAIccess Webapp (MVP)

Arquitetura e implementação inicial (backend + frontend) alinhada ao projeto SAIccess: multi-tenant, RBAC, SoD, auditoria, orquestração de revisão de acesso e motor de sugestões (stub de IA) com conectores simulados para AD/Entra ID.

> Stack sugerida

- **Backend**: Node 20 + TypeScript, Express, Prisma (PostgreSQL), Zod, JWT, bcrypt, rate-limit, Winston, UUID, Helmet, CORS
- **Frontend**: React + Vite + TypeScript, Tailwind, shadcn/ui, Zustand, React Query, React Router, Lucide icons
- **Infra**: Postgres, Docker Compose, Migrations Prisma, Seeds
- **Segurança**: JWT + Refresh, RBAC no backend, SoD checks, MFA (hook para TOTP/WebAuthn), validação de entrada (Zod), rate limit por IP/tenant, logs imutáveis (WORM) via tabela append-only

---

## Como rodar (dev)

1. **Banco**: `docker compose up -d` na pasta `apps/backend`.
2. **Prisma**: `pnpm i` (ou `npm i`) no backend, depois `pnpm prisma:generate && pnpm prisma:migrate && pnpm seed`.
3. **API**: `pnpm dev` (porta 3000). Ajuste `.env` se necessário.
4. **Frontend**: na pasta `apps/frontend`, `pnpm i && pnpm dev` (porta 5173). Configure `VITE_API_URL` se for diferente.

Login de teste: `admin@acme.test` / `Admin@123` • Tenant: `acme`.

---

## Próximos passos sugeridos

- Conector real para **AD/Entra ID** via SCIM/Graph: ingest de grupos/atributos → normalização.
- **MFA/WebAuthn** (passkeys) para admins, fluxo de recuperação seguro.
- **Journey de aprovação** para solicitações e revogações (workflow com etapas, SLA, delegação).
- **Motor de SoD avançado** (catálogo de funções, conflitos, exceções temporárias com expiração).
- **Camada de observabilidade** (OpenTelemetry) + correlação de auditoria.
- **Hardening**: CSP estrita, secure cookies para refresh, rotação de chaves, backup imutável.
- **Testes**: e2e (Playwright), API (Vitest), lint/CI.

Este MVP cobre o básico de autenticação, multitenancy, RBAC, SoD, revisão de acesso e sugestões iniciais — pronto para evoluir em cima dos conectores e fluxos de governança que definimos no projeto.

