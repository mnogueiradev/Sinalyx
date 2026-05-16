# Sinalyx versão apresentável TCC

## Identificação

- Versão: `v0.1.0-tcc`
- Data: 2026-05-05
- Commit Git: não disponível neste checkout
- Nome oficial: Sinalyx

## Funcionalidades incluídas

- Parser de logs reais do pfSense.
- Janelas agregadas e 13 features obrigatórias.
- Autoencoder, Isolation Forest, heurística, ensemble e Decision Engine.
- API FastAPI.
- PostgreSQL via Docker Compose.
- Histórico estruturado.
- Login, autenticação e painel admin.
- Dashboard com gráficos.
- Alertas recentes.
- Histórico com filtros.
- Detalhe de janela com explicabilidade.
- Modo Demo.
- Relatórios HTML e impressão para PDF.
- Página Sobre.
- Endpoint de auditoria `/system/audit`.
- Seed controlado de admin.
- Base inicial de migrations com Alembic.
- Testes smoke da API.

## Rotas frontend principais

- `/login`
- `/`
- `/demo`
- `/alerts`
- `/history`
- `/reports`
- `/about`
- `/system`
- `/settings`
- `/windows/:id`
- `/admin/users`

## Endpoints principais

- `GET /health`
- `GET /dashboard/summary`
- `GET /alerts/recent`
- `GET /history/summary`
- `GET /history/windows`
- `GET /history/windows/{window_id}`
- `GET /history/alerts`
- `GET /history/executions`
- `GET /system/audit`
- `POST /auth/login`
- `GET /auth/me`
- `GET /admin/users`
- `POST /admin/users`
- `PUT /admin/users/{id}`
- `PATCH /admin/users/{id}/status`

## Comandos de execução

Backend e banco:

```bash
copy .env.example .env
docker compose up -d --build
docker compose ps
```

Antes de uma demonstracao, ajuste no `.env`:

```text
SINALYX_ENV=demo
SINALYX_AUTH_SECRET_KEY=<segredo-forte>
SINALYX_ADMIN_EMAIL=<email-do-admin>
SINALYX_ADMIN_PASSWORD=<senha-forte>
```

Frontend:

```bash
cd frontend
copy .env.example .env
npm install
npm run dev
```

Seed do administrador:

```bash
set SINALYX_ADMIN_EMAIL=admin@sinalyx.local
set SINALYX_ADMIN_PASSWORD=sua-senha
set SINALYX_AUTH_SECRET_KEY=gere-um-segredo-forte-com-pelo-menos-32-caracteres
python scripts/seed_admin.py
```

Detalhes de configuracao por perfil estao em `docs/environment.md`.

Migrations:

```bash
alembic upgrade head
alembic current
alembic revision --autogenerate -m "descricao"
```

Testes:

```bash
python -m compileall src
python -m pytest
```

Frontend:

```bash
node node_modules\vue-tsc\bin\vue-tsc.js --noEmit
node node_modules\vite\bin\vite.js build
```

## O que não deve ser mexido antes da apresentação

- Parser.
- 13 features.
- Modelos treinados.
- Calibração dos modelos.
- Heurística validada.
- Ensemble.
- Decision Engine.
- Dados reais de validação.

## Pendências futuras

- Validar coleta SSH/SFTP real em laboratório.
- Ampliar corpus real.
- Melhorar métricas estatísticas com mais amostras.
- Avaliar retreino somente após nova base de logs.
