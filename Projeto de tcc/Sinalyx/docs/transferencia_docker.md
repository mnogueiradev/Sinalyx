# Transferencia do Sinalyx com Docker

Este guia explica como levar a pasta completa do Sinalyx para outro computador e executar o sistema com Docker, sem depender de `.venv`, caminhos absolutos do Windows ou arquivos fora do projeto.

## Servicos do Docker Compose

O `docker-compose.yml` sobe tres servicos:

- `sinalyx_frontend`: dashboard Vue servido por Nginx.
- `sinalyx_api`: backend FastAPI.
- `sinalyx_postgres`: banco PostgreSQL.

Portas padrao:

- Frontend: `http://localhost:5173`
- API: `http://localhost:8000`
- Documentacao da API: `http://localhost:8000/docs`
- PostgreSQL: `localhost:5432`

## Antes de compactar

Mantenha na pasta:

- `src/`
- `frontend/`
- `data/`
- `docs/`
- `scripts/`
- `migrations/`
- `Dockerfile`
- `docker-compose.yml`
- `.dockerignore`
- `.env`
- `requirements.txt`
- `alembic.ini`
- `README.md`

Nao e necessario levar:

- `.venv/`
- `frontend/node_modules/`
- `frontend/dist/`
- `__pycache__/`
- `.pytest_cache/`

Esses itens sao ignorados pelo Docker ou recriados no build.

## Variaveis importantes do .env

Leve o arquivo `.env` junto com a pasta do projeto.

Para um banco novo no outro PC, o `.env` precisa ter um administrador inicial:

```env
SINALYX_ADMIN_EMAIL=admin@sinalyx.local
SINALYX_ADMIN_PASSWORD=defina-uma-senha-forte-aqui
SINALYX_SUPER_ADMIN_EMAIL=admin@sinalyx.local
```

Se `SINALYX_ADMIN_PASSWORD` estiver vazio e o banco do outro PC tambem estiver vazio, nenhum usuario admin sera criado automaticamente.

Tambem confira:

```env
SINALYX_AUTH_SECRET_KEY=gere-um-segredo-forte-com-pelo-menos-32-caracteres
VITE_API_BASE_URL=http://localhost:8000
SINALYX_FRONTEND_HOST_PORT=5173
SINALYX_API_HOST_PORT=8000
SINALYX_POSTGRES_HOST_PORT=5432
```

## Como compactar

No Windows, compacte a pasta `Sinalyx` inteira pelo Explorador de Arquivos ou por PowerShell:

```powershell
Compress-Archive -Path .\Sinalyx -DestinationPath .\Sinalyx_v0.1.0-tcc.zip
```

Se quiser preservar os dados atuais do PostgreSQL, gere um backup antes de compactar:

```powershell
cd .\Sinalyx
.\scripts\backup_postgres.ps1
```

O backup sera salvo em:

```text
data/backups/
```

## Como executar no outro PC

1. Instale e abra o Docker Desktop.
2. Extraia a pasta do projeto.
3. Entre na pasta extraida:

```powershell
cd .\Sinalyx
```

4. Suba tudo com Docker:

```powershell
docker compose up --build
```

Ou em segundo plano:

```powershell
docker compose up -d --build
```

5. Acesse:

```text
Frontend: http://localhost:5173
API: http://localhost:8000
Docs da API: http://localhost:8000/docs
```

## Como verificar se subiu corretamente

```powershell
docker compose ps
```

Esperado:

- `sinalyx_frontend` em execucao.
- `sinalyx_api` em execucao.
- `sinalyx_postgres` em execucao e `healthy`.

Health da API:

```powershell
curl http://localhost:8000/health
```

Esperado:

```json
{"status":"ok","database":{"enabled":true,"available":true}}
```

## Como ver logs

Todos os servicos:

```powershell
docker compose logs -f
```

Somente API:

```powershell
docker compose logs -f api
```

Somente frontend:

```powershell
docker compose logs -f frontend
```

Somente banco:

```powershell
docker compose logs -f postgres
```

## Como parar

Sem apagar dados:

```powershell
docker compose down
```

## Persistencia dos dados

O PostgreSQL usa o volume Docker:

```text
sinalyx_pgdata
```

Esse volume nao fica dentro da pasta compactada. Em outro PC, o Docker criara um volume novo.

Para preservar dados reais entre PCs, use backup e restore.

Backup no PC antigo:

```powershell
.\scripts\backup_postgres.ps1
```

Restore no PC novo, depois de subir o PostgreSQL:

```powershell
docker compose up -d postgres
.\scripts\restore_postgres.ps1 -BackupPath .\data\backups\nome_do_backup.dump
docker compose up -d --build
```

O restore substitui dados existentes no banco e pede confirmacao digitando `RESTAURAR`.

## Como resetar volumes se necessario

Use somente se quiser apagar o banco local daquele PC e recriar do zero:

```powershell
docker compose down -v
docker compose up -d --build
```

Atencao: `docker compose down -v` apaga o volume PostgreSQL local.

## Observacoes

- O frontend Docker usa `VITE_API_BASE_URL=http://localhost:8000` por padrao.
- A API monta `./data:/app/data`, entao modelos, logs de validacao e runtime continuam vindo da pasta do projeto.
- O projeto nao depende de `.venv` quando executado por Docker.
- O projeto nao depende de caminhos absolutos do Windows.
- O nome oficial do projeto nesta versao e Sinalyx.
