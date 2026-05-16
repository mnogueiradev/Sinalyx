# Configuracao de ambientes do Sinalyx

Este guia separa os perfis `local`, `demo` e `production` sem alterar o
pipeline de inferencia do projeto.

## Arquivos de ambiente

- Backend/Docker: copie `.env.example` para `.env` na raiz do projeto.
- Frontend: copie `frontend/.env.example` para `frontend/.env`.
- Nunca versione arquivos `.env` reais.

```powershell
copy .env.example .env
copy frontend\.env.example frontend\.env
```

## Ambiente local

Uso recomendado para desenvolvimento na propria maquina.

```env
SINALYX_ENV=local
SINALYX_CORS_ORIGINS=http://localhost:5173,http://127.0.0.1:5173,http://localhost:3000,http://127.0.0.1:3000
POSTGRES_DB=sinalyx
POSTGRES_USER=sinalyx
POSTGRES_PASSWORD=sinalyx
DATABASE_URL=postgresql://sinalyx:sinalyx@postgres:5432/sinalyx
SINALYX_API_BIND=127.0.0.1
SINALYX_API_HOST_PORT=8000
SINALYX_POSTGRES_BIND=127.0.0.1
SINALYX_POSTGRES_HOST_PORT=5432
VITE_API_BASE_URL=http://localhost:8000
```

Para habilitar login admin no ambiente local, defina:

```env
SINALYX_ADMIN_EMAIL=admin@sinalyx.local
SINALYX_ADMIN_PASSWORD=defina-uma-senha-local
```

Se `SINALYX_ADMIN_PASSWORD` ficar vazio, o seed automatico nao cria admin.

## Ambiente demo

Uso recomendado para apresentacao controlada do TCC.

1. Defina `SINALYX_ENV=demo`.
2. Gere um segredo JWT forte:

```powershell
.\.venv\Scripts\python.exe -c "import secrets; print(secrets.token_urlsafe(48))"
```

3. Preencha:

```env
SINALYX_AUTH_SECRET_KEY=<segredo-gerado>
SINALYX_ADMIN_EMAIL=<email-do-admin>
SINALYX_ADMIN_PASSWORD=<senha-forte-da-demo>
SINALYX_CORS_ORIGINS=http://localhost:5173
VITE_API_BASE_URL=http://localhost:8000
```

4. Suba a stack:

```powershell
docker compose up -d --build
docker compose ps
```

## Ambiente production

O `docker-compose.yml` deste repositorio e voltado a local/demo. Para producao:

- defina `SINALYX_ENV=production`;
- use `SINALYX_AUTH_SECRET_KEY` unico, forte e armazenado fora do Git;
- use senha propria para `POSTGRES_PASSWORD`;
- atualize `DATABASE_URL` com a mesma senha do PostgreSQL;
- use `SINALYX_CORS_ORIGINS` com o dominio HTTPS real do frontend;
- nao exponha PostgreSQL publicamente;
- use proxy reverso com HTTPS para a API;
- nao publique imagens contendo dados reais de `data/`;
- mantenha credenciais do pfSense apenas no `.env` real.

Exemplo de variaveis criticas:

```env
SINALYX_ENV=production
SINALYX_AUTH_SECRET_KEY=<segredo-forte>
POSTGRES_PASSWORD=<senha-forte>
DATABASE_URL=postgresql://sinalyx:<senha-forte>@postgres:5432/sinalyx
SINALYX_CORS_ORIGINS=https://app.exemplo.com
SINALYX_API_BIND=127.0.0.1
SINALYX_POSTGRES_BIND=127.0.0.1
```

## JWT e segredo de autenticacao

Em `local`, o Compose possui fallback de desenvolvimento para facilitar testes.
Em `demo` e `production`, o backend rejeita segredos fracos ou ausentes ao criar
ou validar tokens.

Valores que nao devem ser usados em demo/producao:

- `sinalyx-dev-secret-change-me`
- `sinalyx-local-dev-secret-change-me`
- `troque-este-segredo-em-producao`

## Portas

Por padrao, o Compose publica API e PostgreSQL apenas no localhost:

- API: `127.0.0.1:8000`
- PostgreSQL: `127.0.0.1:5432`

Se precisar demonstrar em outra maquina da mesma rede, ajuste manualmente:

```env
SINALYX_API_BIND=0.0.0.0
SINALYX_CORS_ORIGINS=http://IP-DA-MAQUINA:5173
VITE_API_BASE_URL=http://IP-DA-MAQUINA:8000
```

Evite expor o PostgreSQL na rede.

## Dados e modelos no Docker

A imagem da API nao copia `data/`. Essa pasta pode conter logs reais, datasets,
modelos treinados e artefatos de validacao. No Compose, tudo continua acessivel
por volume:

```yaml
./data:/app/data
```

Assim:

- `data/models/` fornece os artefatos dos modelos para inferencia;
- `data/runtime/` recebe uploads, resultados e estados de execucao;
- `data/raw/` permanece disponivel para validacoes locais, quando necessario.

Se executar a imagem sem `docker compose`, monte a pasta manualmente:

```powershell
docker run --rm -p 8000:8000 -v ${PWD}\data:/app/data sinalyx-api
```

## Comandos uteis

Backend e banco:

```powershell
docker compose up -d --build
docker compose ps
```

Frontend:

```powershell
cd frontend
npm install
npm run dev
```

Testes:

```powershell
.\.venv\Scripts\python.exe -m compileall src tests
.\.venv\Scripts\python.exe -m pytest -rs
```

Para testar rotas autenticadas via pytest, defina:

```powershell
$env:SINALYX_TEST_ADMIN_EMAIL="admin@sinalyx.local"
$env:SINALYX_TEST_ADMIN_PASSWORD="<senha-do-admin>"
.\.venv\Scripts\python.exe -m pytest -rs
```
