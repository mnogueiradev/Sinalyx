# Sinalyx

Sistema de analise de logs de firewall pfSense com IA para deteccao de
anomalias e classificacao de possiveis ataques.

## Arquitetura

```text
Logs pfSense
-> Parser
-> Feature Engineering
-> Isolation Forest
-> Autoencoder
-> Heuristica
-> Ensemble
-> Decision Engine
-> FastAPI
-> PostgreSQL
-> Dashboard
```

O Sinalyx usa modelos estatisticos, rede autoencoder e regras
comportamentais para analisar janelas de eventos pfSense. A API FastAPI
recebe logs reais, executa o pipeline validado e persiste historico e
resultados no PostgreSQL.

## Stack

- Python 3.10.11
- FastAPI
- scikit-learn
- TensorFlow/Keras
- pandas
- NumPy
- joblib
- SQLAlchemy
- PostgreSQL
- Docker e Docker Compose
- Paramiko para SSH/SFTP
- Vue 3, Vite, TypeScript e Tailwind CSS

## Estrutura De Pastas

```text
Sinalyx/
|-- src/
|   |-- api/        # FastAPI, schemas e orquestracao dos endpoints
|   |-- collectors/ # coleta SSH/SFTP do filter.log do pfSense
|   |-- db/         # SQLAlchemy, modelos e repositorio PostgreSQL
|   |-- features/   # constantes, validacao e engenharia de features
|   |-- models/     # Isolation Forest, Autoencoder, heuristica, ensemble e decisao
|   |-- parsers/    # parser canonico de logs pfSense
|   |-- pipelines/  # treino, validacao, parsing, inferencia batch e live
|   `-- services/   # servicos de dominio reutilizados pela API e CLI
|-- scripts/        # utilitarios de validacao manual
|-- data/
|   |-- raw/        # datasets e logs pfSense reais de entrada
|   |-- processed/  # features e artefatos processados de validacao
|   |-- models/     # modelos treinados e manifestos
|   `-- runtime/    # uploads/resultados gerados pela API em execucao
|-- docs/           # documentacao auxiliar e auditorias
|-- frontend/       # dashboard Vue 3 para operacao e apresentacao
|-- Dockerfile
|-- docker-compose.yml
|-- .dockerignore
|-- .env.example
|-- requirements.txt
`-- README.md
```

## Banco De Dados

O banco principal do projeto e PostgreSQL. No fluxo Docker, o PostgreSQL roda
como servico `postgres`. Em ambiente local, a configuracao padrao usa:

```text
DATABASE_URL=postgresql://sinalyx:sinalyx@postgres:5432/sinalyx
```

A senha `sinalyx` e apenas padrao local/demo controlado. Para demo publica ou
producao, copie `.env.example` para `.env` e defina `POSTGRES_PASSWORD` e
`DATABASE_URL` com valores proprios.

A API tambem salva artefatos locais em `data/runtime/`, mas o historico
principal das analises fica no PostgreSQL. O banco SQLite temporario usado em
uma atividade de aula nao faz parte do projeto principal.

## Fluxo Live pfSense

O Sinalyx possui uma primeira versao operacional para coleta e processamento
incremental do `filter.log` do pfSense:

```text
pfSense /var/log/filter.log
-> coletor SSH/SFTP
-> data/runtime/pfsense/live/filter.log
-> parser incremental
-> features por janela de 1 minuto
-> modelos + heuristica + ensemble + decision engine
-> PostgreSQL
```

Configuracao minima no `.env`:

```text
SINALYX_PFSENSE_HOST=192.168.1.1
SINALYX_PFSENSE_SSH_PORT=22
SINALYX_PFSENSE_USER=admin
SINALYX_PFSENSE_PASSWORD=
SINALYX_PFSENSE_KEY_PATH=
SINALYX_PFSENSE_REMOTE_LOG_PATH=/var/log/filter.log
SINALYX_PFSENSE_LOCAL_LOG_PATH=data/runtime/pfsense/live/filter.log
SINALYX_PFSENSE_COLLECTOR_STATE_PATH=data/runtime/pfsense/live/collector_state.json
SINALYX_PFSENSE_PARSER_STATE_PATH=data/runtime/pfsense/live/parser_state.json
```

Use senha ou chave privada. Nao versionar `.env`.

Execucao manual coletando do pfSense:

```bash
python -m src.pipelines.process_live_pfsense
```

Execucao manual usando apenas o arquivo local ja existente:

```bash
python -m src.pipelines.process_live_pfsense --skip-collect
```

Modo continuo, usado em producao real:

```bash
python -m src.pipelines.process_live_pfsense
```

Nesse modo, a ultima janela permanece aberta para a proxima execucao. Isso evita
fechar uma janela incompleta em um fluxo continuo.

Modo arquivo finito, usado para replay/teste local com logs exportados:

```bash
python -m src.pipelines.process_live_pfsense --skip-collect --finite-file
```

Nesse modo, a ultima janela pendente e fechada ao final do arquivo, permitindo
inferir e persistir tambem logs curtos ou arquivos exportados que nao terao uma
proxima linha futura. A flag antiga `--flush-pending` continua aceita por
compatibilidade, mas `--finite-file` e a forma oficial para novas validacoes
locais.

## Execucao Com Docker

Antes de subir a stack pela primeira vez, copie o exemplo de ambiente e ajuste
as variaveis conforme o perfil desejado:

```powershell
copy .env.example .env
```

Guia completo de perfis local/demo/producao:

```text
docs/environment.md
```

Para login no painel, defina no `.env` pelo menos:

```text
SINALYX_ADMIN_EMAIL=admin@sinalyx.local
SINALYX_ADMIN_PASSWORD=<sua-senha>
SINALYX_AUTH_SECRET_KEY=<segredo-forte-para-demo-ou-producao>
```

Em `SINALYX_ENV=local`, o Compose possui fallback de desenvolvimento para o
segredo JWT. Em `demo` e `production`, use um segredo forte gerado fora do Git.

Build da imagem:

```bash
docker compose build
```

Subir frontend, API e PostgreSQL:

```bash
docker compose up -d
```

URLs padrao com Docker:

```text
Frontend: http://localhost:5173
API: http://localhost:8000
Docs da API: http://localhost:8000/docs
```

No Docker Compose, a imagem da API nao embute a pasta `data/`. Os dados,
modelos treinados e artefatos de runtime sao acessados por volume:

```text
./data:/app/data
```

Por isso, mantenha `data/models/` presente na maquina local antes de executar
inferencias ou analises com os modelos ja treinados. Essa escolha evita publicar
logs reais, datasets, resultados de validacao e modelos dentro da imagem Docker.

Conferir containers:

```bash
docker compose ps
```

Acompanhar logs da API:

```bash
docker compose logs -f api
```

Guia para compactar a pasta e executar em outro computador:

```text
docs/transferencia_docker.md
```

## Frontend

O dashboard fica em `frontend/` e usa Vue 3, Vite, TypeScript e Tailwind CSS.

```bash
cd frontend
npm install
npm run dev
```

URL local padrao:

```text
http://localhost:5173
```

Configure a URL da API no arquivo `.env` do frontend, se necessario:

```text
VITE_API_BASE_URL=http://localhost:8000
```

O exemplo fica em `frontend/.env.example`. Para uso local:

```powershell
copy frontend\.env.example frontend\.env
```

Rotas principais:

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

## Administrador Inicial

O seed de admin usa as variaveis:

```text
SINALYX_ADMIN_NAME
SINALYX_ADMIN_EMAIL
SINALYX_ADMIN_PASSWORD
SINALYX_AUTH_SECRET_KEY
```

Execute:

```bash
python scripts/seed_admin.py
```

O seed nao duplica usuario se o email ja existir e nunca salva senha em texto
puro. Quando a API sobe via Docker, o seed tambem e tentado automaticamente se
`SINALYX_ADMIN_PASSWORD` estiver definido.

## Migrations

O projeto inclui base inicial do Alembic para controlar schema do PostgreSQL.
O `create_all` continua existindo como fallback de desenvolvimento.

Comandos uteis:

```bash
alembic upgrade head
alembic current
alembic revision --autogenerate -m "descricao"
```

## Testes

Testes smoke da API:

```bash
python -m pytest
```

Para validar rotas protegidas nos testes, defina:

```text
SINALYX_TEST_ADMIN_EMAIL
SINALYX_TEST_ADMIN_PASSWORD
```

Build do frontend:

```bash
cd frontend
node node_modules\vue-tsc\bin\vue-tsc.js --noEmit
node node_modules\vite\bin\vite.js build
```

## Relatorios

A rota `/reports` gera um relatorio HTML baixavel e tambem oferece a opcao
`Imprimir / salvar em PDF` pelo navegador.

## Visualizando O Banco No VS Code

Para abrir e consultar o PostgreSQL pelo VS Code, use as extensoes SQLTools e
SQLTools PostgreSQL/Cockroach Driver.

O passo a passo completo, com dados de conexao e consultas uteis, esta em:

```text
docs/database_vscode.md
```

## Endpoints Principais

- `GET /health`
- `POST /analyze/pfsense`
- `GET /analyses`
- `GET /analyses/{analysis_id}`
- `GET /analyses/{analysis_id}/results`
- `GET /live/pfsense/collector/status`
- `GET /live/pfsense/parser/status`
- `POST /live/pfsense/run`
- `GET /live/pfsense/windows`
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

Para disparar um replay local via API, use:

```text
POST /live/pfsense/run?collect=false&finite_file=true
```

Documentacao interativa local:

```text
http://localhost:8000/docs
```

## Como Testar

1. Suba os servicos:

```bash
docker compose up -d
```

2. Verifique o health check:

```text
http://localhost:8000/health
```

Resultado esperado:

```json
{
  "status": "ok",
  "database": {
    "enabled": true,
    "available": true
  }
}
```

3. Teste `POST /analyze/pfsense` com:

```text
data/raw/pfsense/port_scan.log
```

Resultado esperado no payload:

```json
{
  "status": "success",
  "total_windows": 2,
  "persistence": {
    "database_saved": true,
    "error": null
  }
}
```

4. Consulte a analise gerada:

```text
GET /analyses
GET /analyses/{analysis_id}
GET /analyses/{analysis_id}/results
```

## Logs Reais pfSense

Os cenarios de validacao ficam em `data/raw/pfsense/`:

- `normal_firewall.log`
- `port_scan.log`
- `brute_force.log`
- `syn_flood.log`

## Resultados Validados

- Docker funcional com `sinalyx_api` em execucao.
- PostgreSQL funcional com `sinalyx_postgres` em estado `healthy`.
- `GET /health` retorna `database.available=true`.
- `POST /analyze/pfsense` persiste no PostgreSQL com `database_saved=true`.
- `port_scan.log` gera `total_windows=2` e fluxo de consulta completo.
- `GET /analyses`, `GET /analyses/{analysis_id}` e
  `GET /analyses/{analysis_id}/results` retornam `status=success`.

## Proximas Etapas

- Montar ambiente pfSense + Kali para coleta real de logs.
- Ampliar a base de logs reais por cenario.
- Subir o projeto no GitHub com historico limpo.
- Publicar evolucoes tecnicas no LinkedIn.
- Evoluir a coleta SSH/SFTP real no laboratorio final.

## Documentacao Da Versao Apresentavel

- `docs/validacao_final.md`
- `docs/roteiro_apresentacao.md`
- `docs/versao_estavel.md`
- `docs/database_vscode.md`

## Observacoes

- Nao versionar `.env`.
- Nao versionar caches Python, arquivos temporarios ou builds locais.
- Nao versionar dados temporarios de runtime.
- Manter `data/raw/`, `data/processed/` e `data/models/` com criterio, pois
  contem entradas, artefatos processados e modelos importantes do TCC.
