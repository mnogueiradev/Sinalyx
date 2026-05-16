# Visualizando o banco PostgreSQL no VS Code

Este guia mostra como visualizar o banco PostgreSQL do projeto no VS Code usando
as extensoes SQLTools e SQLTools PostgreSQL/Cockroach Driver.

> Observacao importante: o checkout atual do projeto esta configurado como
> Sinalyx. Por isso, os nomes reais encontrados em `docker-compose.yml` sao
> `sinalyx_postgres`, database `sinalyx`, usuario `sinalyx` e senha `sinalyx`.
> O nome da conexao no VS Code pode ser qualquer apelido, por exemplo
> `Sinalyx PostgreSQL`, sem alterar o banco real.
>
> Se voce alterou `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB` ou
> `SINALYX_POSTGRES_HOST_PORT` no `.env`, use esses valores na conexao do
> SQLTools.

## 1. Confirmar que o Docker esta rodando

Antes de conectar pelo VS Code, confirme que o PostgreSQL esta ativo:

```powershell
docker compose ps
```

Esperado no projeto atual:

```text
sinalyx_postgres Up / healthy
sinalyx_api      Up
```

Se os containers nao estiverem rodando:

```powershell
docker compose up -d
```

## 2. Instalar extensoes no VS Code

1. Abra o VS Code.
2. Abra a aba de extensoes.
3. Instale a extensao:
   - `SQLTools`
4. Instale o driver:
   - `SQLTools PostgreSQL/Cockroach Driver`
5. Abra o painel do SQLTools pela barra lateral.
6. Crie uma nova conexao PostgreSQL.

## 3. Dados de conexao

Use estes dados no SQLTools:

```text
Connection name:
Sinalyx PostgreSQL

Host:
localhost

Port:
5432

Database:
sinalyx

Username:
sinalyx

Password:
sinalyx
```

O campo `Connection name` e apenas um nome visual dentro do VS Code. Use
`Sinalyx PostgreSQL` para manter a documentacao alinhada ao nome atual.

## 4. Tabelas reais do projeto

Os modelos SQLAlchemy do projeto usam estes nomes reais:

```text
analyses
analysis_results
live_pfsense_windows
users
```

A tabela `analysis_runs` nao existe no estado atual deste checkout. Para
consultas historicas de analises batch, use `analyses`.

## 5. Acesso alternativo pelo terminal

Tambem e possivel acessar o banco diretamente pelo container:

```powershell
docker exec -it sinalyx_postgres psql -U sinalyx -d sinalyx
```

Dentro do `psql`:

```sql
\dt

SELECT * FROM analyses;

SELECT * FROM analysis_results LIMIT 10;

\q
```

## 6. Consultas uteis

Listar analises mais recentes:

```sql
SELECT *
FROM analyses
ORDER BY created_at DESC;
```

Listar resultados detalhados mais recentes:

```sql
SELECT *
FROM analysis_results
ORDER BY id DESC
LIMIT 20;
```

Listar janelas live do pfSense mais recentes:

```sql
SELECT *
FROM live_pfsense_windows
ORDER BY id DESC
LIMIT 20;
```

Agrupar resultados por tipo de ataque e risco:

```sql
SELECT
    attack_type,
    risk_level,
    COUNT(*) AS total
FROM analysis_results
GROUP BY attack_type, risk_level
ORDER BY total DESC;
```

Resumo das analises batch com quantidade de resultados:

```sql
SELECT
    ar.id,
    ar.filename,
    ar.created_at,
    ar.final_status,
    ar.predominant_attack_type,
    ar.predominant_risk_level,
    COUNT(res.id) AS total_results
FROM analyses ar
LEFT JOIN analysis_results res ON res.analysis_id = ar.id
GROUP BY ar.id
ORDER BY ar.created_at DESC;
```

Resumo das janelas live por tipo de ataque e risco:

```sql
SELECT
    attack_type,
    risk_level,
    COUNT(*) AS total
FROM live_pfsense_windows
GROUP BY attack_type, risk_level
ORDER BY total DESC;
```

## 7. Validar disponibilidade pela API

Com a API rodando, acesse:

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
