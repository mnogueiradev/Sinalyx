# Validação final do Sinalyx

## Objetivo

Registrar a validação da versão apresentável do Sinalyx, sistema de análise de
logs de firewall pfSense com IA, PostgreSQL, API FastAPI e dashboard web.

## Ambiente usado

- Python 3.10.11
- FastAPI
- PostgreSQL via Docker Compose
- Frontend Vue 3, Vite, TypeScript e Tailwind CSS
- Logs reais exportados do pfSense em `data/raw/pfsense/`

## Cenários avaliados

| Cenário | Arquivo | Resultado esperado | Resultado observado |
| --- | --- | --- | --- |
| Normal | `normal_firewall.log` | `normal / normal / low` | Normal sem falso positivo |
| Varredura de portas | `port_scan.log` | `anomaly / port_scan / high` | Anomalia com apoio da IA |
| Força bruta | `brute_force.log` | `anomaly / brute_force / high` | Anomalia classificada como força bruta |
| DDoS | `syn_flood.log` | `anomaly / syn_flood / high` | Anomalia classificada como DDoS |

## Evidência operacional

- `GET /health` validado com `database.enabled=true` e `database.available=true`.
- `GET /history/summary` retorna resumo consolidado do histórico live.
- `GET /history/windows/{window_id}` retorna detalhe estruturado da janela.
- `GET /alerts/recent` retorna somente anomalias.
- `GET /dashboard/summary` alimenta cards e gráficos da dashboard.
- PostgreSQL preserva janelas em `live_pfsense_windows`.

## Métricas da rodada limpa

A rodada final limpa continha 13 janelas:

- 8 janelas normais.
- 5 anomalias.
- 1 varredura de portas.
- 2 força bruta.
- 2 DDoS.
- 1 janela com `ai_support=true`.

Para a base final controlada, a classificação por cenário ficou coerente:

- Recall operacional dos cenários de ataque: 100%.
- Falso positivo no cenário normal: 0 na rodada limpa.
- Precision operacional para anomalia: sem falso positivo observado na rodada.
- F1-score operacional da rodada: compatível com acerto total da amostra limpa.

## Matriz de confusão binária

| Real \ Predito | Normal | Anomalia |
| --- | ---: | ---: |
| Normal | 8 | 0 |
| Anomalia | 0 | 5 |

## Limitações atuais

- A base real ainda é pequena para afirmar generalização estatística ampla.
- A heurística continua importante para força bruta e DDoS.
- O apoio da IA foi calibrado como metadado auxiliar, sem alterar a decisão final.
- A coleta SSH/SFTP real do pfSense ainda deve ser validada no laboratório final.

## Prints esperados

Para a apresentação, capturar:

- Login.
- Dashboard com cards e gráficos.
- Modo Demo.
- Alertas recentes.
- Histórico com filtros.
- Detalhe de janela com explicabilidade.
- Relatório HTML/impressão.
- Tela Sistema.
