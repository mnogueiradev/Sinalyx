# Auditoria Dos Arquivos Python Do Sinalyx

Data da auditoria: 2026-04-30.

Escopo: arquivos `.py` fora da `.venv`, com foco em `src/`, `scripts/` e raiz
do projeto. A atividade temporaria SQLite foi removida do projeto principal.

## Resumo

- Arquivos Python auditados apos limpeza SQLite: 39.
- Arquivos `__init__.py`: mantidos como marcadores de pacote Python; nao devem
  ser removidos automaticamente mesmo quando pequenos ou sem logica executavel.
- Docstrings: todos os modulos relevantes tinham docstring de modulo. Todas as
  funcoes publicas auditadas tinham docstring apos documentar
  `src/pipelines/train.py::main`.
- Arquivos potencialmente legados foram mantidos e marcados para confirmacao,
  sem remocao automatica.

## Tabela De Auditoria

| Arquivo | Funcao principal | Uso direto | Importado por outro modulo | Tipo | Status |
|---|---|---|---|---|---|
| `cleanup_legacy.py` | Utilitario antigo para remover caminhos legados. | Sim, CLI manual. | Nao. | Script legado. | Precisa de confirmacao; pode remover itens validos se executado sem revisao. |
| `run_stream.py` | Atalho para `src.pipelines.stream_processor.main`. | Sim, CLI manual. | Nao. | Script de execucao. | Manter. |
| `scripts/validate_pfsense_scenarios.py` | Executa validacao manual dos cenarios pfSense. | Sim, CLI manual. | Nao. | Script auxiliar. | Manter. |
| `src/api/__init__.py` | Marca `src.api` como pacote. | Nao. | Sim. | Package marker. | Manter. |
| `src/api/main.py` | Define FastAPI, endpoints e startup da API. | Via Uvicorn/Docker. | Nao. | Aplicacao API. | Manter. |
| `src/api/schemas.py` | Define contratos Pydantic da API. | Nao. | Sim, por `src/api/main.py`. | Modulo de apoio. | Manter. |
| `src/api/services.py` | Orquestra upload, parser, inferencia, persistencia local e PostgreSQL. | Nao. | Sim, por `src/api/main.py`. | Modulo de servico. | Manter. |
| `src/core/__init__.py` | Marca `src.core` como pacote. | Nao. | Sim. | Package marker. | Manter. |
| `src/core/artifacts.py` | Controla caminhos e carga/salvamento de artefatos de modelo. | Nao. | Sim, por treino/inferencia/modelos. | Modulo de apoio. | Manter. |
| `src/core/evaluation.py` | Centraliza splits, metricas e selecao de candidatos. | Nao. | Sim, por treino/validacao/modelos. | Modulo de apoio. | Manter. |
| `src/core/paths.py` | Define caminhos oficiais do projeto. | Nao. | Sim, amplamente. | Configuracao de caminhos. | Manter. |
| `src/db/__init__.py` | Marca `src.db` como pacote. | Nao. | Sim. | Package marker. | Manter. |
| `src/db/database.py` | Configura SQLAlchemy, engine, sessao e flag de banco. | Nao. | Sim, por API/repositorio/modelos db. | Camada db. | Manter. |
| `src/db/init_db.py` | Cria tabelas PostgreSQL na inicializacao. | Nao. | Sim, por API. | Camada db. | Manter. |
| `src/db/models.py` | Define tabelas `Analysis` e `AnalysisResult`. | Nao. | Sim, por repositorio/db init. | Camada db. | Manter. |
| `src/db/repository.py` | Persiste e consulta analises no PostgreSQL. | Nao. | Sim, por API/services. | Camada db. | Manter. |
| `src/features/__init__.py` | Marca `src.features` como pacote. | Nao. | Sim. | Package marker. | Manter. |
| `src/features/constants.py` | Define features oficiais e modo de features. | Nao. | Sim, amplamente. | Modulo de apoio. | Manter. |
| `src/features/dataset_loader.py` | Carrega CSVs e prepara registros de treino/inferencia. | Nao. | Sim, por API/pipelines. | Modulo de apoio. | Manter. |
| `src/features/engineering.py` | Sanitiza dados numericos e cria features derivadas. | Nao. | Sim, por API/pipelines. | Modulo de apoio. | Manter. |
| `src/models/__init__.py` | Marca `src.models` como pacote. | Nao. | Sim. | Package marker. | Manter. |
| `src/models/autoencoder.py` | Treina, carrega e executa o Autoencoder. | Nao. | Sim, por ensemble/inferencia/treino. | Modelo IA. | Manter. |
| `src/models/classifier.py` | Implementa heuristica comportamental e classificacao auxiliar. | Nao. | Sim, por API/inferencia/reporting. | Heuristica. | Manter. |
| `src/models/decision_engine.py` | Consolida sinais e gera decisao final explicavel. | Nao. | Sim, por API/ensemble/inferencia. | Decision engine. | Manter. |
| `src/models/detection.py` | Treina, carrega e executa Isolation Forest. | Nao. | Sim, por API/ensemble/inferencia/treino. | Modelo IA. | Manter. |
| `src/models/ensemble.py` | Combina IF, AE e heuristica em score/configuracao. | Nao. | Sim, por API/inferencia/treino/validacao. | Ensemble. | Manter. |
| `src/parsers/__init__.py` | Exporta parser pfSense canonico. | Nao. | Sim, por pipelines. | Package marker/export. | Manter. |
| `src/parsers/pfsense_parser.py` | Parser canonico de logs pfSense/filterlog. | Nao. | Sim, por pipelines e shim. | Parser principal. | Manter. |
| `src/parsers/pipilines/parse-pfsense_logs.py` | Wrapper legado para pipeline canonico de parsing. | Sim, CLI legado. | Nao por caminho canonico. | Compatibilidade legada. | Precisa de confirmacao antes de remover. |
| `src/pfsense_parser.py` | Reexporta parser canonico para imports antigos. | Nao. | Possivel uso externo. | Shim de compatibilidade. | Manter por compatibilidade. |
| `src/pipelines/__init__.py` | Marca `src.pipelines` como pacote. | Nao. | Sim. | Package marker. | Manter. |
| `src/pipelines/infer_pfsense_batch.py` | Executa inferencia batch pfSense e gera relatorios. | Sim, CLI e API. | Sim, por API/scripts/stream. | Pipeline oficial. | Manter. |
| `src/pipelines/parse_pfsense_logs.py` | Converte logs pfSense em eventos e features. | Sim, CLI e API. | Sim, por API/scripts/wrapper. | Pipeline oficial. | Manter. |
| `src/pipelines/prepare.py` | Prepara datasets CICIDS/UNSW em features oficiais. | Sim, CLI. | Nao. | Pipeline de preparo. | Manter. |
| `src/pipelines/reporting.py` | Monta metricas e comparacoes de validacao. | Nao. | Sim, por treino/validacao. | Modulo de apoio. | Manter. |
| `src/pipelines/stream_processor.py` | Processa logs pfSense em modo streaming/janela. | Sim, via `run_stream.py`. | Sim, por atalho. | Pipeline streaming. | Manter. |
| `src/pipelines/train.py` | Treina IF, Autoencoder e ensemble; salva artefatos. | Sim, CLI. | Nao. | Pipeline oficial. | Manter. |
| `src/pipelines/validate.py` | Valida modelos e perfis usando dataset processado. | Sim, CLI. | Nao. | Pipeline oficial. | Manter. |
| `src/pipelines/window_aggregator.py` | Agrega eventos pfSense por janela e gera features. | Nao. | Sim, por parser/stream. | Modulo de apoio. | Manter. |

## Itens Que Precisam De Confirmacao

- `cleanup_legacy.py`: parece legado e potencialmente perigoso, pois sua lista
  historica inclui caminhos que existem no projeto atual. Nao foi removido.
- `src/parsers/pipilines/parse-pfsense_logs.py`: caminho com grafia antiga
  mantido apenas como wrapper de compatibilidade. Pode ser removido somente
  depois de confirmar que nenhum comando externo usa esse caminho.
