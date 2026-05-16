# Relatório de Reestruturação

## Arquivos legados identificados no projeto original

### Scripts e testes paralelos removidos da arquitetura oficial
- `scripts/debug_teste_csv.py`
- `scripts/generate_pfsense_logs.py`
- `scripts/quick_check.py`
- `scripts/verificar_csv.py`
- `test_detection.py`
- `test_features.py`

### APIs paralelas
- `src/api/main.py` antigo
- `src/api/server.py`

### Fluxos antigos de features / ingestão
- `src/data/load.py`
- `src/data/preparar_treino_normal.py`
- `src/features/build_features.py`
- `src/features/feature_engineer.py`
- `src/features/features.py`
- `src/ingest/pcap_ingest.py`

### Fluxos antigos de treino / inferência
- `src/models/train_detection.py`
- `src/models/train_isolation_forest.py`
- `src/models/train_autoencoder.py`
- `src/models/run_inference.py`
- `src/models/infer_and_act.py`
- `src/models/avaliar_deteccao_ataques.py`

## Motivos da reestruturação

1. Existiam múltiplos pontos de execução com responsabilidades sobrepostas.
2. Os artefatos eram salvos em `models/` na raiz, o que facilitava conflito entre versões antigas e novas.
3. Havia código trabalhando com 3 features e outros trechos aceitando qualquer conjunto numérico do CSV.
4. A API antiga treinava e inferia no próprio endpoint, o que não é consistente para produção nem para demonstração de TCC.
5. O projeto trazia `.venv` dentro do repositório compactado, o que polui a estrutura e infla o pacote.

## Nova regra

A partir desta versão, somente estes fluxos são oficiais:
- `python -m src.pipelines.train --input ...`
- `python -m src.pipelines.validate --input ...`
- `uvicorn src.api.main:app --reload`
