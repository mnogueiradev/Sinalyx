"""
Definicao central de caminhos do projeto Sinalyx.

Manter os caminhos neste arquivo evita repeticao de strings e facilita a
manutencao da estrutura de pastas.
"""

from pathlib import Path

# Diretorio raiz do projeto.
BASE_DIR = Path(__file__).resolve().parents[2]

# Pastas principais de dados e artefatos.
DATA_DIR = BASE_DIR / "data"
RAW_DIR = DATA_DIR / "raw"
PROCESSED_DIR = DATA_DIR / "processed"
MODELS_DIR = DATA_DIR / "models"

AUTOENCODER_DIR = MODELS_DIR / "autoencoder"

# Arquivos centrais usados pelos pipelines e pela API.
FEATURES_FILE = PROCESSED_DIR / "features.csv"

ISOLATION_MODEL_FILE = MODELS_DIR / "isolation.pkl"
SCALER_FILE = MODELS_DIR / "scaler.joblib"

AUTOENCODER_MODEL_FILE = AUTOENCODER_DIR / "model.keras"
# O threshold do Autoencoder passou a ser persistido na raiz de data/models
# para simplificar auditoria e alinhamento entre treino e inferencia.
AUTOENCODER_THRESHOLD_FILE = MODELS_DIR / "threshold.pkl"
# Compatibilidade com artefatos antigos que ainda guardavam o threshold
# dentro de data/models/autoencoder/.
LEGACY_AUTOENCODER_THRESHOLD_FILE = AUTOENCODER_DIR / "threshold.pkl"
ENSEMBLE_CONFIG_FILE = MODELS_DIR / "ensemble.json"
ISOLATION_STATS_FILE = MODELS_DIR / "isolation_stats.json"
AUTOENCODER_STATS_FILE = MODELS_DIR / "autoencoder_stats.json"

VALIDATION_PREDICTIONS_FILE = PROCESSED_DIR / "validation_predictions.csv"
VALIDATION_REPORT_FILE = MODELS_DIR / "validation_report.json"
