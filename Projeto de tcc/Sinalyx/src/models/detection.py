"""
Detector baseado em Isolation Forest do Sinalyx.

Este modulo treina, avalia e executa inferencia com o detector de anomalias
baseado em Isolation Forest, expondo tambem scores e confiancas.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from itertools import product
from typing import Any, Optional, Tuple

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import MinMaxScaler, RobustScaler, StandardScaler

from src.core.evaluation import compute_binary_metrics, select_best_result
from src.core.paths import ISOLATION_MODEL_FILE, SCALER_FILE
from src.features.constants import describe_active_features


@dataclass(frozen=True)
class IsolationForestConfig:
    """
    Configuracao principal do detector baseado em Isolation Forest.

    O projeto continua aceitando troca de scaler e tuning de hiperparametros,
    mas a interface publica do modulo permanece compatível com o pipeline atual.
    """

    n_estimators: int = 300
    contamination: float = 0.05
    max_samples: str | float | int = "auto"
    scaler_type: str = "standard"
    random_state: int = 42
    n_jobs: int = 1


DEFAULT_ISOLATION_FOREST_CONFIG = IsolationForestConfig()
DEFAULT_N_ESTIMATORS_OPTIONS = (100, 200, 300)
DEFAULT_CONTAMINATION_OPTIONS = (0.01, 0.03, 0.05, 0.1)
DEFAULT_MAX_SAMPLES_OPTIONS = ("auto", 0.7)
DEFAULT_SCALER_OPTIONS = ("standard", "robust")

_model: Optional[IsolationForest] = None
_scaler: Optional[Any] = None
_model_config: Optional[dict[str, Any]] = None
_score_stats: Optional[dict[str, float]] = None


def _create_scaler(scaler_type: str) -> Any:
    """
    Retorna o scaler configurado para o detector.
    """
    scaler_map = {
        "standard": StandardScaler,
        "robust": RobustScaler,
    }

    scaler_key = scaler_type.strip().lower()
    scaler_class = scaler_map.get(scaler_key)
    if scaler_class is None:
        raise ValueError(
            f"Scaler invalido: {scaler_type}. Use 'standard' ou 'robust'."
        )

    return scaler_class()


def _prepare_matrix(X, expected_features: int | None = None) -> np.ndarray:
    """
    Converte qualquer entrada em matriz numerica finita.

    Esse passo protege treino e inferencia contra NaN, infinito e shapes
    inesperados. Tambem preserva compatibilidade com modelos legados que
    possam ter sido treinados com menos colunas.
    """
    matrix = np.asarray(X, dtype=float)
    if matrix.ndim == 1:
        matrix = matrix.reshape(1, -1)

    matrix = np.nan_to_num(matrix, nan=0.0, posinf=0.0, neginf=0.0)

    if expected_features is not None and matrix.shape[1] > expected_features:
        matrix = matrix[:, :expected_features]

    if expected_features is not None and matrix.shape[1] != expected_features:
        raise ValueError(
            "Quantidade de features incompatível com o modelo treinado. "
            f"Esperado: {expected_features}. Recebido: {matrix.shape[1]}."
        )

    return matrix


def _sanitize_scores(values) -> np.ndarray:
    """
    Garante que qualquer vetor de score fique finito e unidimensional.
    """
    array = np.asarray(values, dtype=float).reshape(-1)
    return np.nan_to_num(array, nan=0.0, posinf=0.0, neginf=0.0)


def _summarize_scores(label: str, values) -> None:
    """
    Gera logs compactos para depuracao e demonstracao do detector.
    """
    array = _sanitize_scores(values)
    if array.size == 0:
        print(f"[INFO] {label}: sem valores para resumir.")
        return

    preview = ", ".join(f"{value:.6f}" for value in array[:5])
    print(
        f"[INFO] {label}: "
        f"min={float(np.min(array)):.6f}, "
        f"max={float(np.max(array)):.6f}, "
        f"mean={float(np.mean(array)):.6f}, "
        f"preview=[{preview}]"
    )


def _build_score_stats(values) -> dict[str, float]:
    """
    Resume a distribuicao de score salva junto com o modelo.
    """
    array = _sanitize_scores(values)
    return {
        "score_min": float(np.min(array)),
        "score_max": float(np.max(array)),
        "score_mean": float(np.mean(array)),
        "score_std": float(np.std(array)),
    }


def _sigmoid_normalize(values, stats: dict[str, float] | None = None) -> np.ndarray:
    """
    Fallback para normalizacao quando nao ha faixa suficiente para MinMax.

    O sigmoid evita que uma amostra unica vire sempre zero, o que seria ruim
    para a API e para a camada de decisao explicavel.
    """
    array = _sanitize_scores(values)
    center = 0.0
    scale = 1.0

    if stats:
        center = float(stats.get("score_mean", 0.0))
        std = float(stats.get("score_std", 0.0))
        if std > 0:
            scale = max(std * 2.0, 1e-6)

    z_score = (array - center) / scale
    normalized = 1.0 / (1.0 + np.exp(-z_score))
    return np.clip(normalized, 0.0, 1.0)


def _normalize_scores(values, stats: dict[str, float] | None = None) -> np.ndarray:
    """
    Normaliza scores para 0-1 usando limites persistidos quando possivel.
    """
    array = _sanitize_scores(values)
    if array.size == 0:
        return array

    if stats is not None:
        lower = float(stats.get("score_min", 0.0))
        upper = float(stats.get("score_max", 0.0))
        if np.isfinite(lower) and np.isfinite(upper) and upper > lower:
            scaler = MinMaxScaler(feature_range=(0.0, 1.0))
            scaler.fit(np.array([[lower], [upper]], dtype=float))
            normalized = scaler.transform(array.reshape(-1, 1)).reshape(-1)
            return np.clip(normalized, 0.0, 1.0)

    batch_min = float(np.min(array))
    batch_max = float(np.max(array))
    if array.size > 1 and batch_max > batch_min:
        scaler = MinMaxScaler(feature_range=(0.0, 1.0))
        scaler.fit(array.reshape(-1, 1))
        normalized = scaler.transform(array.reshape(-1, 1)).reshape(-1)
        return np.clip(normalized, 0.0, 1.0)

    return _sigmoid_normalize(array, stats=stats)


def _build_prediction_records(
    raw_predictions,
    raw_scores,
    normalized_scores,
) -> list[dict[str, float | int | str]]:
    """
    Constrói a saida explicavel do detector para cada amostra analisada.
    """
    records: list[dict[str, float | int | str]] = []
    for raw_prediction, raw_score, normalized_score in zip(
        raw_predictions,
        raw_scores,
        normalized_scores,
    ):
        pred = 1 if int(raw_prediction) == -1 else 0
        confidence = float(normalized_score if pred == 1 else 1.0 - normalized_score)
        records.append(
            {
                "pred": int(pred),
                "raw_score": float(raw_score),
                "normalized_score": float(normalized_score),
                "confidence": float(np.clip(confidence, 0.0, 1.0)),
                "label": "attack" if pred == 1 else "normal",
            }
        )
    return records


def build_candidate_configs(
    *,
    n_estimators_options: tuple[int, ...] = DEFAULT_N_ESTIMATORS_OPTIONS,
    contamination_options: tuple[float, ...] = DEFAULT_CONTAMINATION_OPTIONS,
    max_samples_options: tuple[str | float | int, ...] = DEFAULT_MAX_SAMPLES_OPTIONS,
    scaler_options: tuple[str, ...] = DEFAULT_SCALER_OPTIONS,
) -> list[IsolationForestConfig]:
    """
    Constroi o grid de candidatos usado no tuning.
    """
    configs: list[IsolationForestConfig] = []
    for n_estimators, contamination, max_samples, scaler_type in product(
        n_estimators_options,
        contamination_options,
        max_samples_options,
        scaler_options,
    ):
        configs.append(
            IsolationForestConfig(
                n_estimators=int(n_estimators),
                contamination=float(contamination),
                max_samples=max_samples,
                scaler_type=str(scaler_type),
            )
        )
    return configs


def train_model(
    X,
    config: IsolationForestConfig | None = None,
    *,
    save_artifacts: bool = True,
) -> dict[str, Any]:
    """
    Treina o detector e persiste modelo, scaler e estatisticas de score.
    """
    global _model, _scaler, _model_config, _score_stats

    config = config or DEFAULT_ISOLATION_FOREST_CONFIG
    X = _prepare_matrix(X)

    scaler = _create_scaler(config.scaler_type)
    X_scaled = scaler.fit_transform(X)

    print(
        "[INFO] Isolation Forest treinando com "
        f"{describe_active_features()}, config={asdict(config)}."
    )

    model = IsolationForest(
        n_estimators=config.n_estimators,
        contamination=config.contamination,
        max_samples=config.max_samples,
        random_state=config.random_state,
        n_jobs=config.n_jobs,
    )
    model.fit(X_scaled)

    train_raw_scores = np.nan_to_num(
        -model.decision_function(X_scaled),
        nan=0.0,
        posinf=0.0,
        neginf=0.0,
    )
    score_stats = _build_score_stats(train_raw_scores)

    bundle = {
        "model": model,
        "scaler": scaler,
        "config": asdict(config),
        "score_stats": score_stats,
    }

    if save_artifacts:
        joblib.dump(
            {
                "model": model,
                "config": asdict(config),
                "score_stats": score_stats,
            },
            ISOLATION_MODEL_FILE,
        )
        joblib.dump(scaler, SCALER_FILE)
        _model = model
        _scaler = scaler
        _model_config = asdict(config)
        _score_stats = score_stats

    return bundle


def load_model() -> None:
    """
    Carrega modelo e scaler salvos, incluindo estatisticas de score.
    """
    global _model, _scaler, _model_config, _score_stats

    payload = joblib.load(ISOLATION_MODEL_FILE)
    if isinstance(payload, dict) and "model" in payload:
        _model = payload["model"]
        _model_config = payload.get("config")
        _score_stats = payload.get("score_stats")
    else:
        _model = payload
        _model_config = None
        _score_stats = None

    _scaler = joblib.load(SCALER_FILE)
    print(
        "[INFO] Isolation Forest carregado com "
        f"expected_features={getattr(_scaler, 'n_features_in_', 'unknown')}, "
        f"config={_model_config}, score_stats={_score_stats}."
    )


def get_loaded_bundle() -> dict[str, Any]:
    """
    Expõe o bundle em memoria para API, validacao e decision engine.
    """
    if _model is None or _scaler is None:
        raise RuntimeError(
            "O modelo Isolation Forest nao foi carregado. "
            "Execute load_model() antes de chamar get_loaded_bundle()."
        )

    return {
        "model": _model,
        "scaler": _scaler,
        "config": _model_config,
        "score_stats": _score_stats,
    }


def predict_with_details(
    X,
    bundle: dict[str, Any] | None = None,
) -> list[dict[str, float | int | str]]:
    """
    Executa a inferencia detalhada do detector.

    A funcao retorna score bruto, score normalizado, predicao e confianca
    para cada amostra, sem quebrar a API legada do modulo.
    """
    if bundle is None:
        bundle = get_loaded_bundle()

    model: IsolationForest = bundle["model"]
    scaler = bundle["scaler"]
    score_stats = bundle.get("score_stats") or _score_stats

    expected_features = getattr(scaler, "n_features_in_", None)
    X = _prepare_matrix(X, expected_features=expected_features)
    X_scaled = scaler.transform(X)

    raw_predictions = model.predict(X_scaled)
    raw_scores = np.nan_to_num(
        -model.decision_function(X_scaled),
        nan=0.0,
        posinf=0.0,
        neginf=0.0,
    )
    normalized_scores = _normalize_scores(raw_scores, stats=score_stats)

    _summarize_scores("Isolation Forest raw_score", raw_scores)
    _summarize_scores("Isolation Forest normalized_score", normalized_scores)

    return _build_prediction_records(
        raw_predictions,
        raw_scores,
        normalized_scores,
    )


def predict(
    X,
    bundle: dict[str, Any] | None = None,
) -> Tuple[list, np.ndarray]:
    """
    Mantem a interface legada retornando apenas predicoes e raw_score.
    """
    outputs = predict_with_details(X, bundle=bundle)
    predictions = [int(item["pred"]) for item in outputs]
    raw_scores = np.asarray([float(item["raw_score"]) for item in outputs], dtype=float)
    return predictions, raw_scores


def evaluate_model(
    bundle: dict[str, Any],
    X,
    y_true,
) -> dict[str, Any]:
    """
    Avalia o detector individualmente em um conjunto rotulado.
    """
    outputs = predict_with_details(X, bundle=bundle)
    predictions = [int(item["pred"]) for item in outputs]
    raw_scores = np.asarray([float(item["raw_score"]) for item in outputs], dtype=float)
    normalized_scores = np.asarray(
        [float(item["normalized_score"]) for item in outputs],
        dtype=float,
    )
    metrics = compute_binary_metrics(y_true, predictions)
    return {
        "config": bundle["config"],
        "metrics": metrics,
        "score_summary": {
            "raw_min": float(np.min(raw_scores)),
            "raw_max": float(np.max(raw_scores)),
            "raw_mean": float(np.mean(raw_scores)),
            "normalized_min": float(np.min(normalized_scores)),
            "normalized_max": float(np.max(normalized_scores)),
            "normalized_mean": float(np.mean(normalized_scores)),
        },
    }


def tune_model(
    X_train,
    y_train,
    X_validation,
    y_validation,
    *,
    candidate_configs: list[IsolationForestConfig] | None = None,
) -> dict[str, Any]:
    """
    Executa grid search do detector usando o conjunto de validacao.
    """
    del y_train

    results: list[dict[str, Any]] = []
    candidate_configs = candidate_configs or build_candidate_configs()

    print(f"[INFO] Testando {len(candidate_configs)} configuracoes do Isolation Forest.")

    for index, config in enumerate(candidate_configs, start=1):
        print(
            "[INFO] Isolation Forest candidato "
            f"{index}/{len(candidate_configs)}: {asdict(config)}"
        )
        bundle = train_model(X_train, config=config, save_artifacts=False)
        result = evaluate_model(bundle, X_validation, y_validation)
        results.append(result)

    best_result = select_best_result(results)
    best_bundle = train_model(
        X_train,
        IsolationForestConfig(**best_result["config"]),
        save_artifacts=False,
    )

    print(
        "[INFO] Melhor configuracao do Isolation Forest: "
        f"{best_result['config']} com metricas={best_result['metrics']}"
    )

    return {
        "best_bundle": best_bundle,
        "best_result": best_result,
        "results": results,
    }
