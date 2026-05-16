"""
Detector baseado em Autoencoder do Sinalyx.

Este modulo cuida do treino, tuning e inferencia do autoencoder, gerando
erro de reconstrucao, score normalizado e confianca por amostra.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from itertools import product
from typing import Any, Optional, Tuple

import joblib
import numpy as np
from tensorflow.keras.callbacks import EarlyStopping
from tensorflow.keras.layers import Dense, Dropout, Input
from tensorflow.keras.models import Model, load_model as keras_load_model

from src.core.artifacts import load_autoencoder_threshold_payload
from src.core.evaluation import compute_binary_metrics, select_best_result
from src.core.paths import (
    AUTOENCODER_DIR,
    AUTOENCODER_MODEL_FILE,
    AUTOENCODER_THRESHOLD_FILE,
    SCALER_FILE,
)
from src.features.constants import describe_active_features


@dataclass(frozen=True)
class AutoencoderConfig:
    """
    Configuracao principal do autoencoder.

    O modelo permanece tunavel e adaptativo ao numero de features, mas agora
    tambem expõe score normalizado e confianca prontos para o decision engine.
    """

    hidden_layers: tuple[int, int, int] | None = None
    dropout_rate: float = 0.0
    batch_size: int = 64
    epochs: int = 30
    threshold_percentile: int = 90
    validation_split: float = 0.1
    patience: int = 3


DEFAULT_AUTOENCODER_CONFIG = AutoencoderConfig()
DEFAULT_BATCH_SIZE_OPTIONS = (32, 64, 128)
DEFAULT_EPOCH_OPTIONS = (20, 30, 50)
DEFAULT_DROPOUT_OPTIONS = (0.0, 0.1, 0.2, 0.3)
DEFAULT_THRESHOLD_PERCENTILES = (80, 85, 90, 95)

_scaler = None
_autoencoder: Optional[Model] = None
_threshold: Optional[float] = None
_autoencoder_config: Optional[dict[str, Any]] = None
_score_stats: Optional[dict[str, float]] = None


def resolve_hidden_layers(
    input_dimension: int,
    hidden_layers: tuple[int, int, int] | None = None,
) -> tuple[int, int, int]:
    """
    Resolve a arquitetura interna automaticamente para o tamanho de entrada.
    """
    if hidden_layers is not None:
        return hidden_layers

    return (
        max(32, input_dimension * 2),
        max(16, input_dimension),
        max(8, max(4, input_dimension // 2)),
    )


def _prepare_matrix(X, expected_features: int | None = None) -> np.ndarray:
    """
    Converte a entrada em matriz numerica segura para treino e inferencia.
    """
    matrix = np.asarray(X, dtype=float)
    if matrix.ndim == 1:
        matrix = matrix.reshape(1, -1)

    matrix = np.nan_to_num(matrix, nan=0.0, posinf=0.0, neginf=0.0)

    if expected_features is not None and matrix.shape[1] > expected_features:
        matrix = matrix[:, :expected_features]

    if expected_features is not None and matrix.shape[1] != expected_features:
        raise ValueError(
            "Quantidade de features incompatível com o autoencoder treinado. "
            f"Esperado: {expected_features}. Recebido: {matrix.shape[1]}."
        )

    return matrix


def _sanitize_scores(values) -> np.ndarray:
    """
    Converte scores em vetor finito e unidimensional.
    """
    array = np.asarray(values, dtype=float).reshape(-1)
    return np.nan_to_num(array, nan=0.0, posinf=0.0, neginf=0.0)


def _summarize_scores(label: str, values) -> None:
    """
    Gera logs compactos do comportamento do autoencoder.
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


def transform_reconstruction_error(values) -> np.ndarray:
    """
    Aplica log1p aos erros para reduzir o efeito de caudas extremas.
    """
    array = _sanitize_scores(values)
    clipped = np.clip(array, a_min=0.0, a_max=None)
    return np.nan_to_num(np.log1p(clipped), nan=0.0, posinf=0.0, neginf=0.0)


def _build_score_stats(values, *, threshold: float) -> dict[str, float]:
    """
    Resume os erros de reconstrucao salvos junto com o modelo.
    """
    raw_scores = _sanitize_scores(values)
    transformed_scores = transform_reconstruction_error(raw_scores)
    return {
        "score_min": float(np.min(transformed_scores)),
        "score_max": float(np.max(transformed_scores)),
        "score_mean": float(np.mean(transformed_scores)),
        "score_std": float(np.std(transformed_scores)),
        "threshold_raw": float(threshold),
        "threshold_transformed": float(np.log1p(max(float(threshold), 0.0))),
    }


def _sigmoid_normalize(values, stats: dict[str, float] | None = None) -> np.ndarray:
    """
    Fallback para normalizacao quando nao ha faixa persistida suficiente.
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
    Normaliza erros transformados para 0-1.
    """
    array = _sanitize_scores(values)
    if array.size == 0:
        return array

    if stats is not None:
        lower = float(stats.get("score_min", 0.0))
        upper = float(stats.get("score_max", 0.0))
        if np.isfinite(lower) and np.isfinite(upper) and upper > lower:
            from sklearn.preprocessing import MinMaxScaler

            scaler = MinMaxScaler(feature_range=(0.0, 1.0))
            scaler.fit(np.array([[lower], [upper]], dtype=float))
            normalized = scaler.transform(array.reshape(-1, 1)).reshape(-1)
            return np.clip(normalized, 0.0, 1.0)

    batch_min = float(np.min(array))
    batch_max = float(np.max(array))
    if array.size > 1 and batch_max > batch_min:
        from sklearn.preprocessing import MinMaxScaler

        scaler = MinMaxScaler(feature_range=(0.0, 1.0))
        scaler.fit(array.reshape(-1, 1))
        normalized = scaler.transform(array.reshape(-1, 1)).reshape(-1)
        return np.clip(normalized, 0.0, 1.0)

    return _sigmoid_normalize(array, stats=stats)


def build_candidate_configs(
    *,
    batch_size_options: tuple[int, ...] = DEFAULT_BATCH_SIZE_OPTIONS,
    epoch_options: tuple[int, ...] = DEFAULT_EPOCH_OPTIONS,
    dropout_options: tuple[float, ...] = DEFAULT_DROPOUT_OPTIONS,
) -> list[AutoencoderConfig]:
    """
    Constroi o grid de candidatos usado no tuning do autoencoder.
    """
    configs: list[AutoencoderConfig] = []
    for batch_size, epochs, dropout_rate in product(
        batch_size_options,
        epoch_options,
        dropout_options,
    ):
        configs.append(
            AutoencoderConfig(
                batch_size=int(batch_size),
                epochs=int(epochs),
                dropout_rate=float(dropout_rate),
            )
        )
    return configs


def build_autoencoder_model(input_dimension: int, config: AutoencoderConfig) -> Model:
    """
    Constroi um autoencoder simetrico ajustado ao tamanho da entrada.
    """
    hidden_1, hidden_2, hidden_3 = resolve_hidden_layers(
        input_dimension,
        config.hidden_layers,
    )

    input_layer = Input(shape=(input_dimension,))
    x = Dense(hidden_1, activation="relu")(input_layer)
    if config.dropout_rate > 0:
        x = Dropout(config.dropout_rate)(x)

    x = Dense(hidden_2, activation="relu")(x)
    if config.dropout_rate > 0:
        x = Dropout(config.dropout_rate)(x)

    x = Dense(hidden_3, activation="relu")(x)
    if config.dropout_rate > 0:
        x = Dropout(config.dropout_rate)(x)

    x = Dense(hidden_2, activation="relu")(x)
    x = Dense(hidden_1, activation="relu")(x)
    output_layer = Dense(input_dimension, activation="linear")(x)

    autoencoder = Model(inputs=input_layer, outputs=output_layer)
    autoencoder.compile(optimizer="adam", loss="mse")
    return autoencoder


def train_autoencoder(
    X,
    config: AutoencoderConfig | None = None,
    *,
    scaler=None,
    save_artifacts: bool = True,
) -> dict[str, Any]:
    """
    Treina o autoencoder e salva threshold + estatisticas dos scores.
    """
    global _autoencoder, _threshold, _scaler, _autoencoder_config, _score_stats

    AUTOENCODER_DIR.mkdir(parents=True, exist_ok=True)
    config = config or DEFAULT_AUTOENCODER_CONFIG

    if scaler is None:
        scaler = joblib.load(SCALER_FILE)

    expected_features = getattr(scaler, "n_features_in_", None)
    X = _prepare_matrix(X, expected_features=expected_features)
    X_scaled = scaler.transform(X)

    input_dimension = X_scaled.shape[1]
    hidden_layers = resolve_hidden_layers(input_dimension, config.hidden_layers)
    effective_config = replace(config, hidden_layers=hidden_layers)

    print(
        "[INFO] Autoencoder treinando com "
        f"input_dim={input_dimension}, {describe_active_features()} "
        f"e config={asdict(effective_config)}."
    )

    autoencoder = build_autoencoder_model(input_dimension, effective_config)
    callbacks = [
        EarlyStopping(
            monitor="loss",
            patience=effective_config.patience,
            restore_best_weights=True,
        )
    ]

    autoencoder.fit(
        X_scaled,
        X_scaled,
        epochs=effective_config.epochs,
        batch_size=effective_config.batch_size,
        shuffle=True,
        verbose=0,
        validation_split=effective_config.validation_split,
        callbacks=callbacks,
    )

    reconstructed_data = autoencoder.predict(X_scaled, verbose=0)
    reconstruction_error = np.mean(np.square(X_scaled - reconstructed_data), axis=1)
    threshold = float(
        np.percentile(reconstruction_error, effective_config.threshold_percentile)
    )
    score_stats = _build_score_stats(reconstruction_error, threshold=threshold)

    bundle = {
        "model": autoencoder,
        "scaler": scaler,
        "threshold": threshold,
        "threshold_transformed": score_stats["threshold_transformed"],
        "config": asdict(effective_config),
        "score_stats": score_stats,
        "train_error_stats": {
            "raw_min": float(np.min(reconstruction_error)),
            "raw_max": float(np.max(reconstruction_error)),
            "raw_mean": float(np.mean(reconstruction_error)),
            "log_min": float(score_stats["score_min"]),
            "log_max": float(score_stats["score_max"]),
            "log_mean": float(score_stats["score_mean"]),
        },
    }

    if save_artifacts:
        autoencoder.save(AUTOENCODER_MODEL_FILE)
        joblib.dump(
            {
                "threshold": threshold,
                "config": asdict(effective_config),
                "score_stats": score_stats,
            },
            AUTOENCODER_THRESHOLD_FILE,
        )
        _autoencoder = autoencoder
        _threshold = threshold
        _scaler = scaler
        _autoencoder_config = asdict(effective_config)
        _score_stats = score_stats

    return bundle


def load_autoencoder() -> None:
    """
    Carrega modelo, threshold e estatisticas persistidas.
    """
    global _autoencoder, _threshold, _scaler, _autoencoder_config, _score_stats

    _autoencoder = keras_load_model(AUTOENCODER_MODEL_FILE)

    _, threshold_payload = load_autoencoder_threshold_payload()
    if isinstance(threshold_payload, dict):
        _threshold = float(threshold_payload["threshold"])
        _autoencoder_config = threshold_payload.get("config")
        _score_stats = threshold_payload.get("score_stats")
    else:
        _threshold = float(threshold_payload)
        _autoencoder_config = None
        _score_stats = None

    _scaler = joblib.load(SCALER_FILE)
    print(
        "[INFO] Autoencoder carregado com "
        f"expected_features={getattr(_scaler, 'n_features_in_', 'unknown')}, "
        f"config={_autoencoder_config}, score_stats={_score_stats}."
    )


def get_loaded_bundle() -> dict[str, Any]:
    """
    Exibe o bundle atual em memoria para API, validacao e ensemble.
    """
    if _autoencoder is None or _threshold is None or _scaler is None:
        raise RuntimeError(
            "O Autoencoder nao foi carregado corretamente. "
            "Execute load_autoencoder() antes de chamar get_loaded_bundle()."
        )

    return {
        "model": _autoencoder,
        "threshold": _threshold,
        "scaler": _scaler,
        "config": _autoencoder_config,
        "score_stats": _score_stats,
    }


def predict_autoencoder_with_details(
    X,
    bundle: dict[str, Any] | None = None,
) -> list[dict[str, float | int | str]]:
    """
    Executa a inferencia detalhada do autoencoder.

    Cada item retornado traz erro bruto de reconstrucao, erro transformado,
    score normalizado, predicao e confianca.
    """
    if bundle is None:
        bundle = get_loaded_bundle()

    model: Model = bundle["model"]
    threshold = float(bundle["threshold"])
    scaler = bundle["scaler"]
    score_stats = bundle.get("score_stats") or _score_stats

    expected_features = getattr(scaler, "n_features_in_", None)
    X = _prepare_matrix(X, expected_features=expected_features)
    X_scaled = scaler.transform(X)
    reconstructed_data = model.predict(X_scaled, verbose=0)
    reconstruction_error = np.mean(np.square(X_scaled - reconstructed_data), axis=1)
    transformed_error = transform_reconstruction_error(reconstruction_error)
    normalized_scores = _normalize_scores(transformed_error, stats=score_stats)

    threshold_transformed = float(
        score_stats.get("threshold_transformed", np.log1p(max(threshold, 0.0)))
    ) if score_stats else float(np.log1p(max(threshold, 0.0)))

    _summarize_scores("Autoencoder reconstruction_error", reconstruction_error)
    _summarize_scores("Autoencoder log_score", transformed_error)
    _summarize_scores("Autoencoder normalized_score", normalized_scores)

    outputs: list[dict[str, float | int | str]] = []
    for raw_error, log_error, normalized_score in zip(
        reconstruction_error,
        transformed_error,
        normalized_scores,
    ):
        pred = 1 if float(raw_error) > threshold else 0
        confidence = float(normalized_score if pred == 1 else 1.0 - normalized_score)
        outputs.append(
            {
                "pred": int(pred),
                "raw_score": float(raw_error),
                "log_score": float(log_error),
                "normalized_score": float(normalized_score),
                "confidence": float(np.clip(confidence, 0.0, 1.0)),
                "threshold_raw": float(threshold),
                "threshold_log": float(threshold_transformed),
                "label": "attack" if pred == 1 else "normal",
            }
        )

    return outputs


def predict_autoencoder(
    X,
    bundle: dict[str, Any] | None = None,
) -> Tuple[list, np.ndarray]:
    """
    Mantem a interface legada retornando apenas predicoes e erro bruto.
    """
    outputs = predict_autoencoder_with_details(X, bundle=bundle)
    predictions = [int(item["pred"]) for item in outputs]
    raw_scores = np.asarray([float(item["raw_score"]) for item in outputs], dtype=float)
    return predictions, raw_scores


def evaluate_autoencoder(
    bundle: dict[str, Any],
    X,
    y_true,
) -> dict[str, Any]:
    """
    Avalia o autoencoder em um conjunto rotulado.
    """
    outputs = predict_autoencoder_with_details(X, bundle=bundle)
    predictions = [int(item["pred"]) for item in outputs]
    raw_scores = np.asarray([float(item["raw_score"]) for item in outputs], dtype=float)
    log_scores = np.asarray([float(item["log_score"]) for item in outputs], dtype=float)
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
            "log_min": float(np.min(log_scores)),
            "log_max": float(np.max(log_scores)),
            "log_mean": float(np.mean(log_scores)),
            "normalized_min": float(np.min(normalized_scores)),
            "normalized_max": float(np.max(normalized_scores)),
            "normalized_mean": float(np.mean(normalized_scores)),
        },
    }


def tune_autoencoder(
    X_train,
    y_train,
    X_validation,
    y_validation,
    *,
    scaler,
    candidate_configs: list[AutoencoderConfig] | None = None,
    threshold_percentiles: tuple[int, ...] = DEFAULT_THRESHOLD_PERCENTILES,
) -> dict[str, Any]:
    """
    Executa o tuning do autoencoder e do threshold de deteccao.
    """
    del y_train

    candidate_configs = candidate_configs or build_candidate_configs()
    results: list[dict[str, Any]] = []

    print(f"[INFO] Testando {len(candidate_configs)} configuracoes de Autoencoder.")

    for index, base_config in enumerate(candidate_configs, start=1):
        print(
            f"[INFO] Autoencoder candidato {index}/{len(candidate_configs)}: "
            f"{asdict(base_config)}"
        )

        trained_bundle = train_autoencoder(
            X_train,
            config=base_config,
            scaler=scaler,
            save_artifacts=False,
        )

        model = trained_bundle["model"]
        expected_features = getattr(scaler, "n_features_in_", None)
        X_train_prepared = _prepare_matrix(X_train, expected_features=expected_features)
        X_validation_prepared = _prepare_matrix(
            X_validation,
            expected_features=expected_features,
        )

        X_train_scaled = scaler.transform(X_train_prepared)
        X_validation_scaled = scaler.transform(X_validation_prepared)

        train_reconstructed = model.predict(X_train_scaled, verbose=0)
        validation_reconstructed = model.predict(X_validation_scaled, verbose=0)

        train_errors = np.mean(np.square(X_train_scaled - train_reconstructed), axis=1)
        validation_errors = np.mean(
            np.square(X_validation_scaled - validation_reconstructed),
            axis=1,
        )

        threshold_candidates: list[dict[str, Any]] = []
        for percentile in threshold_percentiles:
            threshold = float(np.percentile(train_errors, percentile))
            predictions = [1 if error > threshold else 0 for error in validation_errors]
            metrics = compute_binary_metrics(y_validation, predictions)

            effective_config = replace(
                AutoencoderConfig(**trained_bundle["config"]),
                threshold_percentile=int(percentile),
            )
            threshold_candidates.append(
                {
                    "config": asdict(effective_config),
                    "metrics": metrics,
                    "score_summary": {
                        "raw_min": float(np.min(validation_errors)),
                        "raw_max": float(np.max(validation_errors)),
                        "raw_mean": float(np.mean(validation_errors)),
                        "log_min": float(np.min(transform_reconstruction_error(validation_errors))),
                        "log_max": float(np.max(transform_reconstruction_error(validation_errors))),
                        "log_mean": float(np.mean(transform_reconstruction_error(validation_errors))),
                    },
                    "threshold": threshold,
                }
            )

        best_threshold_result = select_best_result(threshold_candidates)
        results.append(best_threshold_result)

    best_result = select_best_result(results)
    best_config = AutoencoderConfig(**best_result["config"])
    best_bundle = train_autoencoder(
        X_train,
        config=best_config,
        scaler=scaler,
        save_artifacts=False,
    )
    best_bundle["threshold"] = float(best_result["threshold"])
    best_bundle["threshold_transformed"] = float(
        np.log1p(max(float(best_result["threshold"]), 0.0))
    )

    print(
        "[INFO] Melhor configuracao do Autoencoder: "
        f"{best_result['config']} com metricas={best_result['metrics']}"
    )

    return {
        "best_bundle": best_bundle,
        "best_result": best_result,
        "results": results,
    }
