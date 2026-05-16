"""
Camada de orquestracao do ensemble do Sinalyx.

Nesta versao, o ensemble deixa de ser uma media simples e passa a atuar como:
- calibrador dos scores dos detectores
- camada de risco continuo centrada no Autoencoder
- fonte de sinais auxiliares para o decision engine

O Autoencoder assume o papel principal porque foi o detector mais estavel.
O Isolation Forest continua presente, mas entra como modulador de conflito
e estabilidade, nao como voto simetrico.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from itertools import product
from typing import Any, Tuple

import numpy as np
from sklearn.preprocessing import MinMaxScaler

from src.core.evaluation import compute_binary_metrics
from src.core.paths import ENSEMBLE_CONFIG_FILE
from src.features.constants import describe_active_features
from src.models.autoencoder import (
    get_loaded_bundle as get_loaded_autoencoder_bundle,
    load_autoencoder,
    predict_autoencoder,
    predict_autoencoder_with_details,
    train_autoencoder,
)
from src.models.decision_engine import (
    DEFAULT_DECISION_CONFIG,
    DecisionConfig,
    clamp_confidence,
    make_decision,
    resolve_config,
    resolve_runtime_profile,
)
from src.models.detection import (
    DEFAULT_ISOLATION_FOREST_CONFIG,
    get_loaded_bundle as get_loaded_detection_bundle,
    load_model,
    predict,
    predict_with_details,
    train_model,
)


@dataclass(frozen=True)
class EnsembleConfig:
    """
    Configuracao persistida do ensemble do Sinalyx.
    """

    profile_name: str = "balanced"
    if_weight: float = 0.12
    ae_weight: float = 0.88
    heuristic_weight: float = 0.10
    threshold: float = 0.55
    prioritize_recall: bool = True
    prioritize_precision: bool = False
    strong_attack_threshold: float = 0.72
    moderate_attack_threshold: float = 0.55
    ae_low_ratio: float = 0.24
    ae_medium_ratio: float = 0.32
    ae_high_ratio: float = 0.64
    if_conflict_weight: float = 0.08
    if_agreement_weight: float = 0.05
    if_score_min: float | None = None
    if_score_max: float | None = None
    ae_score_min: float | None = None
    ae_score_max: float | None = None
    ae_reference_threshold_raw: float | None = None
    ae_reference_cap_raw: float | None = None
    if_alert_score_center: float = 0.0
    if_alert_score_scale: float = 0.05
    if_alert_floor_when_predicted: float = 0.0
    medium_band_support_boost: float = 0.0
    high_band_support_boost: float = 0.0


DEFAULT_ENSEMBLE_CONFIG = EnsembleConfig()
DEFAULT_WEIGHT_OPTIONS = (
    (0.10, 0.90),
    (0.12, 0.88),
    (0.15, 0.85),
    (0.20, 0.80),
)
DEFAULT_THRESHOLD_OPTIONS = (0.52, 0.55, 0.58, 0.60)

_ensemble_config: EnsembleConfig | None = None


def save_ensemble_config(config: EnsembleConfig) -> None:
    """Salva a configuracao do ensemble em disco."""
    ENSEMBLE_CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with ENSEMBLE_CONFIG_FILE.open("w", encoding="utf-8") as file:
        json.dump(asdict(config), file, indent=2, ensure_ascii=False)


def load_ensemble_config() -> None:
    """Carrega a configuracao persistida do ensemble."""
    global _ensemble_config

    if not ENSEMBLE_CONFIG_FILE.exists():
        _ensemble_config = DEFAULT_ENSEMBLE_CONFIG
        print("[INFO] Configuracao do ensemble nao encontrada. Usando padrao.")
        return

    with ENSEMBLE_CONFIG_FILE.open("r", encoding="utf-8") as file:
        payload = json.load(file)

    _ensemble_config = EnsembleConfig(**payload)
    print(f"[INFO] Ensemble carregado com config={payload}.")


def get_loaded_config() -> EnsembleConfig:
    """Retorna a configuracao base atual ou um padrao seguro."""
    return _ensemble_config or DEFAULT_ENSEMBLE_CONFIG


def resolve_ensemble_config(
    config: EnsembleConfig | None = None,
    *,
    runtime_profile: str | None = None,
) -> EnsembleConfig:
    """Aplica o perfil operacional sobre a configuracao carregada."""
    base_config = config or get_loaded_config()
    profile_name = resolve_runtime_profile(runtime_profile or base_config.profile_name)
    payload = asdict(base_config)
    payload["profile_name"] = profile_name

    if profile_name == "conservative":
        payload["threshold"] = max(float(payload["threshold"]), 0.60)
        payload["if_weight"] = min(max(float(payload["if_weight"]), 0.12), 0.20)
        payload["ae_weight"] = max(float(payload["ae_weight"]), 0.88)
        payload["if_conflict_weight"] = max(float(payload["if_conflict_weight"]), 0.08)
        payload["if_agreement_weight"] = max(float(payload["if_agreement_weight"]), 0.05)
        payload["ae_reference_cap_raw"] = None
        payload["if_alert_score_center"] = 0.0
        payload["if_alert_score_scale"] = 0.05
        payload["if_alert_floor_when_predicted"] = 0.0
        payload["medium_band_support_boost"] = 0.0
        payload["high_band_support_boost"] = 0.0
        return EnsembleConfig(**payload)

    payload["threshold"] = min(max(float(payload["threshold"]), 0.28), 0.32)
    payload["if_weight"] = max(float(payload["if_weight"]), 0.18)
    payload["ae_weight"] = max(float(payload["ae_weight"]), 0.82)
    payload["if_conflict_weight"] = min(max(float(payload["if_conflict_weight"]), 0.02), 0.04)
    payload["if_agreement_weight"] = max(float(payload["if_agreement_weight"]), 0.08)
    payload["strong_attack_threshold"] = min(
        max(float(payload["strong_attack_threshold"]), 0.62),
        0.68,
    )
    payload["moderate_attack_threshold"] = min(
        max(float(payload["moderate_attack_threshold"]), 0.44),
        0.50,
    )
    payload["ae_reference_cap_raw"] = None
    payload["if_alert_score_center"] = -0.18
    payload["if_alert_score_scale"] = 0.04
    payload["if_alert_floor_when_predicted"] = 0.72
    payload["medium_band_support_boost"] = 0.06
    payload["high_band_support_boost"] = 0.12
    return EnsembleConfig(**payload)


def _sanitize_scores(values) -> np.ndarray:
    """Converte qualquer score em vetor numerico finito."""
    array = np.asarray(values, dtype=float).reshape(-1)
    return np.nan_to_num(array, nan=0.0, posinf=0.0, neginf=0.0)


def summarize_scores(label: str, values) -> None:
    """Gera logs compactos para depuracao do ensemble."""
    array = _sanitize_scores(values)
    if array.size == 0:
        print(f"[INFO] {label}: sem valores para resumir.")
        return
    preview = ", ".join(f"{value:.6f}" for value in array[:5])
    print(
        f"[INFO] {label}: min={float(np.min(array)):.6f}, "
        f"max={float(np.max(array)):.6f}, mean={float(np.mean(array)):.6f}, "
        f"preview=[{preview}]"
    )


def normalize_scores(
    values,
    *,
    score_min: float | None = None,
    score_max: float | None = None,
) -> np.ndarray:
    """
    Normaliza scores para 0-1, preservando compatibilidade com a camada antiga.
    """
    array = _sanitize_scores(values)
    if array.size == 0:
        return array

    lower = None if score_min is None else float(score_min)
    upper = None if score_max is None else float(score_max)

    if (
        lower is not None
        and upper is not None
        and np.isfinite(lower)
        and np.isfinite(upper)
        and upper > lower
    ):
        fit_values = np.array([[lower], [upper]], dtype=float)
    else:
        batch_min = float(np.min(array))
        batch_max = float(np.max(array))
        if batch_max <= batch_min:
            return np.zeros_like(array)
        fit_values = array.reshape(-1, 1)

    scaler = MinMaxScaler(feature_range=(0.0, 1.0))
    scaler.fit(fit_values)
    normalized = scaler.transform(array.reshape(-1, 1)).reshape(-1)
    normalized = np.nan_to_num(normalized, nan=0.0, posinf=1.0, neginf=0.0)
    return np.clip(normalized, 0.0, 1.0)


def transform_autoencoder_scores(values) -> np.ndarray:
    """Aplica log1p aos erros do Autoencoder antes da normalizacao."""
    array = _sanitize_scores(values)
    clipped = np.clip(array, a_min=0.0, a_max=None)
    return np.nan_to_num(np.log1p(clipped), nan=0.0, posinf=0.0, neginf=0.0)


def orient_isolation_forest_scores(values) -> np.ndarray:
    """Mantem uma orientacao consistente para o score bruto do IF."""
    array = _sanitize_scores(values)
    if array.size == 0:
        return array
    return -array if float(np.max(array)) <= 0.0 else array


def _sigmoid(values) -> np.ndarray:
    """Sigmoid numericamente estavel para calibracao continua."""
    array = _sanitize_scores(values)
    return 1.0 / (1.0 + np.exp(-array))


def _resolve_runtime_weights(config: EnsembleConfig) -> tuple[float, float]:
    """
    Resolve pesos operacionais em tempo de inferencia.

    Mesmo se o `ensemble.json` vier de uma calibracao antiga, o runtime
    mantem AE dominante para evitar que o IF distorça a decisao final.
    """
    ae_weight = max(float(config.ae_weight), 0.80)
    if_weight = min(float(config.if_weight), 0.20)
    total = ae_weight + if_weight
    return if_weight / total, ae_weight / total


def resolve_threshold(threshold: float) -> float:
    """Resolve um threshold operacional seguro para a camada de suporte."""
    try:
        value = float(threshold)
    except (TypeError, ValueError):
        value = DEFAULT_ENSEMBLE_CONFIG.threshold

    # Ainda protegemos contra extremos, mas sem voltar automaticamente
    # para o estado conservador demais.
    return float(np.clip(value, 0.25, 0.80))


def _resolve_ae_reference_threshold(
    config: EnsembleConfig,
    autoencoder_bundle: dict[str, Any] | None = None,
) -> float:
    """Resolve o threshold bruto do AE usado para montar as zonas de risco."""
    reference: float
    if config.ae_reference_threshold_raw is not None:
        reference = float(config.ae_reference_threshold_raw)
    elif autoencoder_bundle is not None and "threshold" in autoencoder_bundle:
        reference = float(autoencoder_bundle["threshold"])
    else:
        reference = float(get_loaded_autoencoder_bundle()["threshold"])

    if config.ae_reference_cap_raw is not None:
        reference = min(reference, float(config.ae_reference_cap_raw))
    return max(reference, 1e-6)


def _compute_ae_runtime_bands(
    ae_score_raw: float,
    ae_score_norm: float,
    ae_pred: int,
    ae_reference_threshold_raw: float,
    config: EnsembleConfig,
) -> dict[str, float | str]:
    """Converte o erro bruto do AE em faixas operacionais."""
    reference = max(float(ae_reference_threshold_raw), 1e-6)
    low_threshold = max(reference * float(config.ae_low_ratio), 1e-6)
    medium_threshold = max(reference * float(config.ae_medium_ratio), low_threshold + 1e-6)
    high_threshold = max(reference * float(config.ae_high_ratio), medium_threshold + 1e-6)

    raw_score = max(float(ae_score_raw), 0.0)
    normalized_score = clamp_confidence(float(ae_score_norm))
    threshold_ratio = raw_score / reference

    if int(ae_pred) == 1 and (
        normalized_score >= float(config.strong_attack_threshold)
        or threshold_ratio >= 1.50
        or raw_score >= high_threshold
    ):
        band = "high"
    elif int(ae_pred) == 1 or (
        normalized_score >= float(config.moderate_attack_threshold)
        and threshold_ratio >= 0.75
    ) or raw_score >= medium_threshold:
        band = "medium"
    else:
        band = "low"

    if int(ae_pred) == 1:
        risk_score = clamp_confidence(
            max(
                normalized_score,
                min(threshold_ratio, 1.0),
            )
        )
    else:
        risk_score = clamp_confidence(
            max(
                normalized_score * 0.25,
                min(threshold_ratio, 1.0) * 0.15,
            )
        )

    return {
        "band": band,
        "risk_score": clamp_confidence(risk_score),
        "reference_threshold_raw": reference,
        "low_threshold_raw": float(low_threshold),
        "medium_threshold_raw": float(medium_threshold),
        "high_threshold_raw": float(high_threshold),
    }


def _compute_if_runtime_signals(
    *,
    if_pred: int,
    if_score_raw: float,
    if_score_norm: float,
    config: EnsembleConfig,
) -> dict[str, float]:
    """
    Calcula os sinais operacionais do IF.

    O IF segue presente, mas com peso reduzido. Ele atua mais como modulador
    de conflito do que como detector principal de ataque.
    """
    raw_score = float(if_score_raw)
    scale = max(float(config.if_alert_score_scale), 1e-6)
    centered_score = (raw_score - float(config.if_alert_score_center)) / scale
    base_alert_score = float(_sigmoid([centered_score])[0])
    if int(if_pred) == 1:
        alert_score = max(
            base_alert_score,
            float(config.if_alert_floor_when_predicted),
            clamp_confidence(if_score_norm),
        )
    else:
        alert_score = clamp_confidence(
            min(base_alert_score, clamp_confidence(if_score_norm)) * 0.25
        )
    stability_score = clamp_confidence(1.0 - alert_score)

    return {
        "pred": float(int(if_pred)),
        "alert_score": clamp_confidence(alert_score),
        "stability_score": stability_score,
    }


def compute_model_confidence(normalized_score: float, pred: int) -> float:
    """Calcula a confianca individual de um detector."""
    normalized_score = clamp_confidence(normalized_score)
    pred = 1 if int(pred) == 1 else 0
    return clamp_confidence(normalized_score if pred == 1 else 1.0 - normalized_score)


def _build_support_snapshot(
    *,
    if_output: dict[str, Any],
    ae_output: dict[str, Any],
    config: EnsembleConfig,
    ae_reference_threshold_raw: float,
) -> dict[str, Any]:
    """Monta todos os sinais do ensemble para uma unica amostra."""
    if_weight, ae_weight = _resolve_runtime_weights(config)

    ae_bands = _compute_ae_runtime_bands(
        ae_score_raw=float(ae_output["raw_score"]),
        ae_score_norm=float(ae_output["normalized_score"]),
        ae_pred=int(ae_output["pred"]),
        ae_reference_threshold_raw=ae_reference_threshold_raw,
        config=config,
    )
    if_runtime = _compute_if_runtime_signals(
        if_pred=int(if_output["pred"]),
        if_score_raw=float(if_output["raw_score"]),
        if_score_norm=float(if_output["normalized_score"]),
        config=config,
    )

    agreement_score = clamp_confidence(
        min(ae_bands["risk_score"], if_runtime["alert_score"])
        if int(if_output["pred"]) == 1 and int(ae_output["pred"]) == 1
        else 0.0
    )

    # O conflito do IF so pesa de verdade quando o AE ainda esta em zona baixa
    # ou media. Em zona alta do AE, o IF nao pode derrubar a decisao sozinho.
    conflict_penalty = 0.0
    if int(if_output["pred"]) == 1 and ae_bands["band"] == "medium":
        conflict_penalty = float(config.if_conflict_weight) * 0.60
    elif int(if_output["pred"]) == 1 and ae_bands["band"] == "low":
        conflict_penalty = float(config.if_conflict_weight)

    band_support_boost = 0.0
    if ae_bands["band"] == "medium":
        band_support_boost = float(config.medium_band_support_boost)
    elif ae_bands["band"] == "high":
        band_support_boost = float(config.high_band_support_boost)

    support_score = clamp_confidence(
        (float(ae_bands["risk_score"]) * ae_weight)
        + (float(if_runtime["alert_score"]) * if_weight)
        + (float(agreement_score) * float(config.if_agreement_weight))
        + float(band_support_boost)
        - float(conflict_penalty)
    )
    threshold = float(resolve_threshold(config.threshold))
    allow_low_band_promotion = (
        config.profile_name == "balanced"
        and float(if_runtime["alert_score"]) >= float(config.strong_attack_threshold)
    )
    support_pred = int(
        support_score >= threshold
        and (ae_bands["band"] != "low" or allow_low_band_promotion)
    )

    return {
        "pred": support_pred,
        "score": support_score,
        "threshold": threshold,
        "runtime_profile": str(config.profile_name),
        "if_weight": float(if_weight),
        "ae_weight": float(ae_weight),
        "normalized_if_score": float(if_output["normalized_score"]),
        "normalized_ae_score": float(ae_output["normalized_score"]),
        "if_confidence": float(if_output["confidence"]),
        "ae_confidence": float(ae_output["confidence"]),
        "if_pred": int(if_output["pred"]),
        "ae_pred": int(ae_output["pred"]),
        "if_score_raw": float(if_output["raw_score"]),
        "ae_score_raw": float(ae_output["raw_score"]),
        "if_alert_score": float(if_runtime["alert_score"]),
        "if_stability_score": float(if_runtime["stability_score"]),
        "agreement_score": float(agreement_score),
        "conflict_penalty": float(conflict_penalty),
        "band_support_boost": float(band_support_boost),
        "ae_risk_score": float(ae_bands["risk_score"]),
        "ae_risk_band": str(ae_bands["band"]),
        "ae_reference_threshold_raw": float(ae_bands["reference_threshold_raw"]),
        "ae_low_threshold_raw": float(ae_bands["low_threshold_raw"]),
        "ae_medium_threshold_raw": float(ae_bands["medium_threshold_raw"]),
        "ae_high_threshold_raw": float(ae_bands["high_threshold_raw"]),
    }


def to_decision_config(config: EnsembleConfig | None = None) -> DecisionConfig:
    """Converte a configuracao do ensemble para o decision engine."""
    config = config or resolve_ensemble_config()
    return resolve_config(
        DecisionConfig(
            profile_name=str(config.profile_name),
            prioritize_recall=bool(config.prioritize_recall),
            prioritize_precision=bool(config.prioritize_precision),
            if_weight=min(float(config.if_weight), 0.20),
            ae_weight=max(float(config.ae_weight), 0.80),
            heuristic_weight=min(float(config.heuristic_weight), 0.15),
            strong_attack_threshold=float(config.strong_attack_threshold),
            moderate_attack_threshold=float(config.moderate_attack_threshold),
            ae_low_ratio=float(config.ae_low_ratio),
            ae_medium_ratio=float(config.ae_medium_ratio),
            ae_high_ratio=float(config.ae_high_ratio),
            contextual_heuristic_boost=(
                0.03 if str(config.profile_name) == "balanced" else 0.0
            ),
            conflict_penalty=float(config.if_conflict_weight),
            agreement_boost=max(0.06, float(config.if_agreement_weight)),
        )
    )


def describe_runtime_profile(
    *,
    runtime_profile: str | None = None,
    config: EnsembleConfig | None = None,
) -> dict[str, Any]:
    """Explicita os parametros efetivos usados em runtime por perfil."""
    effective_config = resolve_ensemble_config(config, runtime_profile=runtime_profile)
    decision_config = to_decision_config(effective_config)
    return {
        "profile_name": str(effective_config.profile_name),
        "ensemble_config": asdict(effective_config),
        "decision_config": asdict(decision_config),
    }


def build_ensemble_config_from_scores(
    scores_if,
    scores_ae,
    *,
    if_weight: float,
    ae_weight: float,
    threshold: float,
    ae_reference_threshold_raw: float | None = None,
) -> EnsembleConfig:
    """Constroi a configuracao persistida usando os scores observados."""
    scores_if_array = orient_isolation_forest_scores(scores_if)
    scores_ae_array = _sanitize_scores(scores_ae)

    return EnsembleConfig(
        if_weight=float(if_weight),
        ae_weight=float(ae_weight),
        heuristic_weight=DEFAULT_ENSEMBLE_CONFIG.heuristic_weight,
        threshold=float(threshold),
        prioritize_recall=DEFAULT_ENSEMBLE_CONFIG.prioritize_recall,
        prioritize_precision=DEFAULT_ENSEMBLE_CONFIG.prioritize_precision,
        strong_attack_threshold=DEFAULT_ENSEMBLE_CONFIG.strong_attack_threshold,
        moderate_attack_threshold=DEFAULT_ENSEMBLE_CONFIG.moderate_attack_threshold,
        ae_low_ratio=DEFAULT_ENSEMBLE_CONFIG.ae_low_ratio,
        ae_medium_ratio=DEFAULT_ENSEMBLE_CONFIG.ae_medium_ratio,
        ae_high_ratio=DEFAULT_ENSEMBLE_CONFIG.ae_high_ratio,
        if_conflict_weight=DEFAULT_ENSEMBLE_CONFIG.if_conflict_weight,
        if_agreement_weight=DEFAULT_ENSEMBLE_CONFIG.if_agreement_weight,
        if_score_min=float(np.min(scores_if_array)),
        if_score_max=float(np.max(scores_if_array)),
        ae_score_min=float(np.min(scores_ae_array)),
        ae_score_max=float(np.max(scores_ae_array)),
        ae_reference_threshold_raw=(
            float(ae_reference_threshold_raw)
            if ae_reference_threshold_raw is not None
            else None
        ),
    )


def compute_ensemble_components(
    scores_if,
    scores_ae,
    config: EnsembleConfig,
) -> dict[str, Any]:
    """
    Mantem uma camada vetorizada de suporte para treino e avaliacao.
    """
    oriented_if_scores = orient_isolation_forest_scores(scores_if)
    transformed_ae_scores = transform_autoencoder_scores(scores_ae)
    normalized_if_scores = normalize_scores(
        oriented_if_scores,
        score_min=config.if_score_min,
        score_max=config.if_score_max,
    )
    normalized_ae_scores = normalize_scores(
        transformed_ae_scores,
        score_min=(
            float(transform_autoencoder_scores([config.ae_score_min])[0])
            if config.ae_score_min is not None
            else None
        ),
        score_max=(
            float(transform_autoencoder_scores([config.ae_score_max])[0])
            if config.ae_score_max is not None
            else None
        ),
    )

    if_weight, ae_weight = _resolve_runtime_weights(config)
    support_scores = clamp_confidence(
        (normalized_ae_scores * ae_weight) + (normalized_if_scores * if_weight)
    )
    threshold = resolve_threshold(config.threshold)
    support_predictions = [1 if score >= threshold else 0 for score in support_scores]

    summarize_scores("Isolation Forest score normalizado", normalized_if_scores)
    summarize_scores("Autoencoder score normalizado", normalized_ae_scores)
    summarize_scores("Ensemble support_score", support_scores)

    return {
        "threshold": threshold,
        "if_scores_normalized": normalized_if_scores,
        "ae_scores_normalized": normalized_ae_scores,
        "support_scores": support_scores,
        "support_predictions": support_predictions,
    }


def compute_ensemble_scores(
    scores_if,
    scores_ae,
    config: EnsembleConfig,
) -> np.ndarray:
    """Mantem compatibilidade com a interface antiga de score continuo."""
    components = compute_ensemble_components(scores_if, scores_ae, config)
    return np.asarray(components["support_scores"], dtype=float)


def run_ensemble_decision(
    *,
    if_pred: int,
    if_score_raw: float,
    ae_pred: int,
    ae_score_raw: float,
    heuristic_pred: bool,
    heuristic_confidence: float,
    heuristic_attack_type: str,
    heuristic_reason: str,
    config: EnsembleConfig | None = None,
    ae_threshold_raw: float | None = None,
    runtime_profile: str | None = None,
) -> dict[str, Any]:
    """
    Executa o fluxo final do ensemble para uma unica amostra.
    """
    config = resolve_ensemble_config(config, runtime_profile=runtime_profile)
    ae_reference_threshold_raw = (
        float(ae_threshold_raw)
        if ae_threshold_raw is not None
        else _resolve_ae_reference_threshold(config)
    )

    if_score_norm = float(
        normalize_scores(
            orient_isolation_forest_scores([if_score_raw]),
            score_min=config.if_score_min,
            score_max=config.if_score_max,
        )[0]
    )
    ae_score_norm = float(
        normalize_scores(
            transform_autoencoder_scores([ae_score_raw]),
            score_min=(
                float(transform_autoencoder_scores([config.ae_score_min])[0])
                if config.ae_score_min is not None
                else None
            ),
            score_max=(
                float(transform_autoencoder_scores([config.ae_score_max])[0])
                if config.ae_score_max is not None
                else None
            ),
        )[0]
    )

    if_output = {
        "pred": int(if_pred),
        "raw_score": float(if_score_raw),
        "normalized_score": if_score_norm,
        "confidence": compute_model_confidence(if_score_norm, int(if_pred)),
    }
    ae_output = {
        "pred": int(ae_pred),
        "raw_score": float(ae_score_raw),
        "normalized_score": ae_score_norm,
        "confidence": compute_model_confidence(ae_score_norm, int(ae_pred)),
    }
    snapshot = _build_support_snapshot(
        if_output=if_output,
        ae_output=ae_output,
        config=config,
        ae_reference_threshold_raw=ae_reference_threshold_raw,
    )

    print(
        "[INFO] Ensemble decision input: "
        f"if_score_raw={float(if_score_raw):.6f}, "
        f"ae_score_raw={float(ae_score_raw):.6f}, "
        f"ae_risk_band={snapshot['ae_risk_band']}, "
        f"support_score={snapshot['score']:.6f}."
    )

    result = make_decision(
        isolation_score=float(if_score_raw),
        isolation_prediction=int(if_pred),
        isolation_normalized_score=if_score_norm,
        isolation_confidence=float(if_output["confidence"]),
        autoencoder_score=float(ae_score_raw),
        autoencoder_threshold=float(snapshot["ae_reference_threshold_raw"]),
        autoencoder_prediction=int(ae_pred),
        autoencoder_normalized_score=ae_score_norm,
        autoencoder_confidence=float(ae_output["confidence"]),
        ensemble_score=float(snapshot["score"]),
        ensemble_prediction=int(snapshot["pred"]),
        heuristic_attack_type=str(heuristic_attack_type),
        heuristic_detected_attack=bool(heuristic_pred),
        heuristic_confidence=float(heuristic_confidence),
        heuristic_reason=str(heuristic_reason),
        ensemble_risk_band=str(snapshot["ae_risk_band"]),
        config=to_decision_config(config),
        runtime_profile=str(config.profile_name),
        prioritize_recall=bool(config.prioritize_recall),
        prioritize_precision=bool(config.prioritize_precision),
    )

    result["runtime_profile"] = str(config.profile_name)
    result["ensemble_support_score"] = float(snapshot["score"])
    result["ensemble_support_pred"] = int(snapshot["pred"])
    result["ensemble_threshold"] = float(snapshot["threshold"])
    result["ae_risk_band"] = str(snapshot["ae_risk_band"])
    return result


def train_all(X) -> None:
    """Treina os detectores e salva uma configuracao inicial do ensemble."""
    print(f"[INFO] Ensemble em treino com {describe_active_features()}.")
    detection_bundle = train_model(X, config=DEFAULT_ISOLATION_FOREST_CONFIG)
    autoencoder_bundle = train_autoencoder(X, scaler=detection_bundle["scaler"])

    _, scores_if = predict(X, bundle=detection_bundle)
    _, scores_ae = predict_autoencoder(X, bundle=autoencoder_bundle)

    config = build_ensemble_config_from_scores(
        scores_if,
        scores_ae,
        if_weight=DEFAULT_ENSEMBLE_CONFIG.if_weight,
        ae_weight=DEFAULT_ENSEMBLE_CONFIG.ae_weight,
        threshold=DEFAULT_ENSEMBLE_CONFIG.threshold,
        ae_reference_threshold_raw=float(autoencoder_bundle["threshold"]),
    )
    save_ensemble_config(config)


def load_all_models() -> None:
    """Carrega os artefatos principais do projeto."""
    print(f"[INFO] Carregando modelos com {describe_active_features()}.")
    load_model()
    load_autoencoder()
    load_ensemble_config()


def predict_ensemble_details(
    X,
    *,
    config: EnsembleConfig | None = None,
    detection_bundle: dict[str, Any] | None = None,
    autoencoder_bundle: dict[str, Any] | None = None,
    runtime_profile: str | None = None,
) -> list[dict[str, Any]]:
    """
    Retorna a camada de suporte do ensemble com detalhes por amostra.
    """
    config = resolve_ensemble_config(config, runtime_profile=runtime_profile)
    detection_bundle = detection_bundle or get_loaded_detection_bundle()
    autoencoder_bundle = autoencoder_bundle or get_loaded_autoencoder_bundle()

    if_outputs = predict_with_details(X, bundle=detection_bundle)
    ae_outputs = predict_autoencoder_with_details(X, bundle=autoencoder_bundle)
    ae_reference_threshold_raw = _resolve_ae_reference_threshold(
        config,
        autoencoder_bundle=autoencoder_bundle,
    )

    outputs: list[dict[str, Any]] = []
    for if_output, ae_output in zip(if_outputs, ae_outputs):
        snapshot = _build_support_snapshot(
            if_output=if_output,
            ae_output=ae_output,
            config=config,
            ae_reference_threshold_raw=ae_reference_threshold_raw,
        )
        outputs.append(snapshot)

    return outputs


def predict_all(
    X,
    *,
    config: EnsembleConfig | None = None,
    detection_bundle: dict[str, Any] | None = None,
    autoencoder_bundle: dict[str, Any] | None = None,
    runtime_profile: str | None = None,
) -> Tuple[list, list]:
    """Interface legada do projeto: retorna predicoes e support_scores."""
    outputs = predict_ensemble_details(
        X,
        config=config,
        detection_bundle=detection_bundle,
        autoencoder_bundle=autoencoder_bundle,
        runtime_profile=runtime_profile,
    )
    predictions = [int(item["pred"]) for item in outputs]
    scores = [float(item["score"]) for item in outputs]
    return predictions, scores


def evaluate_ensemble(
    X,
    y_true,
    *,
    detection_bundle: dict[str, Any],
    autoencoder_bundle: dict[str, Any],
    config: EnsembleConfig,
    runtime_profile: str | None = None,
) -> dict[str, Any]:
    """Avalia a camada de suporte do ensemble em um conjunto rotulado."""
    outputs = predict_ensemble_details(
        X,
        config=config,
        detection_bundle=detection_bundle,
        autoencoder_bundle=autoencoder_bundle,
        runtime_profile=runtime_profile,
    )
    predictions = [int(item["pred"]) for item in outputs]
    scores = np.asarray([float(item["score"]) for item in outputs], dtype=float)
    metrics = compute_binary_metrics(y_true, predictions)
    return {
        "config": asdict(config),
        "metrics": metrics,
        "score_summary": {
            "min": float(np.min(scores)),
            "max": float(np.max(scores)),
            "mean": float(np.mean(scores)),
        },
    }


def _ensemble_candidate_key(
    result: dict[str, Any],
    *,
    prioritize_recall: bool,
) -> tuple[float, float, float, float]:
    """Ordena candidatos do tuning priorizando recall sem ignorar F1."""
    metrics = result["metrics"]
    recall = float(metrics["recall"])
    f1_score = float(metrics["f1_score"])
    false_positive_rate = float(metrics["false_positive_rate"])
    precision = float(metrics["precision"])
    if prioritize_recall:
        return (recall, f1_score, -false_positive_rate, precision)
    return (f1_score, recall, -false_positive_rate, precision)


def tune_ensemble(
    X_validation,
    y_validation,
    *,
    detection_bundle: dict[str, Any],
    autoencoder_bundle: dict[str, Any],
    weight_options: tuple[tuple[float, float], ...] = DEFAULT_WEIGHT_OPTIONS,
    threshold_options: tuple[float, ...] = DEFAULT_THRESHOLD_OPTIONS,
    prioritize_recall: bool = DEFAULT_DECISION_CONFIG.prioritize_recall,
) -> dict[str, Any]:
    """Executa tuning apenas da camada de combinacao, sem re-treinar detectores."""
    _, scores_if = predict(X_validation, bundle=detection_bundle)
    _, scores_ae = predict_autoencoder(X_validation, bundle=autoencoder_bundle)

    results: list[dict[str, Any]] = []
    for (if_weight, ae_weight), threshold in product(weight_options, threshold_options):
        config = build_ensemble_config_from_scores(
            scores_if,
            scores_ae,
            if_weight=if_weight,
            ae_weight=ae_weight,
            threshold=threshold,
            ae_reference_threshold_raw=float(autoencoder_bundle["threshold"]),
        )
        result = evaluate_ensemble(
            X_validation,
            y_validation,
            detection_bundle=detection_bundle,
            autoencoder_bundle=autoencoder_bundle,
            config=config,
        )
        results.append(result)

    best_result = max(
        results,
        key=lambda item: _ensemble_candidate_key(
            item,
            prioritize_recall=prioritize_recall,
        ),
    )
    best_config = EnsembleConfig(**best_result["config"])
    print(
        "[INFO] Melhor configuracao do ensemble: "
        f"{best_result['config']} com metricas={best_result['metrics']}"
    )

    return {
        "best_config": best_config,
        "best_result": best_result,
        "results": results,
        "validation_if_scores": [float(value) for value in scores_if],
        "validation_ae_scores": [float(value) for value in scores_ae],
    }
