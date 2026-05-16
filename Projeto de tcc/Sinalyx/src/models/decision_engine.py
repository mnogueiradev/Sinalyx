"""
Motor de decisao final do Sinalyx.

Este modulo combina os sinais de:
- Isolation Forest
- Autoencoder
- Heuristica comportamental
- Ensemble de suporte

A estrategia e assimetrica:
- o Autoencoder define a zona principal de risco
- o Isolation Forest modula conflito e estabilidade
- a heuristica entra como contexto, nao como decisora sozinha
- o ensemble continua agregando risco, mas a resposta final sai daqui
"""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass
from typing import Any

import numpy as np


@dataclass(frozen=True)
class DecisionConfig:
    """
    Configuracao central do motor de decisao.
    """

    profile_name: str = "balanced"
    prioritize_recall: bool = True
    prioritize_precision: bool = False
    if_weight: float = 0.10
    ae_weight: float = 0.90
    heuristic_weight: float = 0.10
    strong_attack_threshold: float = 0.72
    moderate_attack_threshold: float = 0.55
    ae_low_ratio: float = 0.24
    ae_medium_ratio: float = 0.32
    ae_high_ratio: float = 0.64
    supportive_heuristic_boost: float = 0.08
    contextual_heuristic_boost: float = 0.04
    suppressive_heuristic_penalty: float = 0.18
    agreement_boost: float = 0.06
    conflict_penalty: float = 0.08
    safe_negative_boost: float = 0.08


DEFAULT_DECISION_CONFIG = DecisionConfig()
PRIORITIZE_RECALL = DEFAULT_DECISION_CONFIG.prioritize_recall
PRIORITIZE_PRECISION = DEFAULT_DECISION_CONFIG.prioritize_precision
DEFAULT_RUNTIME_PROFILE = "balanced"
AVAILABLE_RUNTIME_PROFILES = {"balanced", "conservative"}

STANDARD_ATTACK_TYPES = {
    "normal",
    "port_scan",
    "brute_force",
    "ssh_suspicious",
    "syn_flood",
    "ddos",
    "unknown_anomaly",
}

ATTACK_TYPE_ALIASES = {
    "": "normal",
    "none": "normal",
    "anomalous_unknown": "unknown_anomaly",
    "unknown": "unknown_anomaly",
    "unknown_attack": "unknown_anomaly",
    "anomaly": "unknown_anomaly",
}

SUPPORTIVE_HEURISTIC_TYPES = {"unknown_anomaly", "ddos", "syn_flood"}
CONTEXTUAL_HEURISTIC_TYPES = {"port_scan", "brute_force", "ssh_suspicious"}
SUPPRESSIVE_HEURISTIC_TYPES = set()


def clamp_confidence(value: float, lower: float = 0.0, upper: float = 1.0) -> float:
    """Garante que scores e confiancas fiquem no intervalo esperado."""
    return float(np.clip(float(value), lower, upper))


def _safe_bool(value: Any) -> bool:
    """Converte qualquer entrada para bool."""
    return bool(value)


def _safe_int(value: Any) -> int:
    """Converte qualquer entrada para inteiro seguro."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _safe_float(value: Any, default: float = 0.0) -> float:
    """Converte qualquer entrada para float resiliente."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return float(default)


def _normalize_weights(config: DecisionConfig) -> tuple[float, float, float]:
    """Normaliza os pesos internos da decisao."""
    raw = np.asarray(
        [
            max(_safe_float(config.if_weight, 0.0), 0.0),
            max(_safe_float(config.ae_weight, 0.0), 0.0),
            max(_safe_float(config.heuristic_weight, 0.0), 0.0),
        ],
        dtype=float,
    )
    total = float(np.sum(raw))
    if total <= 0:
        return (0.10, 0.80, 0.10)
    normalized = raw / total
    return float(normalized[0]), float(normalized[1]), float(normalized[2])


def resolve_runtime_profile(profile: str | None = None) -> str:
    """Resolve o perfil operacional ativo do sistema."""
    candidate = str(
        profile or os.getenv("SINALYX_RUNTIME_PROFILE", DEFAULT_RUNTIME_PROFILE)
    ).strip().lower()
    if candidate in AVAILABLE_RUNTIME_PROFILES:
        return candidate
    return DEFAULT_RUNTIME_PROFILE


def _apply_profile_defaults(payload: dict[str, Any], profile_name: str) -> dict[str, Any]:
    """Aplica defaults por perfil sem quebrar configs persistidas antigas."""
    updated = dict(payload)
    updated["profile_name"] = profile_name

    if profile_name == "conservative":
        updated["if_weight"] = min(max(float(updated["if_weight"]), 0.10), 0.20)
        updated["ae_weight"] = max(float(updated["ae_weight"]), 0.88)
        updated["heuristic_weight"] = min(max(float(updated["heuristic_weight"]), 0.08), 0.15)
        updated["strong_attack_threshold"] = max(float(updated["strong_attack_threshold"]), 0.72)
        updated["moderate_attack_threshold"] = max(
            float(updated["moderate_attack_threshold"]),
            0.55,
        )
        updated["supportive_heuristic_boost"] = max(
            float(updated["supportive_heuristic_boost"]),
            0.08,
        )
        updated["contextual_heuristic_boost"] = 0.0
        updated["suppressive_heuristic_penalty"] = max(
            float(updated["suppressive_heuristic_penalty"]),
            0.18,
        )
        updated["agreement_boost"] = max(float(updated["agreement_boost"]), 0.06)
        updated["conflict_penalty"] = max(float(updated["conflict_penalty"]), 0.08)
        updated["safe_negative_boost"] = max(float(updated["safe_negative_boost"]), 0.08)
        return updated

    updated["if_weight"] = max(float(updated["if_weight"]), 0.14)
    updated["ae_weight"] = max(float(updated["ae_weight"]), 0.82)
    updated["heuristic_weight"] = max(float(updated["heuristic_weight"]), 0.10)
    updated["strong_attack_threshold"] = min(
        max(float(updated["strong_attack_threshold"]), 0.62),
        0.68,
    )
    updated["moderate_attack_threshold"] = min(
        max(float(updated["moderate_attack_threshold"]), 0.44),
        0.50,
    )
    updated["supportive_heuristic_boost"] = max(
        float(updated["supportive_heuristic_boost"]),
        0.10,
    )
    updated["contextual_heuristic_boost"] = max(
        float(updated.get("contextual_heuristic_boost", 0.0)),
        0.03,
    )
    updated["suppressive_heuristic_penalty"] = min(
        max(float(updated["suppressive_heuristic_penalty"]), 0.00),
        0.04,
    )
    updated["agreement_boost"] = max(float(updated["agreement_boost"]), 0.08)
    updated["conflict_penalty"] = min(max(float(updated["conflict_penalty"]), 0.04), 0.08)
    updated["safe_negative_boost"] = min(max(float(updated["safe_negative_boost"]), 0.02), 0.05)
    return updated


def resolve_config(
    config: DecisionConfig | dict[str, Any] | None = None,
    *,
    profile: str | None = None,
    prioritize_recall: bool | None = None,
    prioritize_precision: bool | None = None,
) -> DecisionConfig:
    """Resolve a configuracao final do motor."""
    if config is None:
        resolved = DEFAULT_DECISION_CONFIG
    elif isinstance(config, DecisionConfig):
        resolved = config
    else:
        resolved = DecisionConfig(**config)

    payload = _apply_profile_defaults(
        asdict(resolved),
        resolve_runtime_profile(profile or getattr(resolved, "profile_name", None)),
    )
    if prioritize_recall is not None:
        payload["prioritize_recall"] = bool(prioritize_recall)
    if prioritize_precision is not None:
        payload["prioritize_precision"] = bool(prioritize_precision)

    payload["profile_name"] = resolve_runtime_profile(payload.get("profile_name"))
    payload["if_weight"] = min(max(float(payload["if_weight"]), 0.05), 0.20)
    payload["ae_weight"] = max(float(payload["ae_weight"]), 0.75)
    payload["heuristic_weight"] = min(max(float(payload["heuristic_weight"]), 0.05), 0.15)
    payload["strong_attack_threshold"] = min(
        max(float(payload["strong_attack_threshold"]), 0.60),
        0.80,
    )
    payload["moderate_attack_threshold"] = min(
        max(float(payload["moderate_attack_threshold"]), 0.42),
        0.65,
    )
    payload["supportive_heuristic_boost"] = min(
        max(float(payload["supportive_heuristic_boost"]), 0.04),
        0.12,
    )
    payload["contextual_heuristic_boost"] = min(
        max(float(payload.get("contextual_heuristic_boost", 0.0)), 0.0),
        0.08,
    )
    payload["suppressive_heuristic_penalty"] = min(
        max(float(payload["suppressive_heuristic_penalty"]), 0.0),
        0.22,
    )
    payload["agreement_boost"] = min(max(float(payload["agreement_boost"]), 0.03), 0.10)
    payload["conflict_penalty"] = min(max(float(payload["conflict_penalty"]), 0.05), 0.12)

    if payload["prioritize_precision"]:
        payload["strong_attack_threshold"] = max(
            float(payload["strong_attack_threshold"]),
            0.76,
        )
        payload["moderate_attack_threshold"] = max(
            float(payload["moderate_attack_threshold"]),
            0.58,
        )
        if payload["profile_name"] == "conservative":
            payload["suppressive_heuristic_penalty"] = max(
                float(payload["suppressive_heuristic_penalty"]),
                0.18,
            )

    return DecisionConfig(**payload)


def _normalize_attack_type(value: str | None) -> str:
    """Padroniza o tipo heuristico."""
    normalized = str(value or "normal").strip().lower()
    normalized = ATTACK_TYPE_ALIASES.get(normalized, normalized or "normal")
    if normalized in STANDARD_ATTACK_TYPES:
        return normalized
    if normalized == "normal":
        return normalized
    return "unknown_anomaly"


def _resolve_legacy_attack_type(attack_type: str) -> str:
    """Mantem o alias legado para consumidores antigos."""
    if attack_type == "unknown_anomaly":
        return "anomalous_unknown"
    return attack_type


def resolve_attack_type(*, is_attack: bool, heuristic_attack_type: str | None) -> str:
    """Resolve o tipo final mostrado ao usuario."""
    attack_type = _normalize_attack_type(heuristic_attack_type)
    if not is_attack:
        return "normal"
    if attack_type not in {"", "normal", "none"}:
        return attack_type
    return "unknown_anomaly"


def resolve_final_label(is_attack: bool) -> str:
    """Traduz a decisao booleana para o rotulo final padronizado."""
    return "anomaly" if bool(is_attack) else "normal"


def _resolve_normalized_score(
    *,
    pred: int,
    normalized_score: float | None,
    confidence: float | None,
) -> float:
    """Resolve score normalizado quando o chamador so conhece a confianca."""
    if normalized_score is not None:
        return clamp_confidence(normalized_score)
    if confidence is None:
        return 1.0 if int(pred) == 1 else 0.0
    confidence = clamp_confidence(confidence)
    return confidence if int(pred) == 1 else 1.0 - confidence


def _resolve_confidence(
    *,
    pred: int,
    normalized_score: float,
    confidence: float | None,
) -> float:
    """Resolve a confianca individual com fallback seguro."""
    if confidence is not None:
        return clamp_confidence(confidence)
    pred = 1 if int(pred) == 1 else 0
    return clamp_confidence(normalized_score if pred == 1 else 1.0 - normalized_score)


def compute_risk_level(confidence: float, *, is_attack: bool) -> str:
    """Traduz a confianca em nivel de risco."""
    confidence = clamp_confidence(confidence)
    if is_attack:
        if confidence >= 0.78:
            return "high"
        if confidence >= 0.55:
            return "medium"
        return "low"
    if confidence >= 0.70:
        return "low"
    return "medium"


def compute_heuristic_context(
    *,
    heuristic_pred: bool,
    heuristic_confidence: float,
    heuristic_attack_type: str,
    config: DecisionConfig,
) -> dict[str, Any]:
    """
    Traduz a heuristica em contexto operacional.
    """
    attack_type = _normalize_attack_type(heuristic_attack_type)
    confidence = clamp_confidence(heuristic_confidence)

    if not heuristic_pred and attack_type == "normal":
        return {
            "label": "neutral",
            "score": 0.0,
            "attack_type": attack_type,
            "reason_fragment": "A heuristica nao detectou ataque e permaneceu neutra.",
        }

    if attack_type in SUPPORTIVE_HEURISTIC_TYPES and heuristic_pred:
        boost = config.supportive_heuristic_boost * (0.65 if attack_type == "ddos" else 1.0)
        return {
            "label": "supportive",
            "score": clamp_confidence(confidence * boost),
            "attack_type": attack_type,
            "reason_fragment": "A heuristica reforcou o contexto de ataque.",
        }

    if attack_type in CONTEXTUAL_HEURISTIC_TYPES and heuristic_pred:
        if config.profile_name == "conservative":
            if attack_type == "port_scan":
                penalty = config.suppressive_heuristic_penalty
            else:
                penalty = config.suppressive_heuristic_penalty * 0.85
            return {
                "label": "suppressive",
                "score": -clamp_confidence(max(confidence, 0.70) * penalty),
                "attack_type": attack_type,
                "reason_fragment": (
                    "A heuristica trouxe um contexto com historico operacional de "
                    "alto falso positivo neste perfil conservador."
                ),
            }

        contextual_boost = config.contextual_heuristic_boost
        if attack_type == "brute_force":
            contextual_boost *= 0.85
        return {
            "label": "contextual",
            "score": clamp_confidence(max(confidence, 0.45) * contextual_boost),
            "attack_type": attack_type,
            "reason_fragment": (
                "A heuristica sugeriu uma familia de ataque e entrou apenas como "
                "contexto interpretativo, sem bloquear o alerta."
            ),
        }

    return {
        "label": "neutral",
        "score": 0.0,
        "attack_type": attack_type,
        "reason_fragment": "A heuristica nao alterou o contexto da decisao.",
    }


def compute_ae_bands(
    *,
    ae_score_raw: float,
    ae_score_norm: float,
    ae_pred: int,
    ae_reference_threshold: float | None,
    config: DecisionConfig,
) -> dict[str, float | str]:
    """
    Converte o erro do AE em faixas de risco operacionais.
    """
    reference = max(_safe_float(ae_reference_threshold, 0.0), 1e-6)
    low_threshold = max(reference * config.ae_low_ratio, 1e-6)
    medium_threshold = max(reference * config.ae_medium_ratio, low_threshold + 1e-6)
    high_threshold = max(reference * config.ae_high_ratio, medium_threshold + 1e-6)

    raw_score = max(_safe_float(ae_score_raw), 0.0)
    normalized_score = clamp_confidence(_safe_float(ae_score_norm))
    threshold_ratio = raw_score / reference

    if (
        int(ae_pred) == 1
        and (
            normalized_score >= config.strong_attack_threshold
            or threshold_ratio >= 1.50
            or raw_score >= high_threshold
        )
    ):
        band = "high"
    elif (
        int(ae_pred) == 1
        or (
            normalized_score >= config.moderate_attack_threshold
            and threshold_ratio >= 0.75
        )
        or raw_score >= medium_threshold
    ):
        band = "medium"
    else:
        band = "low"

    return {
        "band": band,
        "reference_threshold": float(reference),
        "low_threshold": float(low_threshold),
        "medium_threshold": float(medium_threshold),
        "high_threshold": float(high_threshold),
        "threshold_ratio": float(threshold_ratio),
        "normalized_score": float(normalized_score),
    }


def compute_detector_attack_signal(
    *,
    pred: int,
    normalized_score: float,
    detector_name: str,
) -> float:
    """
    Converte a saida de cada detector em evidencia orientada a ataque.

    `confidence` do detector representa confianca na classe prevista, entao
    nao pode ser usado diretamente para risco de ataque quando o detector
    previu `normal`. Esta funcao corrige isso.
    """
    normalized = clamp_confidence(normalized_score)

    if int(pred) == 1:
        floor = 0.55 if detector_name == "if" else 0.60
        return clamp_confidence(max(normalized, floor))

    if detector_name == "if":
        return clamp_confidence(max(normalized - 0.85, 0.0) * 1.50)

    return clamp_confidence(normalized * 0.25)


def compute_heuristic_attack_signal(
    *,
    heuristic_pred: bool,
    heuristic_confidence: float,
    heuristic_attack_type: str,
) -> float:
    """
    Converte a heuristica em uma evidencia positiva coerente com ataque.
    """
    if not heuristic_pred:
        return 0.0

    attack_type = _normalize_attack_type(heuristic_attack_type)
    confidence = clamp_confidence(heuristic_confidence)

    if attack_type in {"syn_flood", "ddos"}:
        return clamp_confidence(max(confidence * 0.92, 0.65))
    if attack_type == "port_scan":
        return clamp_confidence(max(confidence * 0.88, 0.60))
    if attack_type == "brute_force":
        return clamp_confidence(max(confidence * 0.84, 0.56))
    if attack_type == "ssh_suspicious":
        return clamp_confidence(max(confidence * 0.78, 0.45))
    return clamp_confidence(confidence * 0.70)


def resolve_heuristic_signature_override(
    *,
    heuristic_pred: bool,
    heuristic_confidence: float,
    heuristic_attack_type: str,
    attack_support: float,
    config: DecisionConfig,
) -> dict[str, str] | None:
    """
    Permite promover assinaturas heuristicas muito claras de pfSense.
    """
    if not heuristic_pred:
        return None

    attack_type = _normalize_attack_type(heuristic_attack_type)
    confidence = clamp_confidence(heuristic_confidence)
    min_support = 0.04 if config.profile_name == "balanced" else 0.08
    if attack_support < min_support:
        return None

    if attack_type in {"syn_flood", "ddos"}:
        threshold = 0.84 if config.profile_name == "balanced" else 0.90
        if confidence >= threshold:
            return {
                "agreement_level": "contextual_support",
                "decision_source": "heuristic_signature",
                "decision_reason": (
                    "A heuristica reconheceu uma assinatura forte de flood em logs reais do pfSense e preservou o alerta."
                ),
            }

    if attack_type == "port_scan":
        threshold = 0.86 if config.profile_name == "balanced" else 0.90
        if confidence >= threshold:
            return {
                "agreement_level": "contextual_support",
                "decision_source": "heuristic_signature",
                "decision_reason": (
                    "A heuristica reconheceu um padrao forte de port scan usando portas, flags e repeticao de conexoes do pfSense."
                ),
            }

    if attack_type == "brute_force":
        threshold = 0.80 if config.profile_name == "balanced" else 0.86
        if confidence >= threshold:
            return {
                "agreement_level": "contextual_support",
                "decision_source": "heuristic_signature",
                "decision_reason": (
                    "A heuristica reconheceu repeticao bloqueada em porta sensivel do pfSense e promoveu o caso como brute force."
                ),
            }

    if attack_type == "ssh_suspicious":
        threshold = 0.72 if config.profile_name == "balanced" else 0.78
        if confidence >= threshold:
            return {
                "agreement_level": "contextual_support",
                "decision_source": "heuristic_signature",
                "decision_reason": (
                    "A heuristica reconheceu atividade SSH suspeita e preservou esse contexto na decisao final."
                ),
            }

    return None


def compute_attack_support(
    *,
    if_attack_signal: float,
    ae_attack_signal: float,
    ensemble_support_score: float | None,
    heuristic_context_score: float,
    config: DecisionConfig,
) -> float:
    """Calcula o suporte bruto para a classe ataque."""
    if_weight, ae_weight, _ = _normalize_weights(config)
    if ensemble_support_score is not None:
        support = clamp_confidence(ensemble_support_score)
    else:
        support = clamp_confidence(
            (clamp_confidence(ae_attack_signal) * ae_weight)
            + (clamp_confidence(if_attack_signal) * if_weight)
        )
    support += heuristic_context_score
    return clamp_confidence(support)


def compute_negative_support(
    *,
    attack_support: float,
    if_confidence: float,
    ae_confidence: float,
    heuristic_context_label: str,
    config: DecisionConfig,
) -> float:
    """Calcula o suporte bruto para a classe normal."""
    support = 1.0 - clamp_confidence(attack_support)
    if heuristic_context_label == "suppressive":
        support += config.safe_negative_boost * 0.50
    support += max(clamp_confidence(if_confidence), clamp_confidence(ae_confidence)) * 0.05
    return clamp_confidence(support)


def compute_final_confidence(
    *,
    is_attack: bool,
    attack_support: float,
    negative_support: float,
    agreement_level: str,
    if_attack_signal: float,
    ae_attack_signal: float,
    heuristic_attack_signal: float,
    if_confidence: float,
    ae_confidence: float,
    heuristic_context_score: float,
    config: DecisionConfig,
) -> float:
    """Calcula a confianca final da decisao."""
    if is_attack:
        confidence = max(
            attack_support,
            clamp_confidence(if_attack_signal),
            clamp_confidence(ae_attack_signal),
            clamp_confidence(heuristic_attack_signal),
        )
        if agreement_level == "full_agreement":
            confidence += config.agreement_boost
        elif agreement_level == "contextual_agreement":
            confidence += config.agreement_boost * 0.50
        elif agreement_level == "contextual_support":
            confidence += config.agreement_boost * 0.35
        elif agreement_level == "ae_primary":
            confidence += config.agreement_boost * 0.25
    else:
        confidence = max(
            negative_support,
            clamp_confidence((if_confidence + ae_confidence) / 2.0),
        )
        if agreement_level == "full_agreement_negative":
            confidence += config.safe_negative_boost
        elif agreement_level == "suppressed_by_context":
            confidence += config.safe_negative_boost * 0.50

    if heuristic_context_score < 0 and is_attack:
        confidence += heuristic_context_score * 0.50
    return clamp_confidence(confidence)


def _resolve_conflict_winner(
    *,
    is_attack: bool,
    decision_source: str,
    if_pred: int,
    ae_pred: int,
    heuristic_context_label: str,
) -> str:
    """Explica quem mais pesou no conflito."""
    if decision_source == "if+ae":
        return "if+ae"
    if decision_source.startswith("ae_"):
        return "ae_primary"
    if decision_source in {
        "ensemble_support",
        "heuristic_guided_attack",
        "contextual_attack",
        "heuristic_signature",
    }:
        return "contextual_support"
    if decision_source == "suppressed_by_context":
        return "heuristic_filter"
    if not is_attack and if_pred == 1 and ae_pred == 0:
        return "if_filtered"
    if not is_attack and ae_pred == 1 and heuristic_context_label == "suppressive":
        return "heuristic_filter"
    return "safe_negative"


def _build_result(
    *,
    is_attack: bool,
    agreement_level: str,
    decision_source: str,
    decision_reason: str,
    if_pred: int,
    ae_pred: int,
    heuristic_pred: bool,
    if_confidence: float,
    ae_confidence: float,
    heuristic_confidence: float,
    if_score_raw: float,
    ae_score_raw: float,
    if_score_norm: float,
    ae_score_norm: float,
    heuristic_attack_type: str,
    heuristic_reason: str,
    heuristic_context_label: str,
    heuristic_context_score: float,
    ensemble_support_score: float | None,
    ensemble_pred: int | None,
    ae_band: str,
    ae_reference_threshold: float | None,
    config: DecisionConfig,
) -> dict[str, Any]:
    """Monta o payload final do motor de decisao."""
    if_attack_signal = compute_detector_attack_signal(
        pred=if_pred,
        normalized_score=if_score_norm,
        detector_name="if",
    )
    ae_attack_signal = compute_detector_attack_signal(
        pred=ae_pred,
        normalized_score=ae_score_norm,
        detector_name="ae",
    )
    heuristic_attack_signal = compute_heuristic_attack_signal(
        heuristic_pred=heuristic_pred,
        heuristic_confidence=heuristic_confidence,
        heuristic_attack_type=heuristic_attack_type,
    )
    attack_support = compute_attack_support(
        if_attack_signal=if_attack_signal,
        ae_attack_signal=ae_attack_signal,
        ensemble_support_score=ensemble_support_score,
        heuristic_context_score=heuristic_context_score,
        config=config,
    )
    negative_support = compute_negative_support(
        attack_support=attack_support,
        if_confidence=if_confidence,
        ae_confidence=ae_confidence,
        heuristic_context_label=heuristic_context_label,
        config=config,
    )
    confidence = compute_final_confidence(
        is_attack=is_attack,
        attack_support=attack_support,
        negative_support=negative_support,
        agreement_level=agreement_level,
        if_attack_signal=if_attack_signal,
        ae_attack_signal=ae_attack_signal,
        heuristic_attack_signal=heuristic_attack_signal,
        if_confidence=if_confidence,
        ae_confidence=ae_confidence,
        heuristic_context_score=heuristic_context_score,
        config=config,
    )

    standardized_attack_type = resolve_attack_type(
        is_attack=is_attack,
        heuristic_attack_type=heuristic_attack_type,
    )
    explanation = str(decision_reason or heuristic_reason or "")
    effective_ensemble_score = (
        clamp_confidence(ensemble_support_score)
        if ensemble_support_score is not None
        else attack_support
    )
    if ensemble_pred is None:
        effective_ensemble_pred = int(
            effective_ensemble_score >= clamp_confidence(config.moderate_attack_threshold)
        )
    else:
        effective_ensemble_pred = 1 if _safe_int(ensemble_pred) == 1 else 0

    conflict_winner = _resolve_conflict_winner(
        is_attack=is_attack,
        decision_source=decision_source,
        if_pred=if_pred,
        ae_pred=ae_pred,
        heuristic_context_label=heuristic_context_label,
    )

    return {
        "runtime_profile": str(config.profile_name),
        "is_anomaly": bool(is_attack),
        "final_label": resolve_final_label(is_attack),
        "attack_type": standardized_attack_type,
        "attack_type_legacy": _resolve_legacy_attack_type(standardized_attack_type),
        "risk_level": compute_risk_level(confidence, is_attack=is_attack),
        "confidence": confidence,
        "explanation": explanation,
        "isolation_score": float(if_score_raw),
        "isolation_prediction": int(if_pred),
        "isolation_confidence": clamp_confidence(if_confidence),
        "autoencoder_score": float(ae_score_raw),
        "autoencoder_prediction": int(ae_pred),
        "autoencoder_threshold": (
            _safe_float(ae_reference_threshold) if ae_reference_threshold is not None else None
        ),
        "autoencoder_confidence": clamp_confidence(ae_confidence),
        "ensemble_score": float(effective_ensemble_score),
        "ensemble_prediction": int(effective_ensemble_pred),
        "heuristic_attack_type": _normalize_attack_type(heuristic_attack_type),
        "heuristic_detected_attack": bool(heuristic_pred),
        "heuristic_confidence": clamp_confidence(heuristic_confidence),
        "heuristic_reason": str(heuristic_reason or ""),
        "is_attack": bool(is_attack),
        "decision_source": decision_source,
        "agreement_level": agreement_level,
        "if_pred": int(if_pred),
        "ae_pred": int(ae_pred),
        "heuristic_pred": bool(heuristic_pred),
        "if_confidence": clamp_confidence(if_confidence),
        "ae_confidence": clamp_confidence(ae_confidence),
        "if_score_raw": float(if_score_raw),
        "ae_score_raw": float(ae_score_raw),
        "if_score": float(if_score_raw),
        "ae_score": float(ae_score_raw),
        "if_score_norm": clamp_confidence(if_score_norm),
        "ae_score_norm": clamp_confidence(ae_score_norm),
        "decision_reason": explanation,
        "conflict_winner": conflict_winner,
        "base_attack_support": attack_support,
        "base_negative_support": negative_support,
        "ensemble_support_score": (
            clamp_confidence(ensemble_support_score)
            if ensemble_support_score is not None
            else None
        ),
        "ensemble_support_pred": int(effective_ensemble_pred),
        "ae_risk_band": ae_band,
        "ae_reference_threshold_raw": (
            _safe_float(ae_reference_threshold) if ae_reference_threshold is not None else None
        ),
    }


def make_decision(
    *,
    isolation_score: float,
    isolation_prediction: int,
    autoencoder_score: float,
    autoencoder_threshold: float | None = None,
    autoencoder_prediction: int = 0,
    ensemble_score: float | None = None,
    ensemble_prediction: int | None = None,
    heuristic_attack_type: str | None = None,
    heuristic_detected_attack: bool = False,
    heuristic_confidence: float = 0.0,
    heuristic_reason: str = "",
    isolation_normalized_score: float | None = None,
    isolation_confidence: float | None = None,
    autoencoder_normalized_score: float | None = None,
    autoencoder_confidence: float | None = None,
    ensemble_risk_band: str | None = None,
    features: dict[str, Any] | None = None,
    metadata: dict[str, Any] | None = None,
    config: DecisionConfig | dict[str, Any] | None = None,
    runtime_profile: str | None = None,
    prioritize_recall: bool | None = None,
    prioritize_precision: bool | None = None,
) -> dict[str, Any]:
    """
    Funcao principal explicita do motor de decisao.
    """
    resolved_config = resolve_config(
        config,
        profile=runtime_profile,
        prioritize_recall=prioritize_recall,
        prioritize_precision=prioritize_precision,
    )

    del features
    del metadata

    if_pred = 1 if _safe_int(isolation_prediction) == 1 else 0
    ae_pred = 1 if _safe_int(autoencoder_prediction) == 1 else 0
    heuristic_pred = _safe_bool(heuristic_detected_attack)
    if_score_raw = _safe_float(isolation_score)
    ae_score_raw = max(_safe_float(autoencoder_score), 0.0)
    if_score_norm = _resolve_normalized_score(
        pred=if_pred,
        normalized_score=(
            _safe_float(isolation_normalized_score)
            if isolation_normalized_score is not None
            else None
        ),
        confidence=(
            _safe_float(isolation_confidence)
            if isolation_confidence is not None
            else None
        ),
    )
    ae_score_norm = _resolve_normalized_score(
        pred=ae_pred,
        normalized_score=(
            _safe_float(autoencoder_normalized_score)
            if autoencoder_normalized_score is not None
            else None
        ),
        confidence=(
            _safe_float(autoencoder_confidence)
            if autoencoder_confidence is not None
            else None
        ),
    )
    if_confidence = _resolve_confidence(
        pred=if_pred,
        normalized_score=if_score_norm,
        confidence=(
            _safe_float(isolation_confidence)
            if isolation_confidence is not None
            else None
        ),
    )
    ae_confidence = _resolve_confidence(
        pred=ae_pred,
        normalized_score=ae_score_norm,
        confidence=(
            _safe_float(autoencoder_confidence)
            if autoencoder_confidence is not None
            else None
        ),
    )
    heuristic_confidence = clamp_confidence(_safe_float(heuristic_confidence))

    heuristic_context = compute_heuristic_context(
        heuristic_pred=heuristic_pred,
        heuristic_confidence=heuristic_confidence,
        heuristic_attack_type=str(heuristic_attack_type or "normal"),
        config=resolved_config,
    )
    ae_band_info = compute_ae_bands(
        ae_score_raw=ae_score_raw,
        ae_score_norm=ae_score_norm,
        ae_pred=ae_pred,
        ae_reference_threshold=autoencoder_threshold,
        config=resolved_config,
    )
    ae_band = str(ae_band_info["band"])
    ensemble_band = str(ensemble_risk_band or "").strip().lower()
    if ensemble_band in {"low", "medium", "high"} and not (
        ae_pred == 0
        and ae_band_info["band"] == "low"
        and ensemble_band in {"medium", "high"}
    ):
        ae_band = ensemble_band
    heuristic_label = str(heuristic_context["label"])
    heuristic_is_contextual = heuristic_label in {"supportive", "contextual"}
    ensemble_support = (
        clamp_confidence(_safe_float(ensemble_score))
        if ensemble_score is not None
        else None
    )
    effective_ensemble_pred = (
        1 if ensemble_prediction is not None and _safe_int(ensemble_prediction) == 1 else 0
    )
    if_attack_signal = compute_detector_attack_signal(
        pred=if_pred,
        normalized_score=if_score_norm,
        detector_name="if",
    )
    ae_attack_signal = compute_detector_attack_signal(
        pred=ae_pred,
        normalized_score=ae_score_norm,
        detector_name="ae",
    )
    attack_support = compute_attack_support(
        if_attack_signal=if_attack_signal,
        ae_attack_signal=ae_attack_signal,
        ensemble_support_score=ensemble_support,
        heuristic_context_score=float(heuristic_context["score"]),
        config=resolved_config,
    )
    signature_override = resolve_heuristic_signature_override(
        heuristic_pred=heuristic_pred,
        heuristic_confidence=heuristic_confidence,
        heuristic_attack_type=str(heuristic_attack_type or "normal"),
        attack_support=attack_support,
        config=resolved_config,
    )
    if_signal_medium = if_attack_signal >= 0.20
    if_signal_high = if_attack_signal >= 0.45
    ae_signal_medium = ae_pred == 1 or ae_attack_signal >= 0.30
    ae_signal_high = ae_pred == 1 and ae_attack_signal >= 0.70
    moderate_ensemble = effective_ensemble_pred == 1 or (
        ensemble_support is not None
        and ensemble_support >= clamp_confidence(resolved_config.moderate_attack_threshold)
    )
    strong_ensemble = ensemble_support is not None and ensemble_support >= clamp_confidence(
        resolved_config.strong_attack_threshold
    )

    if signature_override is not None:
        return _build_result(
            is_attack=True,
            agreement_level=signature_override["agreement_level"],
            decision_source=signature_override["decision_source"],
            decision_reason=signature_override["decision_reason"],
            if_pred=if_pred,
            ae_pred=ae_pred,
            heuristic_pred=heuristic_pred,
            if_confidence=if_confidence,
            ae_confidence=ae_confidence,
            heuristic_confidence=heuristic_confidence,
            if_score_raw=if_score_raw,
            ae_score_raw=ae_score_raw,
            if_score_norm=if_score_norm,
            ae_score_norm=ae_score_norm,
            heuristic_attack_type=str(heuristic_attack_type or "normal"),
            heuristic_reason=heuristic_reason,
            heuristic_context_label=heuristic_label,
            heuristic_context_score=float(heuristic_context["score"]),
            ensemble_support_score=ensemble_score,
            ensemble_pred=ensemble_prediction,
            ae_band=ae_band,
            ae_reference_threshold=autoencoder_threshold,
            config=resolved_config,
        )

    if resolved_config.profile_name == "conservative":
        if (
            if_pred == 1
            and ae_pred == 1
            and ae_band in {"medium", "high"}
            and heuristic_label != "suppressive"
        ):
            return _build_result(
                is_attack=True,
                agreement_level="full_agreement",
                decision_source="if+ae",
                decision_reason=(
                    "Isolation Forest e Autoencoder concordaram e o caso ficou acima da zona segura."
                ),
                if_pred=if_pred,
                ae_pred=ae_pred,
                heuristic_pred=heuristic_pred,
                if_confidence=if_confidence,
                ae_confidence=ae_confidence,
                heuristic_confidence=heuristic_confidence,
                if_score_raw=if_score_raw,
                ae_score_raw=ae_score_raw,
                if_score_norm=if_score_norm,
                ae_score_norm=ae_score_norm,
                heuristic_attack_type=str(heuristic_attack_type or "normal"),
                heuristic_reason=heuristic_reason,
                heuristic_context_label=heuristic_label,
                heuristic_context_score=float(heuristic_context["score"]),
                ensemble_support_score=ensemble_score,
                ensemble_pred=ensemble_prediction,
                ae_band=ae_band,
                ae_reference_threshold=autoencoder_threshold,
                config=resolved_config,
            )

        if ae_band == "high" and (ae_pred == 1 or ae_signal_high):
            if heuristic_label == "suppressive":
                return _build_result(
                    is_attack=False,
                    agreement_level="suppressed_by_context",
                    decision_source="suppressed_by_context",
                    decision_reason=(
                        "O Autoencoder entrou em zona alta, mas o contexto heuristico pertence a uma familia com alto falso positivo e bloqueou o alerta neste perfil conservador."
                    ),
                    if_pred=if_pred,
                    ae_pred=ae_pred,
                    heuristic_pred=heuristic_pred,
                    if_confidence=if_confidence,
                    ae_confidence=ae_confidence,
                    heuristic_confidence=heuristic_confidence,
                    if_score_raw=if_score_raw,
                    ae_score_raw=ae_score_raw,
                    if_score_norm=if_score_norm,
                    ae_score_norm=ae_score_norm,
                    heuristic_attack_type=str(heuristic_attack_type or "normal"),
                    heuristic_reason=heuristic_reason,
                    heuristic_context_label=heuristic_label,
                    heuristic_context_score=float(heuristic_context["score"]),
                    ensemble_support_score=ensemble_score,
                    ensemble_pred=ensemble_prediction,
                    ae_band=ae_band,
                    ae_reference_threshold=autoencoder_threshold,
                    config=resolved_config,
                )

            return _build_result(
                is_attack=True,
                agreement_level="ae_primary",
                decision_source="ae_high_risk",
                decision_reason=(
                    "O Autoencoder entrou em zona alta de anomalia e o contexto nao indicou uma familia conhecida por ruido excessivo."
                ),
                if_pred=if_pred,
                ae_pred=ae_pred,
                heuristic_pred=heuristic_pred,
                if_confidence=if_confidence,
                ae_confidence=ae_confidence,
                heuristic_confidence=heuristic_confidence,
                if_score_raw=if_score_raw,
                ae_score_raw=ae_score_raw,
                if_score_norm=if_score_norm,
                ae_score_norm=ae_score_norm,
                heuristic_attack_type=str(heuristic_attack_type or "normal"),
                heuristic_reason=heuristic_reason,
                heuristic_context_label=heuristic_label,
                heuristic_context_score=float(heuristic_context["score"]),
                ensemble_support_score=ensemble_score,
                ensemble_pred=ensemble_prediction,
                ae_band=ae_band,
                ae_reference_threshold=autoencoder_threshold,
                config=resolved_config,
            )

        if ae_band == "medium" and (ae_pred == 1 or ae_signal_medium):
            if heuristic_label == "suppressive":
                return _build_result(
                    is_attack=False,
                    agreement_level="suppressed_by_context",
                    decision_source="suppressed_by_context",
                    decision_reason=(
                        "O Autoencoder entrou na zona media, mas o contexto heuristico pertence a uma familia com historico forte de falso positivo."
                    ),
                    if_pred=if_pred,
                    ae_pred=ae_pred,
                    heuristic_pred=heuristic_pred,
                    if_confidence=if_confidence,
                    ae_confidence=ae_confidence,
                    heuristic_confidence=heuristic_confidence,
                    if_score_raw=if_score_raw,
                    ae_score_raw=ae_score_raw,
                    if_score_norm=if_score_norm,
                    ae_score_norm=ae_score_norm,
                    heuristic_attack_type=str(heuristic_attack_type or "normal"),
                    heuristic_reason=heuristic_reason,
                    heuristic_context_label=heuristic_label,
                    heuristic_context_score=float(heuristic_context["score"]),
                    ensemble_support_score=ensemble_score,
                    ensemble_pred=ensemble_prediction,
                    ae_band=ae_band,
                    ae_reference_threshold=autoencoder_threshold,
                    config=resolved_config,
                )

            agreement = "contextual_agreement" if heuristic_label == "supportive" else "ae_primary"
            source = "ae_contextual_band" if heuristic_label == "supportive" else "ae_medium_risk"
            reason = (
                "O Autoencoder entrou na zona util de ataque e a heuristica reforcou o alerta."
                if heuristic_label == "supportive"
                else "O Autoencoder entrou na zona util de ataque e o contexto nao trouxe um sinal forte de supressao."
            )
            return _build_result(
                is_attack=True,
                agreement_level=agreement,
                decision_source=source,
                decision_reason=reason,
                if_pred=if_pred,
                ae_pred=ae_pred,
                heuristic_pred=heuristic_pred,
                if_confidence=if_confidence,
                ae_confidence=ae_confidence,
                heuristic_confidence=heuristic_confidence,
                if_score_raw=if_score_raw,
                ae_score_raw=ae_score_raw,
                if_score_norm=if_score_norm,
                ae_score_norm=ae_score_norm,
                heuristic_attack_type=str(heuristic_attack_type or "normal"),
                heuristic_reason=heuristic_reason,
                heuristic_context_label=heuristic_label,
                heuristic_context_score=float(heuristic_context["score"]),
                ensemble_support_score=ensemble_score,
                ensemble_pred=ensemble_prediction,
                ae_band=ae_band,
                ae_reference_threshold=autoencoder_threshold,
                config=resolved_config,
            )
    else:
        supportive_confirmation_threshold = min(
            clamp_confidence(resolved_config.moderate_attack_threshold * 0.55),
            0.25,
        )
        contextual_confirmation_threshold = min(
            clamp_confidence(resolved_config.strong_attack_threshold * 0.60),
            0.35,
        )

        if (
            heuristic_label == "supportive"
            and ensemble_support is not None
            and ensemble_support >= supportive_confirmation_threshold
        ):
            return _build_result(
                is_attack=True,
                agreement_level="contextual_support",
                decision_source="heuristic_guided_attack",
                decision_reason=(
                    "A heuristica indicou um contexto coerente de ataque e o ensemble confirmou sinal suficiente para promover o caso no perfil balanceado."
                ),
                if_pred=if_pred,
                ae_pred=ae_pred,
                heuristic_pred=heuristic_pred,
                if_confidence=if_confidence,
                ae_confidence=ae_confidence,
                heuristic_confidence=heuristic_confidence,
                if_score_raw=if_score_raw,
                ae_score_raw=ae_score_raw,
                if_score_norm=if_score_norm,
                ae_score_norm=ae_score_norm,
                heuristic_attack_type=str(heuristic_attack_type or "normal"),
                heuristic_reason=heuristic_reason,
                heuristic_context_label=heuristic_label,
                heuristic_context_score=float(heuristic_context["score"]),
                ensemble_support_score=ensemble_score,
                ensemble_pred=ensemble_prediction,
                ae_band=ae_band,
                ae_reference_threshold=autoencoder_threshold,
                config=resolved_config,
            )

        if (
            heuristic_label == "contextual"
            and ensemble_support is not None
            and ensemble_support >= contextual_confirmation_threshold
            and (ae_band in {"medium", "high"} or if_signal_medium)
        ):
            return _build_result(
                is_attack=True,
                agreement_level="contextual_support",
                decision_source="contextual_attack",
                decision_reason=(
                    "A heuristica apontou uma familia contextual de ataque e o ensemble recebeu corroboracao suficiente dos modelos para nao suprimir o alerta."
                ),
                if_pred=if_pred,
                ae_pred=ae_pred,
                heuristic_pred=heuristic_pred,
                if_confidence=if_confidence,
                ae_confidence=ae_confidence,
                heuristic_confidence=heuristic_confidence,
                if_score_raw=if_score_raw,
                ae_score_raw=ae_score_raw,
                if_score_norm=if_score_norm,
                ae_score_norm=ae_score_norm,
                heuristic_attack_type=str(heuristic_attack_type or "normal"),
                heuristic_reason=heuristic_reason,
                heuristic_context_label=heuristic_label,
                heuristic_context_score=float(heuristic_context["score"]),
                ensemble_support_score=ensemble_score,
                ensemble_pred=ensemble_prediction,
                ae_band=ae_band,
                ae_reference_threshold=autoencoder_threshold,
                config=resolved_config,
            )

        if (
            if_pred == 1
            and ae_pred == 1
            and ae_band in {"medium", "high"}
            and heuristic_label != "suppressive"
        ):
            return _build_result(
                is_attack=True,
                agreement_level="full_agreement",
                decision_source="if+ae",
                decision_reason=(
                    "Isolation Forest e Autoencoder concordaram acima da zona segura, e o perfil balanceado preservou esse alerta."
                ),
                if_pred=if_pred,
                ae_pred=ae_pred,
                heuristic_pred=heuristic_pred,
                if_confidence=if_confidence,
                ae_confidence=ae_confidence,
                heuristic_confidence=heuristic_confidence,
                if_score_raw=if_score_raw,
                ae_score_raw=ae_score_raw,
                if_score_norm=if_score_norm,
                ae_score_norm=ae_score_norm,
                heuristic_attack_type=str(heuristic_attack_type or "normal"),
                heuristic_reason=heuristic_reason,
                heuristic_context_label=heuristic_label,
                heuristic_context_score=float(heuristic_context["score"]),
                ensemble_support_score=ensemble_score,
                ensemble_pred=ensemble_prediction,
                ae_band=ae_band,
                ae_reference_threshold=autoencoder_threshold,
                config=resolved_config,
            )

        if (ae_pred == 1 or ae_signal_high) and ae_band == "high" and (
            moderate_ensemble
            or heuristic_is_contextual
            or if_signal_medium
            or attack_support >= clamp_confidence(resolved_config.moderate_attack_threshold)
        ):
            agreement = (
                "full_agreement"
                if moderate_ensemble and if_signal_medium
                else "contextual_agreement"
                if heuristic_is_contextual
                else "ae_primary"
            )
            reason = (
                "O Autoencoder entrou em zona alta e houve corroboracao suficiente no ensemble, no IF ou no contexto heuristico para preservar o alerta."
            )
            return _build_result(
                is_attack=True,
                agreement_level=agreement,
                decision_source="ae_high_risk",
                decision_reason=reason,
                if_pred=if_pred,
                ae_pred=ae_pred,
                heuristic_pred=heuristic_pred,
                if_confidence=if_confidence,
                ae_confidence=ae_confidence,
                heuristic_confidence=heuristic_confidence,
                if_score_raw=if_score_raw,
                ae_score_raw=ae_score_raw,
                if_score_norm=if_score_norm,
                ae_score_norm=ae_score_norm,
                heuristic_attack_type=str(heuristic_attack_type or "normal"),
                heuristic_reason=heuristic_reason,
                heuristic_context_label=heuristic_label,
                heuristic_context_score=float(heuristic_context["score"]),
                ensemble_support_score=ensemble_score,
                ensemble_pred=ensemble_prediction,
                ae_band=ae_band,
                ae_reference_threshold=autoencoder_threshold,
                config=resolved_config,
            )

        if (ae_pred == 1 or ae_signal_medium) and ae_band == "medium" and (
            moderate_ensemble
            or attack_support >= clamp_confidence(resolved_config.moderate_attack_threshold)
            or (heuristic_is_contextual and if_signal_medium)
        ):
            agreement = (
                "contextual_agreement" if heuristic_is_contextual or moderate_ensemble else "ae_primary"
            )
            source = "ae_contextual_band" if heuristic_is_contextual else "ae_medium_risk"
            reason = (
                "O Autoencoder entrou na zona media util de ataque e o perfil balanceado permitiu a promocao com suporte contextual suficiente."
            )
            return _build_result(
                is_attack=True,
                agreement_level=agreement,
                decision_source=source,
                decision_reason=reason,
                if_pred=if_pred,
                ae_pred=ae_pred,
                heuristic_pred=heuristic_pred,
                if_confidence=if_confidence,
                ae_confidence=ae_confidence,
                heuristic_confidence=heuristic_confidence,
                if_score_raw=if_score_raw,
                ae_score_raw=ae_score_raw,
                if_score_norm=if_score_norm,
                ae_score_norm=ae_score_norm,
                heuristic_attack_type=str(heuristic_attack_type or "normal"),
                heuristic_reason=heuristic_reason,
                heuristic_context_label=heuristic_label,
                heuristic_context_score=float(heuristic_context["score"]),
                ensemble_support_score=ensemble_score,
                ensemble_pred=ensemble_prediction,
                ae_band=ae_band,
                ae_reference_threshold=autoencoder_threshold,
                config=resolved_config,
            )

        if strong_ensemble and (
            heuristic_is_contextual or if_signal_high or ae_signal_medium
        ):
            return _build_result(
                is_attack=True,
                agreement_level="contextual_support",
                decision_source="ensemble_support",
                decision_reason=(
                    "O ensemble entrou na faixa forte e recebeu apoio suficiente do IF, do Autoencoder ou do contexto heuristico para elevar o caso."
                ),
                if_pred=if_pred,
                ae_pred=ae_pred,
                heuristic_pred=heuristic_pred,
                if_confidence=if_confidence,
                ae_confidence=ae_confidence,
                heuristic_confidence=heuristic_confidence,
                if_score_raw=if_score_raw,
                ae_score_raw=ae_score_raw,
                if_score_norm=if_score_norm,
                ae_score_norm=ae_score_norm,
                heuristic_attack_type=str(heuristic_attack_type or "normal"),
                heuristic_reason=heuristic_reason,
                heuristic_context_label=heuristic_label,
                heuristic_context_score=float(heuristic_context["score"]),
                ensemble_support_score=ensemble_score,
                ensemble_pred=ensemble_prediction,
                ae_band=ae_band,
                ae_reference_threshold=autoencoder_threshold,
                config=resolved_config,
            )

    return _build_result(
        is_attack=False,
        agreement_level="full_agreement_negative",
        decision_source="safe_negative",
        decision_reason=(
            "O Autoencoder permaneceu na zona baixa de anomalia e nao houve sinal suficiente para elevar o caso."
        ),
        if_pred=if_pred,
        ae_pred=ae_pred,
        heuristic_pred=heuristic_pred,
        if_confidence=if_confidence,
        ae_confidence=ae_confidence,
        heuristic_confidence=heuristic_confidence,
        if_score_raw=if_score_raw,
        ae_score_raw=ae_score_raw,
        if_score_norm=if_score_norm,
        ae_score_norm=ae_score_norm,
        heuristic_attack_type=str(heuristic_attack_type or "normal"),
        heuristic_reason=heuristic_reason,
        heuristic_context_label=heuristic_label,
        heuristic_context_score=float(heuristic_context["score"]),
        ensemble_support_score=ensemble_score,
        ensemble_pred=ensemble_prediction,
        ae_band=ae_band,
        ae_reference_threshold=autoencoder_threshold,
        config=resolved_config,
    )


def decision_from_signals(
    *,
    if_pred: int,
    if_score_raw: float,
    if_score_norm: float,
    if_confidence: float,
    ae_pred: int,
    ae_score_raw: float,
    ae_score_norm: float,
    ae_confidence: float,
    heuristic_pred: bool,
    heuristic_confidence: float,
    heuristic_attack_type: str,
    heuristic_reason: str,
    ae_reference_threshold: float | None = None,
    ensemble_support_score: float | None = None,
    ensemble_pred: int | None = None,
    ensemble_risk_band: str | None = None,
    config: DecisionConfig | dict[str, Any] | None = None,
    runtime_profile: str | None = None,
    prioritize_recall: bool | None = None,
    prioritize_precision: bool | None = None,
) -> dict[str, Any]:
    """
    Alias legado para chamadas internas baseadas nos nomes antigos.
    """
    return make_decision(
        isolation_score=if_score_raw,
        isolation_prediction=if_pred,
        autoencoder_score=ae_score_raw,
        autoencoder_threshold=ae_reference_threshold,
        autoencoder_prediction=ae_pred,
        ensemble_score=ensemble_support_score,
        ensemble_prediction=ensemble_pred,
        heuristic_attack_type=heuristic_attack_type,
        heuristic_detected_attack=heuristic_pred,
        heuristic_confidence=heuristic_confidence,
        heuristic_reason=heuristic_reason,
        isolation_normalized_score=if_score_norm,
        isolation_confidence=if_confidence,
        autoencoder_normalized_score=ae_score_norm,
        autoencoder_confidence=ae_confidence,
        ensemble_risk_band=ensemble_risk_band,
        config=config,
        runtime_profile=runtime_profile,
        prioritize_recall=prioritize_recall,
        prioritize_precision=prioritize_precision,
    )


def _extract_signal_from_output(output: dict[str, Any], prefix: str) -> dict[str, Any]:
    """Adapter para manter compatibilidade com o restante do projeto."""
    return {
        "pred": _safe_int(output.get("pred", 0)),
        "score_raw": _safe_float(output.get("raw_score", output.get("score", 0.0))),
        "score_norm": clamp_confidence(
            _safe_float(
                output.get("normalized_score", output.get(f"normalized_{prefix}_score", 0.0))
            )
        ),
        "confidence": clamp_confidence(_safe_float(output.get("confidence", 0.0))),
    }


def decide_attack(
    *,
    if_output: dict[str, Any],
    ae_output: dict[str, Any],
    heuristic_output: dict[str, Any],
    ensemble_output: dict[str, Any] | None = None,
    config: DecisionConfig | dict[str, Any] | None = None,
    runtime_profile: str | None = None,
    prioritize_recall: bool = PRIORITIZE_RECALL,
    prioritize_precision: bool = PRIORITIZE_PRECISION,
) -> dict[str, Any]:
    """Adapter principal usado pela API e pelos pipelines."""
    if_signal = _extract_signal_from_output(if_output, "if")
    ae_signal = _extract_signal_from_output(ae_output, "ae")
    ensemble_output = ensemble_output or {}

    return make_decision(
        isolation_score=if_signal["score_raw"],
        isolation_prediction=if_signal["pred"],
        isolation_normalized_score=if_signal["score_norm"],
        isolation_confidence=if_signal["confidence"],
        autoencoder_score=ae_signal["score_raw"],
        autoencoder_threshold=_safe_float(
            ensemble_output.get("ae_reference_threshold_raw", ae_output.get("threshold_raw", 0.0))
        ),
        autoencoder_prediction=ae_signal["pred"],
        autoencoder_normalized_score=ae_signal["score_norm"],
        autoencoder_confidence=ae_signal["confidence"],
        ensemble_score=_safe_float(ensemble_output.get("score", 0.0)),
        ensemble_prediction=_safe_int(ensemble_output.get("pred", 0)),
        heuristic_attack_type=str(heuristic_output.get("attack_type", "normal")),
        heuristic_detected_attack=bool(
            heuristic_output.get("heuristic_detected_attack", False)
        ),
        heuristic_confidence=_safe_float(heuristic_output.get("heuristic_confidence", 0.0)),
        heuristic_reason=str(heuristic_output.get("heuristic_reason", "")),
        ensemble_risk_band=str(ensemble_output.get("ae_risk_band", "")),
        config=config,
        runtime_profile=runtime_profile,
        prioritize_recall=prioritize_recall,
        prioritize_precision=prioritize_precision,
    )


def decide_attack_batch(
    *,
    if_outputs: list[dict[str, Any]],
    ae_outputs: list[dict[str, Any]],
    heuristic_outputs: list[dict[str, Any]],
    ensemble_outputs: list[dict[str, Any]] | None = None,
    config: DecisionConfig | dict[str, Any] | None = None,
    runtime_profile: str | None = None,
    prioritize_recall: bool = PRIORITIZE_RECALL,
    prioritize_precision: bool = PRIORITIZE_PRECISION,
) -> list[dict[str, Any]]:
    """Executa o motor de decisao em lote."""
    if ensemble_outputs is None:
        ensemble_outputs = [{} for _ in if_outputs]

    decisions: list[dict[str, Any]] = []
    for if_output, ae_output, heuristic_output, ensemble_output in zip(
        if_outputs,
        ae_outputs,
        heuristic_outputs,
        ensemble_outputs,
    ):
        decisions.append(
            decide_attack(
                if_output=if_output,
                ae_output=ae_output,
                heuristic_output=heuristic_output,
                ensemble_output=ensemble_output,
                config=config,
                runtime_profile=runtime_profile,
                prioritize_recall=prioritize_recall,
                prioritize_precision=prioritize_precision,
            )
        )

    return decisions
