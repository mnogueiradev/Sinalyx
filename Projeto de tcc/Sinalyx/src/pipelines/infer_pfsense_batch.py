"""
Pipeline oficial de inferencia para lotes reais do pfSense no Sinalyx.

Este script:
1. carrega o CSV agregado gerado a partir dos logs reais
2. valida as 13 features esperadas pelo projeto
3. executa Isolation Forest, Autoencoder, heuristica, ensemble e decision engine
4. salva um CSV com a contribuicao de cada modulo por linha agregada
5. salva um JSON com auditoria de artefatos e resumo da execucao
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

import joblib
import pandas as pd

from src.core.artifacts import (
    MANIFEST_FILE,
    load_autoencoder_threshold_payload,
    resolve_autoencoder_threshold_file,
)
from src.core.evaluation import save_json_report
from src.core.paths import (
    ENSEMBLE_CONFIG_FILE,
    ISOLATION_MODEL_FILE,
    PROCESSED_DIR,
)
from src.features.constants import FEATURE_COLUMNS, describe_active_features
from src.features.dataset_loader import load_features_csv, validate_feature_order
from src.features.engineering import to_feature_matrix
from src.models.autoencoder import (
    get_loaded_bundle as get_loaded_autoencoder_bundle,
    predict_autoencoder_with_details,
)
from src.models.classifier import analyze_behavior
from src.models.decision_engine import decide_attack_batch
from src.models.detection import (
    get_loaded_bundle as get_loaded_detection_bundle,
    predict_with_details,
)
from src.models.ensemble import load_all_models, predict_ensemble_details


PFSENSE_PROCESSED_DIR = PROCESSED_DIR / "pfsense"
DEFAULT_INPUT_FILE = PFSENSE_PROCESSED_DIR / "sinalyx_features.csv"
DEFAULT_OUTPUT_CSV = PFSENSE_PROCESSED_DIR / "inference_results.csv"
DEFAULT_OUTPUT_JSON = PFSENSE_PROCESSED_DIR / "inference_report.json"
AI_SUPPORT_ENSEMBLE_THRESHOLD = 0.05
AI_SUPPORT_CONSERVATIVE_AE_RAW_THRESHOLD = 1.0
AI_SUPPORT_CONSERVATIVE_IF_NORMALIZED_THRESHOLD = 0.82
AI_SUPPORT_CRITERIA_VERSION = "ai_support_v1"
SSH_BRUTE_FORCE_CORRELATION_SECONDS = 120
SSH_BRUTE_FORCE_MIN_ANCHOR_BLOCKED = 4
SSH_BRUTE_FORCE_MIN_CONTINUATION_BLOCKED = 2
SSH_BRUTE_FORCE_CONTEXT_VERSION = "ssh_brute_force_context_v1"


def _to_builtin(value: Any) -> Any:
    """
    Converte tipos pandas/numpy para tipos nativos serializaveis.
    """
    if hasattr(value, "item"):
        return value.item()
    if isinstance(value, Path):
        return str(value)
    return value


def _float_or_none(value: Any) -> float | None:
    """
    Converte um valor para float quando possivel.
    """
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _record_float(record: dict[str, Any], key: str, default: float = 0.0) -> float:
    """
    Le um campo numerico de um registro agregado de forma resiliente.
    """
    value = _float_or_none(record.get(key))
    return default if value is None else value


def _record_int(record: dict[str, Any], key: str, default: int = 0) -> int:
    """
    Le um campo inteiro de um registro agregado de forma resiliente.
    """
    return int(round(_record_float(record, key, float(default))))


def _record_text(record: dict[str, Any], *keys: str) -> str:
    """
    Le o primeiro campo textual disponivel e padroniza para comparacao.
    """
    for key in keys:
        value = record.get(key)
        if value is not None and str(value).strip():
            return str(value).strip().lower()
    return ""


def _parse_destination_ports(record: dict[str, Any]) -> set[int]:
    """
    Recupera portas de destino sem depender das 13 features numericas.
    """
    ports: set[int] = set()
    common_ports = record.get("common_destination_ports")
    if common_ports is not None:
        for token in re.split(r"[^0-9]+", str(common_ports)):
            if token.isdigit():
                ports.add(int(token))

    for key in ("destination_port", "dst_port", "destination_port_min", "destination_port_max"):
        value = _record_int(record, key)
        if value > 0:
            ports.add(value)

    return ports


def _window_timestamp(record: dict[str, Any]) -> pd.Timestamp | None:
    """
    Resolve o timestamp de inicio da janela quando ele existe no CSV agregado.
    """
    for key in ("window_start", "timestamp", "time_window", "window_timestamp"):
        value = record.get(key)
        if value is None or not str(value).strip():
            continue
        timestamp = pd.to_datetime(value, errors="coerce")
        if not pd.isna(timestamp):
            return pd.Timestamp(timestamp)

    window_id = str(record.get("window_id", "") or "")
    for token in window_id.split("|"):
        timestamp = pd.to_datetime(token, errors="coerce")
        if not pd.isna(timestamp):
            return pd.Timestamp(timestamp)

    return None


def _ssh_context_key(record: dict[str, Any]) -> tuple[str, str, str, str] | None:
    """
    Cria uma chave conservadora para correlacionar janelas SSH do mesmo fluxo.
    """
    source_ip = _record_text(record, "source_ip", "src_ip")
    destination_ip = _record_text(record, "destination_ip_sample", "destination_ip", "dst_ip")
    protocol = _record_text(record, "protocol")
    action = _record_text(record, "action")

    if not source_ip or not destination_ip:
        return None
    return (source_ip, destination_ip, protocol, action)


def _is_blocked_ssh_window(record: dict[str, Any]) -> bool:
    """
    Identifica janelas concentradas em SSH bloqueado sem olhar nome de arquivo.
    """
    protocol = _record_text(record, "protocol")
    action = _record_text(record, "action")
    blocked_count = _record_int(record, "blocked_count")
    destination_ports = _parse_destination_ports(record)

    destination_port_count = max(
        _record_int(record, "destination_port_count"),
        int(round(_record_float(record, "ports"))),
        len(destination_ports),
    )
    destination_ip_count = _record_int(record, "destination_ip_count", default=1)

    return bool(
        protocol == "tcp"
        and 22 in destination_ports
        and (action == "block" or blocked_count >= 1)
        and destination_port_count <= 1
        and destination_ip_count <= 3
    )


def _is_strong_ssh_brute_force_anchor(
    record: dict[str, Any],
    heuristic_output: dict[str, Any],
) -> bool:
    """
    Reconhece uma janela forte de brute force SSH para servir de ancora.
    """
    return bool(
        str(heuristic_output.get("attack_type", "")).lower() == "brute_force"
        and _is_blocked_ssh_window(record)
        and _record_int(record, "blocked_count") >= SSH_BRUTE_FORCE_MIN_ANCHOR_BLOCKED
        and (
            _record_int(record, "tcp_pa_count") >= 4
            or _record_int(record, "tcp_syn_count") >= 4
            or _record_float(record, "packets") >= 6
            or _record_float(record, "connections") >= 6
        )
    )


def _is_weak_ssh_continuation_candidate(
    record: dict[str, Any],
    heuristic_output: dict[str, Any],
) -> bool:
    """
    Reconhece uma janela SSH fraca que so deve ser promovida se houver ancora.
    """
    return bool(
        str(heuristic_output.get("attack_type", "")).lower() == "ssh_suspicious"
        and _is_blocked_ssh_window(record)
        and _record_int(record, "blocked_count") >= SSH_BRUTE_FORCE_MIN_CONTINUATION_BLOCKED
        and _record_float(record, "packets") >= 2
        and _record_float(record, "connections") >= 2
        and (
            _record_int(record, "tcp_pa_count") >= 2
            or _record_int(record, "tcp_syn_count") >= 2
            or _record_float(record, "packets") >= 2
        )
    )


def _is_near_anchor(
    *,
    candidate_index: int,
    candidate_time: pd.Timestamp | None,
    anchor_index: int,
    anchor_time: pd.Timestamp | None,
) -> bool:
    """
    Decide se duas janelas pertencem ao mesmo bloco temporal curto.
    """
    if candidate_time is not None and anchor_time is not None:
        distance = abs((candidate_time - anchor_time).total_seconds())
        return 0 < distance <= SSH_BRUTE_FORCE_CORRELATION_SECONDS
    return abs(candidate_index - anchor_index) <= 1


def refine_heuristic_outputs_with_window_context(
    heuristic_inputs: list[dict[str, Any]],
    heuristic_outputs: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Promove SSH suspeito fraco a brute_force somente quando ha continuidade real.

    A heuristica por janela continua conservadora. Este refinamento usa o
    contexto do lote/live para preservar `ssh_suspicious` em atividade isolada
    e classificar como `brute_force` quando a janela fraca e vizinha de uma
    janela forte com mesma origem, destino, protocolo, acao e porta 22.
    """
    refined_outputs = [dict(output) for output in heuristic_outputs]
    anchors: dict[tuple[str, str, str, str], list[tuple[int, pd.Timestamp | None]]] = {}

    for index, (record, output) in enumerate(zip(heuristic_inputs, heuristic_outputs)):
        if not _is_strong_ssh_brute_force_anchor(record, output):
            continue
        context_key = _ssh_context_key(record)
        if context_key is None:
            continue
        anchors.setdefault(context_key, []).append((index, _window_timestamp(record)))

    if not anchors:
        return refined_outputs

    for index, (record, output) in enumerate(zip(heuristic_inputs, heuristic_outputs)):
        if not _is_weak_ssh_continuation_candidate(record, output):
            continue
        context_key = _ssh_context_key(record)
        if context_key is None or context_key not in anchors:
            continue

        candidate_time = _window_timestamp(record)
        matching_anchor = next(
            (
                (anchor_index, anchor_time)
                for anchor_index, anchor_time in anchors[context_key]
                if _is_near_anchor(
                    candidate_index=index,
                    candidate_time=candidate_time,
                    anchor_index=anchor_index,
                    anchor_time=anchor_time,
                )
            ),
            None,
        )
        if matching_anchor is None:
            continue

        previous_confidence = _record_float(output, "heuristic_confidence")
        promoted_confidence = min(0.91, max(previous_confidence + 0.05, 0.90))
        previous_reason = str(output.get("heuristic_reason", "")).strip()
        refined_outputs[index].update(
            {
                "heuristic_detected_attack": True,
                "attack_type": "brute_force",
                "heuristic_confidence": round(promoted_confidence, 4),
                "heuristic_reason": (
                    "Janela SSH bloqueada de baixo volume, mas correlacionada em "
                    "ate 120 segundos com uma janela forte de brute force da mesma "
                    "origem, destino, protocolo, acao e porta 22. "
                    f"Regra: {SSH_BRUTE_FORCE_CONTEXT_VERSION}. "
                    f"Motivo original: {previous_reason}"
                ),
            }
        )

    return refined_outputs


def _json_object_or_empty(value: Any) -> dict[str, Any]:
    """
    Converte um campo JSON textual em dicionario quando possivel.
    """
    if isinstance(value, dict):
        return value
    if value is None:
        return {}
    if isinstance(value, str) and value.strip():
        try:
            payload = json.loads(value)
        except json.JSONDecodeError:
            return {}
        return payload if isinstance(payload, dict) else {}
    return {}


def build_ai_support_metadata(
    *,
    ensemble_score: float,
    autoencoder_score: float,
    score_if_normalized: float,
) -> dict[str, Any]:
    """
    Calcula suporte auxiliar da IA sem alterar a decisao final.

    O criterio inicial vem da calibracao offline dos logs reais do pfSense:
    `ensemble_score >= 0.05`. O criterio conservador exige tambem
    Autoencoder e Isolation Forest acima dos limiares calibrados.
    """
    ensemble_passed = ensemble_score >= AI_SUPPORT_ENSEMBLE_THRESHOLD
    autoencoder_passed = (
        autoencoder_score >= AI_SUPPORT_CONSERVATIVE_AE_RAW_THRESHOLD
    )
    isolation_passed = (
        score_if_normalized >= AI_SUPPORT_CONSERVATIVE_IF_NORMALIZED_THRESHOLD
    )
    conservative = bool(ensemble_passed and autoencoder_passed and isolation_passed)
    enabled = bool(ensemble_passed)

    if conservative:
        support_type = "ensemble_autoencoder_if"
        support_level = "strong"
        reason = (
            "ensemble_score, autoencoder_score e score_if_normalized atingiram "
            "os limiares conservadores de suporte da IA; metadado auxiliar sem "
            "alterar final_label, attack_type ou risk_level."
        )
    elif enabled:
        support_type = "ensemble_score"
        support_level = "moderate"
        reason = (
            "ensemble_score atingiu o limiar calibrado de suporte da IA; "
            "metadado auxiliar sem alterar final_label, attack_type ou risk_level."
        )
    else:
        support_type = "none"
        support_level = "none"
        reason = (
            "Nenhum criterio calibrado de suporte da IA foi atingido; "
            "a decisao final permanece inalterada."
        )

    signals = {
        "criteria_version": AI_SUPPORT_CRITERIA_VERSION,
        "ensemble": {
            "score": float(ensemble_score),
            "threshold": AI_SUPPORT_ENSEMBLE_THRESHOLD,
            "passed": bool(ensemble_passed),
        },
        "autoencoder": {
            "raw_score": float(autoencoder_score),
            "threshold_raw": AI_SUPPORT_CONSERVATIVE_AE_RAW_THRESHOLD,
            "passed": bool(autoencoder_passed),
        },
        "isolation_forest": {
            "normalized_score": float(score_if_normalized),
            "threshold_normalized": AI_SUPPORT_CONSERVATIVE_IF_NORMALIZED_THRESHOLD,
            "passed": bool(isolation_passed),
        },
        "conservative_passed": bool(conservative),
    }

    return {
        "ai_support": enabled,
        "ai_support_conservative": conservative,
        "ai_support_type": support_type,
        "ai_support_level": support_level,
        "ai_support_reason": reason,
        "ai_support_signals": signals,
    }


def _counter_from_series(series: pd.Series) -> dict[str, int]:
    """
    Conta valores de uma serie em formato serializavel.
    """
    return {
        str(key): int(value)
        for key, value in Counter(series.astype(str).tolist()).items()
    }


def _numeric_summary(series: pd.Series) -> dict[str, float]:
    """
    Resume uma serie numerica em minimo, maximo e media.
    """
    numeric = pd.to_numeric(series, errors="coerce").fillna(0.0)
    return {
        "min": float(numeric.min()),
        "max": float(numeric.max()),
        "mean": float(numeric.mean()),
    }


def _json_load(path: Path) -> dict[str, Any] | None:
    """
    Le um JSON de forma resiliente.
    """
    if not path.exists():
        return None

    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def audit_model_artifacts(active_features: list[str]) -> dict[str, Any]:
    """
    Audita os artefatos persistidos para detectar inconsistencias conhecidas.
    """
    warnings: list[str] = []

    manifest_payload = _json_load(MANIFEST_FILE)
    manifest_audit = {
        "path": str(MANIFEST_FILE),
        "exists": manifest_payload is not None,
        "matches_active_features": False,
        "needs_regeneration": False,
        "feature_columns": [],
        "n_features": None,
    }

    if manifest_payload is None:
        manifest_audit["needs_regeneration"] = True
        warnings.append("manifest.json ausente.")
    else:
        manifest_columns = list(manifest_payload.get("feature_columns", []))
        manifest_n_features = manifest_payload.get("n_features")
        manifest_matches = (
            manifest_columns == active_features
            and manifest_n_features == len(active_features)
        )
        manifest_audit.update(
            {
                "feature_columns": manifest_columns,
                "n_features": manifest_n_features,
                "matches_active_features": manifest_matches,
                "needs_regeneration": not manifest_matches,
            }
        )
        if not manifest_matches:
            warnings.append(
                "manifest.json inconsistente com o conjunto ativo de 13 features."
            )

    ensemble_payload = _json_load(ENSEMBLE_CONFIG_FILE)
    ensemble_audit = {
        "path": str(ENSEMBLE_CONFIG_FILE),
        "exists": ensemble_payload is not None,
        "needs_regeneration": False,
        "payload": ensemble_payload,
        "runtime_safe_mismatch": False,
    }

    if ensemble_payload is None:
        ensemble_audit["needs_regeneration"] = True
        warnings.append("ensemble.json ausente.")
    else:
        persisted_if_weight = _float_or_none(ensemble_payload.get("if_weight"))
        persisted_ae_weight = _float_or_none(ensemble_payload.get("ae_weight"))
        persisted_threshold = _float_or_none(ensemble_payload.get("threshold"))
        runtime_safe_mismatch = bool(
            (persisted_if_weight is not None and persisted_if_weight > 0.20)
            or (persisted_ae_weight is not None and persisted_ae_weight < 0.80)
            or (persisted_threshold is not None and persisted_threshold < 0.45)
            or ("ae_reference_threshold_raw" not in ensemble_payload)
        )
        ensemble_audit.update(
            {
                "runtime_safe_mismatch": runtime_safe_mismatch,
                "needs_regeneration": runtime_safe_mismatch,
            }
        )
        if runtime_safe_mismatch:
            warnings.append(
                "ensemble.json persistido diverge da configuracao segura usada em runtime."
            )

    isolation_payload = None
    if ISOLATION_MODEL_FILE.exists():
        isolation_payload = joblib.load(ISOLATION_MODEL_FILE)
    isolation_score_stats_present = bool(
        isinstance(isolation_payload, dict) and isolation_payload.get("score_stats")
    )
    if not isolation_score_stats_present:
        warnings.append("Isolation Forest sem score_stats persistidos.")

    autoencoder_threshold_payload = None
    threshold_path = resolve_autoencoder_threshold_file()
    if threshold_path.exists():
        _, autoencoder_threshold_payload = load_autoencoder_threshold_payload()
    autoencoder_score_stats_present = bool(
        isinstance(autoencoder_threshold_payload, dict)
        and autoencoder_threshold_payload.get("score_stats")
    )
    if not autoencoder_score_stats_present:
        warnings.append("Autoencoder sem score_stats persistidos.")

    score_stats_audit = {
        "isolation": {
            "path": str(ISOLATION_MODEL_FILE),
            "score_stats_present": isolation_score_stats_present,
            "needs_regeneration": not isolation_score_stats_present,
        },
        "autoencoder": {
            "path": str(threshold_path),
            "score_stats_present": autoencoder_score_stats_present,
            "needs_regeneration": not autoencoder_score_stats_present,
        },
    }

    needs_regeneration = any(
        (
            manifest_audit["needs_regeneration"],
            ensemble_audit["needs_regeneration"],
            score_stats_audit["isolation"]["needs_regeneration"],
            score_stats_audit["autoencoder"]["needs_regeneration"],
        )
    )

    return {
        "status": "warning" if warnings else "ok",
        "needs_regeneration": needs_regeneration,
        "warnings": warnings,
        "manifest": manifest_audit,
        "ensemble": ensemble_audit,
        "score_stats": score_stats_audit,
        "recommended_regeneration_command": (
            ".\\.venv\\Scripts\\python.exe -m src.pipelines.train "
            "--input data/processed/features.csv --tune"
        ),
    }


def validate_input_frame(raw_df: pd.DataFrame, validated_df: pd.DataFrame) -> dict[str, Any]:
    """
    Valida a compatibilidade do CSV de entrada com as 13 features do projeto.
    """
    missing = [column for column in FEATURE_COLUMNS if column not in raw_df.columns]
    metadata_columns = [column for column in raw_df.columns if column not in FEATURE_COLUMNS]

    dtypes = {
        column: str(raw_df[column].dtype)
        for column in FEATURE_COLUMNS
        if column in raw_df.columns
    }
    nan_counts = {
        column: int(raw_df[column].isna().sum())
        for column in FEATURE_COLUMNS
        if column in raw_df.columns
    }
    negative_counts = {
        column: int(
            (pd.to_numeric(raw_df[column], errors="coerce") < 0).fillna(False).sum()
        )
        for column in FEATURE_COLUMNS
        if column in raw_df.columns
    }
    infinite_counts = {
        column: int(
            pd.to_numeric(raw_df[column], errors="coerce")
            .isin([float("inf"), float("-inf")])
            .sum()
        )
        for column in FEATURE_COLUMNS
        if column in raw_df.columns
    }

    return {
        "required_features": FEATURE_COLUMNS,
        "required_features_present": len(missing) == 0,
        "missing_features": missing,
        "raw_shape": list(raw_df.shape),
        "validated_shape": list(validated_df.shape),
        "feature_order_matches_runtime": list(validated_df.columns) == FEATURE_COLUMNS,
        "dtypes": dtypes,
        "nan_counts": nan_counts,
        "negative_counts": negative_counts,
        "infinite_counts": infinite_counts,
        "metadata_columns": metadata_columns,
    }


def build_heuristic_inputs(
    raw_df: pd.DataFrame,
    validated_df: pd.DataFrame,
) -> list[dict[str, Any]]:
    """
    Monta a entrada da heuristica com metadados reais do pfSense.

    As 13 features continuam indo so para scaler/modelos. Aqui apenas
    reanexamos os metadados ao registro enviado para a heuristica.
    """
    heuristic_df = raw_df.copy().reset_index(drop=True)
    for column in FEATURE_COLUMNS:
        heuristic_df[column] = validated_df[column].astype(float).reset_index(drop=True)
    return heuristic_df.to_dict(orient="records")


def build_results_dataframe(
    raw_df: pd.DataFrame,
    validated_df: pd.DataFrame,
    if_outputs: list[dict[str, Any]],
    ae_outputs: list[dict[str, Any]],
    heuristic_outputs: list[dict[str, Any]],
    ensemble_outputs: list[dict[str, Any]],
    decision_outputs: list[dict[str, Any]],
) -> pd.DataFrame:
    """
    Constrói o CSV final com a contribuicao de cada modulo por linha agregada.
    """
    output = raw_df.copy().reset_index(drop=True)

    for column in FEATURE_COLUMNS:
        output[column] = validated_df[column].astype(float)

    output["pred_if"] = [int(item["pred"]) for item in if_outputs]
    output["label_if"] = [str(item["label"]) for item in if_outputs]
    output["score_if"] = [float(item["raw_score"]) for item in if_outputs]
    output["score_if_normalized"] = [float(item["normalized_score"]) for item in if_outputs]
    output["if_confidence"] = [float(item["confidence"]) for item in if_outputs]

    output["pred_ae"] = [int(item["pred"]) for item in ae_outputs]
    output["label_ae"] = [str(item["label"]) for item in ae_outputs]
    output["score_ae"] = [float(item["raw_score"]) for item in ae_outputs]
    output["score_ae_log"] = [float(item["log_score"]) for item in ae_outputs]
    output["score_ae_normalized"] = [float(item["normalized_score"]) for item in ae_outputs]
    output["ae_confidence"] = [float(item["confidence"]) for item in ae_outputs]
    output["ae_threshold_raw"] = [float(item["threshold_raw"]) for item in ae_outputs]
    output["ae_threshold_log"] = [float(item["threshold_log"]) for item in ae_outputs]

    output["pred_heuristic"] = [
        int(bool(item["heuristic_detected_attack"])) for item in heuristic_outputs
    ]
    output["heuristic_attack_type"] = [str(item["attack_type"]) for item in heuristic_outputs]
    output["heuristic_confidence"] = [
        float(item["heuristic_confidence"]) for item in heuristic_outputs
    ]
    output["heuristic_reason"] = [str(item["heuristic_reason"]) for item in heuristic_outputs]

    output["pred_ensemble"] = [int(item["pred"]) for item in ensemble_outputs]
    output["score_ensemble"] = [float(item["score"]) for item in ensemble_outputs]
    output["ensemble_score"] = [float(item["score"]) for item in ensemble_outputs]
    output["ensemble_threshold"] = [float(item["threshold"]) for item in ensemble_outputs]
    output["runtime_profile"] = [str(item["runtime_profile"]) for item in ensemble_outputs]
    output["ensemble_if_weight"] = [float(item["if_weight"]) for item in ensemble_outputs]
    output["ensemble_ae_weight"] = [float(item["ae_weight"]) for item in ensemble_outputs]
    output["ensemble_if_pred"] = [int(item["if_pred"]) for item in ensemble_outputs]
    output["ensemble_ae_pred"] = [int(item["ae_pred"]) for item in ensemble_outputs]
    output["ensemble_if_alert_score"] = [
        float(item["if_alert_score"]) for item in ensemble_outputs
    ]
    output["ensemble_agreement_score"] = [
        float(item["agreement_score"]) for item in ensemble_outputs
    ]
    output["ensemble_conflict_penalty"] = [
        float(item["conflict_penalty"]) for item in ensemble_outputs
    ]
    output["ensemble_ae_risk_score"] = [
        float(item["ae_risk_score"]) for item in ensemble_outputs
    ]
    output["ensemble_ae_risk_band"] = [
        str(item["ae_risk_band"]) for item in ensemble_outputs
    ]

    ai_support_outputs = [
        build_ai_support_metadata(
            ensemble_score=float(ensemble_outputs[index]["score"]),
            autoencoder_score=float(ae_outputs[index]["raw_score"]),
            score_if_normalized=float(if_outputs[index]["normalized_score"]),
        )
        for index in range(len(ensemble_outputs))
    ]
    output["ai_support"] = [
        bool(item["ai_support"]) for item in ai_support_outputs
    ]
    output["ai_support_conservative"] = [
        bool(item["ai_support_conservative"]) for item in ai_support_outputs
    ]
    output["ai_support_type"] = [
        str(item["ai_support_type"]) for item in ai_support_outputs
    ]
    output["ai_support_level"] = [
        str(item["ai_support_level"]) for item in ai_support_outputs
    ]
    output["ai_support_reason"] = [
        str(item["ai_support_reason"]) for item in ai_support_outputs
    ]
    output["ai_support_signals"] = [
        json.dumps(item["ai_support_signals"], ensure_ascii=False, sort_keys=True)
        for item in ai_support_outputs
    ]

    output["pred_decision_engine"] = [
        int(bool(item["is_attack"])) for item in decision_outputs
    ]
    output["decision_runtime_profile"] = [
        str(item["runtime_profile"]) for item in decision_outputs
    ]
    output["is_anomaly"] = [bool(item["is_anomaly"]) for item in decision_outputs]
    output["final_label"] = [str(item["final_label"]) for item in decision_outputs]
    output["attack_type"] = [str(item["attack_type"]) for item in decision_outputs]
    output["risk_level"] = [str(item["risk_level"]) for item in decision_outputs]
    output["confidence"] = [float(item["confidence"]) for item in decision_outputs]
    output["explanation"] = [str(item["explanation"]) for item in decision_outputs]
    output["isolation_score"] = [float(item["isolation_score"]) for item in decision_outputs]
    output["autoencoder_score"] = [float(item["autoencoder_score"]) for item in decision_outputs]
    output["decision_attack_type"] = [
        str(item["attack_type"]) for item in decision_outputs
    ]
    output["decision_confidence"] = [
        float(item["confidence"]) for item in decision_outputs
    ]
    output["decision_risk_level"] = [str(item["risk_level"]) for item in decision_outputs]
    output["decision_source"] = [str(item["decision_source"]) for item in decision_outputs]
    output["agreement_level"] = [str(item["agreement_level"]) for item in decision_outputs]
    output["decision_reason"] = [str(item["decision_reason"]) for item in decision_outputs]
    output["conflict_winner"] = [str(item["conflict_winner"]) for item in decision_outputs]
    output["base_attack_support"] = [
        float(item["base_attack_support"]) for item in decision_outputs
    ]
    output["base_negative_support"] = [
        float(item["base_negative_support"]) for item in decision_outputs
    ]

    return output


def build_row_details(results_df: pd.DataFrame) -> list[dict[str, Any]]:
    """
    Gera uma estrutura detalhada por linha agregada para o JSON final.
    """
    rows: list[dict[str, Any]] = []
    metadata_columns = [column for column in results_df.columns if column not in FEATURE_COLUMNS]

    for row_index, record in enumerate(results_df.to_dict(orient="records")):
        metadata = {
            key: _to_builtin(record[key])
            for key in metadata_columns
            if not key.startswith("pred_")
            and not key.startswith("score_")
            and not key.endswith("_confidence")
            and not key.startswith("ensemble_")
            and not key.startswith("decision_")
            and key not in {
                "label_if",
                "label_ae",
                "heuristic_attack_type",
                "heuristic_reason",
                "agreement_level",
                "conflict_winner",
                "base_attack_support",
                "base_negative_support",
                "is_anomaly",
                "final_label",
                "attack_type",
                "risk_level",
                "confidence",
                "explanation",
                "isolation_score",
                "autoencoder_score",
                "ensemble_score",
            }
        }
        features = {column: float(record[column]) for column in FEATURE_COLUMNS}
        rows.append(
            {
                "row_index": row_index,
                "metadata": metadata,
                "features": features,
                "isolation_forest": {
                    "pred": int(record["pred_if"]),
                    "label": str(record["label_if"]),
                    "raw_score": float(record["score_if"]),
                    "normalized_score": float(record["score_if_normalized"]),
                    "confidence": float(record["if_confidence"]),
                },
                "autoencoder": {
                    "pred": int(record["pred_ae"]),
                    "label": str(record["label_ae"]),
                    "raw_score": float(record["score_ae"]),
                    "log_score": float(record["score_ae_log"]),
                    "normalized_score": float(record["score_ae_normalized"]),
                    "confidence": float(record["ae_confidence"]),
                    "threshold_raw": float(record["ae_threshold_raw"]),
                    "threshold_log": float(record["ae_threshold_log"]),
                },
                "heuristic": {
                    "pred": bool(record["pred_heuristic"]),
                    "attack_type": str(record["heuristic_attack_type"]),
                    "confidence": float(record["heuristic_confidence"]),
                    "reason": str(record["heuristic_reason"]),
                },
                "ensemble": {
                    "pred": int(record["pred_ensemble"]),
                    "score": float(record["score_ensemble"]),
                    "threshold": float(record["ensemble_threshold"]),
                    "if_weight": float(record["ensemble_if_weight"]),
                    "ae_weight": float(record["ensemble_ae_weight"]),
                    "if_pred": int(record["ensemble_if_pred"]),
                    "ae_pred": int(record["ensemble_ae_pred"]),
                    "if_alert_score": float(record["ensemble_if_alert_score"]),
                    "agreement_score": float(record["ensemble_agreement_score"]),
                    "conflict_penalty": float(record["ensemble_conflict_penalty"]),
                    "ae_risk_score": float(record["ensemble_ae_risk_score"]),
                    "ae_risk_band": str(record["ensemble_ae_risk_band"]),
                },
                "ai_support": {
                    "enabled": bool(record["ai_support"]),
                    "conservative": bool(record["ai_support_conservative"]),
                    "type": str(record["ai_support_type"]),
                    "level": str(record["ai_support_level"]),
                    "reason": str(record["ai_support_reason"]),
                    "signals": _json_object_or_empty(record["ai_support_signals"]),
                },
                "decision_engine": {
                    "is_anomaly": bool(record["is_anomaly"]),
                    "final_label": str(record["final_label"]),
                    "attack_type": str(record["attack_type"]),
                    "risk_level": str(record["risk_level"]),
                    "confidence": float(record["confidence"]),
                    "explanation": str(record["explanation"]),
                    "pred": bool(record["pred_decision_engine"]),
                    "legacy_attack_type": str(record["decision_attack_type"]),
                    "legacy_confidence": float(record["decision_confidence"]),
                    "legacy_risk_level": str(record["decision_risk_level"]),
                    "decision_source": str(record["decision_source"]),
                    "agreement_level": str(record["agreement_level"]),
                    "decision_reason": str(record["decision_reason"]),
                    "conflict_winner": str(record["conflict_winner"]),
                    "base_attack_support": float(record["base_attack_support"]),
                    "base_negative_support": float(record["base_negative_support"]),
                },
            }
        )

    return rows


def build_module_summary(results_df: pd.DataFrame) -> dict[str, Any]:
    """
    Resume o comportamento de cada modulo no lote.
    """
    return {
        "isolation_forest": {
            "prediction_counts": _counter_from_series(results_df["pred_if"].astype(int)),
            "raw_score": _numeric_summary(results_df["score_if"]),
            "normalized_score": _numeric_summary(results_df["score_if_normalized"]),
            "confidence": _numeric_summary(results_df["if_confidence"]),
        },
        "autoencoder": {
            "prediction_counts": _counter_from_series(results_df["pred_ae"].astype(int)),
            "raw_score": _numeric_summary(results_df["score_ae"]),
            "log_score": _numeric_summary(results_df["score_ae_log"]),
            "normalized_score": _numeric_summary(results_df["score_ae_normalized"]),
            "confidence": _numeric_summary(results_df["ae_confidence"]),
            "threshold_raw": _numeric_summary(results_df["ae_threshold_raw"]),
        },
        "heuristic": {
            "prediction_counts": _counter_from_series(results_df["pred_heuristic"].astype(int)),
            "attack_type_counts": _counter_from_series(results_df["heuristic_attack_type"]),
            "confidence": _numeric_summary(results_df["heuristic_confidence"]),
        },
        "ensemble": {
            "prediction_counts": _counter_from_series(results_df["pred_ensemble"].astype(int)),
            "risk_band_counts": _counter_from_series(results_df["ensemble_ae_risk_band"]),
            "score": _numeric_summary(results_df["score_ensemble"]),
            "threshold": _numeric_summary(results_df["ensemble_threshold"]),
        },
        "ai_support": {
            "support_counts": _counter_from_series(results_df["ai_support"].astype(bool)),
            "conservative_counts": _counter_from_series(
                results_df["ai_support_conservative"].astype(bool)
            ),
            "type_counts": _counter_from_series(results_df["ai_support_type"]),
            "level_counts": _counter_from_series(results_df["ai_support_level"]),
            "criteria": {
                "version": AI_SUPPORT_CRITERIA_VERSION,
                "ensemble_threshold": AI_SUPPORT_ENSEMBLE_THRESHOLD,
                "conservative_autoencoder_raw_threshold": (
                    AI_SUPPORT_CONSERVATIVE_AE_RAW_THRESHOLD
                ),
                "conservative_if_normalized_threshold": (
                    AI_SUPPORT_CONSERVATIVE_IF_NORMALIZED_THRESHOLD
                ),
            },
        },
        "decision_engine": {
            "prediction_counts": _counter_from_series(results_df["pred_decision_engine"].astype(int)),
            "is_anomaly_counts": _counter_from_series(results_df["is_anomaly"]),
            "final_label_counts": _counter_from_series(results_df["final_label"]),
            "attack_type_counts": _counter_from_series(results_df["attack_type"]),
            "decision_source_counts": _counter_from_series(results_df["decision_source"]),
            "risk_level_counts": _counter_from_series(results_df["risk_level"]),
            "confidence": _numeric_summary(results_df["confidence"]),
        },
    }


def build_inference_summary(results_df: pd.DataFrame) -> dict[str, Any]:
    """
    Explicita os contadores e estatisticas mais importantes do lote final.
    """
    return {
        "prediction_counts": _counter_from_series(results_df["pred_decision_engine"].astype(int)),
        "is_anomaly_counts": _counter_from_series(results_df["is_anomaly"]),
        "final_label_counts": _counter_from_series(results_df["final_label"]),
        "attack_type_counts": _counter_from_series(results_df["attack_type"]),
        "risk_level_counts": _counter_from_series(results_df["risk_level"]),
        "decision_source_counts": _counter_from_series(results_df["decision_source"]),
        "ensemble_score_stats": _numeric_summary(results_df["ensemble_score"]),
        "ai_support_counts": _counter_from_series(results_df["ai_support"].astype(bool)),
        "ai_support_conservative_counts": _counter_from_series(
            results_df["ai_support_conservative"].astype(bool)
        ),
        "ai_support_type_counts": _counter_from_series(results_df["ai_support_type"]),
        "ai_support_level_counts": _counter_from_series(results_df["ai_support_level"]),
        "ai_support_criteria": {
            "version": AI_SUPPORT_CRITERIA_VERSION,
            "ensemble_threshold": AI_SUPPORT_ENSEMBLE_THRESHOLD,
            "conservative_autoencoder_raw_threshold": (
                AI_SUPPORT_CONSERVATIVE_AE_RAW_THRESHOLD
            ),
            "conservative_if_normalized_threshold": (
                AI_SUPPORT_CONSERVATIVE_IF_NORMALIZED_THRESHOLD
            ),
        },
        "ae_score_stats": {
            "raw": _numeric_summary(results_df["score_ae"]),
            "normalized": _numeric_summary(results_df["score_ae_normalized"]),
            "threshold_raw": _numeric_summary(results_df["ae_threshold_raw"]),
        },
        "heuristic_attack_type_counts": _counter_from_series(results_df["heuristic_attack_type"]),
    }


def parse_args() -> argparse.Namespace:
    """
    Resolve os argumentos de linha de comando da pipeline.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default=str(DEFAULT_INPUT_FILE))
    parser.add_argument("--output-csv", default=str(DEFAULT_OUTPUT_CSV))
    parser.add_argument("--output-json", default=str(DEFAULT_OUTPUT_JSON))
    parser.add_argument("--runtime-profile", default=None)
    return parser.parse_args()


def run_inference_from_frame(
    *,
    raw_df: pd.DataFrame,
    input_label: str = "in_memory_dataframe",
    output_csv: str | Path | None = None,
    output_json: str | Path | None = None,
    runtime_profile: str | None = None,
    load_models: bool = True,
) -> tuple[pd.DataFrame, dict[str, Any]]:
    """
    Executa a inferencia oficial a partir de um DataFrame ja carregado.
    """
    validated_df = validate_feature_order(raw_df)
    feature_validation = validate_input_frame(raw_df, validated_df)

    missing = feature_validation["missing_features"]
    if missing:
        raise ValueError(
            "As 13 features esperadas pelo Sinalyx nao foram encontradas. "
            f"Ausentes: {missing}"
        )

    print(f"[INFO] Iniciando inferencia com {describe_active_features()}")
    print(f"[INFO] Origem da entrada: {input_label}")
    print(f"[INFO] Shape validado: {validated_df.shape}")

    X = to_feature_matrix(validated_df)

    if load_models:
        load_all_models()
    detection_bundle = get_loaded_detection_bundle()
    autoencoder_bundle = get_loaded_autoencoder_bundle()

    if_outputs = predict_with_details(X, bundle=detection_bundle)
    ae_outputs = predict_autoencoder_with_details(X, bundle=autoencoder_bundle)
    heuristic_inputs = build_heuristic_inputs(raw_df, validated_df)
    heuristic_outputs = [analyze_behavior(record) for record in heuristic_inputs]
    heuristic_outputs = refine_heuristic_outputs_with_window_context(
        heuristic_inputs,
        heuristic_outputs,
    )
    ensemble_outputs = predict_ensemble_details(
        X,
        detection_bundle=detection_bundle,
        autoencoder_bundle=autoencoder_bundle,
        runtime_profile=runtime_profile,
    )
    decision_outputs = decide_attack_batch(
        if_outputs=if_outputs,
        ae_outputs=ae_outputs,
        heuristic_outputs=heuristic_outputs,
        ensemble_outputs=ensemble_outputs,
        runtime_profile=runtime_profile,
    )

    results_df = build_results_dataframe(
        raw_df=raw_df,
        validated_df=validated_df,
        if_outputs=if_outputs,
        ae_outputs=ae_outputs,
        heuristic_outputs=heuristic_outputs,
        ensemble_outputs=ensemble_outputs,
        decision_outputs=decision_outputs,
    )

    output_csv_path = Path(output_csv) if output_csv is not None else None
    output_json_path = Path(output_json) if output_json is not None else None

    if output_csv_path is not None:
        output_csv_path.parent.mkdir(parents=True, exist_ok=True)
        results_df.to_csv(output_csv_path, index=False)

    artifact_audit = audit_model_artifacts(FEATURE_COLUMNS)
    report_payload = {
        "project_name": "Sinalyx",
        "pipeline_name": "infer_pfsense_batch",
        "feature_mode": describe_active_features(),
        "input_file": str(input_label),
        "output_files": {
            "csv": str(output_csv_path) if output_csv_path is not None else None,
            "json": str(output_json_path) if output_json_path is not None else None,
        },
        "feature_validation": feature_validation,
        "artifact_audit": artifact_audit,
        "summary": build_inference_summary(results_df),
        "module_summary": build_module_summary(results_df),
        "rows": build_row_details(results_df),
    }
    if output_json_path is not None:
        save_json_report(output_json_path, report_payload)

    if output_csv_path is not None:
        print(f"[INFO] Resultados salvos em: {output_csv_path}")
    if output_json_path is not None:
        print(f"[INFO] Relatorio salvo em: {output_json_path}")
    if artifact_audit["warnings"]:
        print("[WARNING] Auditoria de artefatos encontrou inconsistencias:")
        for warning in artifact_audit["warnings"]:
            print(f" - {warning}")
    print(
        "[INFO] Predicoes finais do decision engine: "
        f"{results_df['pred_decision_engine'].astype(int).tolist()}"
    )
    return results_df, report_payload


def run_inference(
    *,
    input_path: str | Path,
    output_csv: str | Path,
    output_json: str | Path,
    runtime_profile: str | None = None,
) -> tuple[pd.DataFrame, dict[str, Any]]:
    """
    Executa a inferencia oficial para um lote real agregado do pfSense.
    """
    input_path = Path(input_path)
    raw_df = load_features_csv(str(input_path))
    return run_inference_from_frame(
        raw_df=raw_df,
        input_label=str(input_path),
        output_csv=output_csv,
        output_json=output_json,
        runtime_profile=runtime_profile,
        load_models=True,
    )


def main() -> None:
    """
    Resolve argumentos CLI e executa a inferencia oficial.
    """
    args = parse_args()
    run_inference(
        input_path=args.input,
        output_csv=args.output_csv,
        output_json=args.output_json,
        runtime_profile=args.runtime_profile,
    )


if __name__ == "__main__":
    main()
