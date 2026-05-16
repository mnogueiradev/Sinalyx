"""
Geracao de relatorios de avaliacao do Sinalyx.

Este modulo compara os componentes do sistema em um mesmo split e organiza
as previsoes em um formato pronto para CSV e JSON.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

import pandas as pd

from src.core.evaluation import compute_binary_metrics
from src.features.constants import FEATURE_COLUMNS
from src.features.engineering import to_feature_matrix
from src.models.autoencoder import predict_autoencoder_with_details
from src.models.classifier import analyze_behavior
from src.models.decision_engine import decide_attack_batch
from src.models.detection import predict_with_details
from src.models.ensemble import EnsembleConfig, predict_ensemble_details


FINAL_DECISION_FIELDS = [
    "is_anomaly",
    "final_label",
    "attack_type",
    "risk_level",
    "confidence",
    "explanation",
]


def _column_name(prefix: str, name: str) -> str:
    """Resolve nomes de coluna com prefixo opcional."""
    return f"{prefix}{name}" if prefix else name


def _series_counter(series: pd.Series, *, limit: int | None = None) -> dict[str, int]:
    """Conta valores de uma serie em formato serializavel."""
    counts = Counter(series.astype(str).tolist())
    items = counts.most_common(limit)
    return {str(key): int(value) for key, value in items}


def _safe_float_summary(series: pd.Series) -> dict[str, float]:
    """Resume uma serie numerica para o JSON final."""
    numeric = pd.to_numeric(series, errors="coerce").fillna(0.0)
    return {
        "min": float(numeric.min()),
        "max": float(numeric.max()),
        "mean": float(numeric.mean()),
    }


def build_context_summary(
    input_df: pd.DataFrame,
    context_columns: list[str],
) -> dict[str, Any]:
    """
    Resume colunas humanas/contextuais preservadas na validacao.
    """
    summary: dict[str, Any] = {}
    for column in context_columns:
        if column not in input_df.columns:
            continue

        series = input_df[column]
        if pd.api.types.is_object_dtype(series) or pd.api.types.is_bool_dtype(series):
            summary[column] = {
                "kind": "categorical",
                "unique_values": int(series.astype(str).nunique(dropna=True)),
                "top_counts": _series_counter(series.astype(str), limit=20),
            }
            continue

        if pd.api.types.is_numeric_dtype(series) and series.nunique(dropna=True) <= 20:
            summary[column] = {
                "kind": "categorical_numeric",
                "unique_values": int(series.nunique(dropna=True)),
                "top_counts": _series_counter(series, limit=20),
            }
            continue

        if pd.api.types.is_numeric_dtype(series):
            summary[column] = {
                "kind": "numeric",
                **_safe_float_summary(series),
            }

    return summary


def build_metrics_for_profile(
    predictions_df: pd.DataFrame,
    y_true,
    *,
    ensemble_prefix: str = "",
    decision_prefix: str = "",
) -> dict[str, Any]:
    """
    Calcula metricas para um perfil de runtime usando colunas prefixadas.
    """
    return {
        "isolation_forest": compute_binary_metrics(
            y_true,
            predictions_df["pred_if"].tolist(),
        ),
        "autoencoder": compute_binary_metrics(
            y_true,
            predictions_df["pred_ae"].tolist(),
        ),
        "heuristic": compute_binary_metrics(
            y_true,
            predictions_df["pred_heuristic"].tolist(),
        ),
        "ensemble": compute_binary_metrics(
            y_true,
            predictions_df[_column_name(ensemble_prefix, "pred_ensemble")].tolist(),
        ),
        "decision_engine": compute_binary_metrics(
            y_true,
            predictions_df[_column_name(decision_prefix, "is_anomaly")].astype(int).tolist(),
        ),
    }


def build_module_summary(
    predictions_df: pd.DataFrame,
    *,
    ensemble_prefix: str = "",
    decision_prefix: str = "",
    runtime_profile: str | None = None,
) -> dict[str, Any]:
    """
    Consolida o comportamento dos modulos para leitura humana.
    """
    pred_ensemble_column = _column_name(ensemble_prefix, "pred_ensemble")
    score_ensemble_column = _column_name(ensemble_prefix, "score_ensemble")
    threshold_column = _column_name(ensemble_prefix, "ensemble_threshold")
    risk_band_column = _column_name(ensemble_prefix, "ensemble_ae_risk_band")
    pred_decision_column = _column_name(decision_prefix, "pred_decision_engine")
    anomaly_column = _column_name(decision_prefix, "is_anomaly")
    final_label_column = _column_name(decision_prefix, "final_label")
    attack_type_column = _column_name(decision_prefix, "attack_type")
    risk_level_column = _column_name(decision_prefix, "risk_level")
    decision_source_column = _column_name(decision_prefix, "decision_source")
    agreement_level_column = _column_name(decision_prefix, "agreement_level")
    confidence_column = _column_name(decision_prefix, "confidence")

    return {
        "runtime_profile": runtime_profile,
        "isolation_forest": {
            "prediction_counts": _series_counter(predictions_df["pred_if"]),
            "raw_score": _safe_float_summary(predictions_df["score_if"]),
            "normalized_score": _safe_float_summary(predictions_df["score_if_normalized"]),
            "confidence": _safe_float_summary(predictions_df["if_confidence"]),
        },
        "autoencoder": {
            "prediction_counts": _series_counter(predictions_df["pred_ae"]),
            "raw_score": _safe_float_summary(predictions_df["score_ae"]),
            "log_score": _safe_float_summary(predictions_df["score_ae_log"]),
            "normalized_score": _safe_float_summary(predictions_df["score_ae_normalized"]),
            "confidence": _safe_float_summary(predictions_df["ae_confidence"]),
        },
        "heuristic": {
            "prediction_counts": _series_counter(predictions_df["pred_heuristic"]),
            "attack_type_counts": _series_counter(predictions_df["heuristic_attack_type"]),
            "confidence": _safe_float_summary(predictions_df["heuristic_confidence"]),
        },
        "ensemble": {
            "prediction_counts": _series_counter(predictions_df[pred_ensemble_column]),
            "score": _safe_float_summary(predictions_df[score_ensemble_column]),
            "threshold": _safe_float_summary(predictions_df[threshold_column]),
            "risk_band_counts": (
                _series_counter(predictions_df[risk_band_column])
                if risk_band_column in predictions_df.columns
                else {}
            ),
        },
        "decision_engine": {
            "prediction_counts": _series_counter(predictions_df[pred_decision_column]),
            "is_anomaly_counts": _series_counter(predictions_df[anomaly_column]),
            "final_label_counts": _series_counter(predictions_df[final_label_column]),
            "attack_type_counts": _series_counter(predictions_df[attack_type_column]),
            "risk_level_counts": _series_counter(predictions_df[risk_level_column]),
            "decision_source_counts": _series_counter(predictions_df[decision_source_column]),
            "agreement_level_counts": _series_counter(predictions_df[agreement_level_column]),
            "confidence": _safe_float_summary(predictions_df[confidence_column]),
        },
    }


def append_profile_outputs(
    predictions_df: pd.DataFrame,
    *,
    profile_name: str,
    ensemble_outputs: list[dict[str, Any]],
    decision_outputs: list[dict[str, Any]],
) -> None:
    """
    Adiciona colunas prefixadas para um perfil secundario de runtime.
    """
    prefix = f"{profile_name}_"
    predictions_df[f"{prefix}runtime_profile"] = profile_name
    predictions_df[f"{prefix}pred_ensemble"] = [int(item["pred"]) for item in ensemble_outputs]
    predictions_df[f"{prefix}score_ensemble"] = [float(item["score"]) for item in ensemble_outputs]
    predictions_df[f"{prefix}ensemble_threshold"] = [
        float(item["threshold"]) for item in ensemble_outputs
    ]
    predictions_df[f"{prefix}ensemble_ae_risk_band"] = [
        str(item["ae_risk_band"]) for item in ensemble_outputs
    ]
    predictions_df[f"{prefix}pred_decision_engine"] = [
        int(bool(item["is_anomaly"])) for item in decision_outputs
    ]
    predictions_df[f"{prefix}is_anomaly"] = [
        bool(item["is_anomaly"]) for item in decision_outputs
    ]
    predictions_df[f"{prefix}final_label"] = [
        str(item["final_label"]) for item in decision_outputs
    ]
    predictions_df[f"{prefix}attack_type"] = [
        str(item["attack_type"]) for item in decision_outputs
    ]
    predictions_df[f"{prefix}risk_level"] = [
        str(item["risk_level"]) for item in decision_outputs
    ]
    predictions_df[f"{prefix}confidence"] = [
        float(item["confidence"]) for item in decision_outputs
    ]
    predictions_df[f"{prefix}explanation"] = [
        str(item["explanation"]) for item in decision_outputs
    ]
    predictions_df[f"{prefix}decision_source"] = [
        str(item["decision_source"]) for item in decision_outputs
    ]
    predictions_df[f"{prefix}agreement_level"] = [
        str(item["agreement_level"]) for item in decision_outputs
    ]


def evaluate_models_on_split(
    split_name: str,
    X_df: pd.DataFrame,
    y_true,
    *,
    detection_bundle: dict | None = None,
    autoencoder_bundle: dict | None = None,
    ensemble_config: EnsembleConfig | None = None,
    runtime_profile: str = "balanced",
    comparison_profiles: tuple[str, ...] = (),
) -> dict:
    """
    Avalia todos os componentes do Sinalyx em um split rotulado.

    Saidas calculadas:
    - Isolation Forest
    - Autoencoder
    - Heuristica comportamental
    - Ensemble de score continuo
    - Decision engine final
    """
    context_columns = [column for column in X_df.columns if column not in FEATURE_COLUMNS]
    X = to_feature_matrix(X_df)
    feature_records = X_df.reset_index(drop=True).to_dict(orient="records")

    if_outputs = predict_with_details(X, bundle=detection_bundle)
    ae_outputs = predict_autoencoder_with_details(X, bundle=autoencoder_bundle)
    ensemble_outputs = predict_ensemble_details(
        X,
        config=ensemble_config,
        detection_bundle=detection_bundle,
        autoencoder_bundle=autoencoder_bundle,
        runtime_profile=runtime_profile,
    )
    heuristic_outputs = [analyze_behavior(record) for record in feature_records]
    decision_outputs = decide_attack_batch(
        if_outputs=if_outputs,
        ae_outputs=ae_outputs,
        heuristic_outputs=heuristic_outputs,
        ensemble_outputs=ensemble_outputs,
        runtime_profile=runtime_profile,
    )

    predictions_df = X_df.copy().reset_index(drop=True)
    predictions_df["target"] = pd.Series(y_true).astype(int).reset_index(drop=True)
    predictions_df["split"] = split_name

    predictions_df["pred_if"] = [int(item["pred"]) for item in if_outputs]
    predictions_df["score_if"] = [float(item["raw_score"]) for item in if_outputs]
    predictions_df["score_if_normalized"] = [
        float(item["normalized_score"]) for item in if_outputs
    ]
    predictions_df["if_confidence"] = [float(item["confidence"]) for item in if_outputs]

    predictions_df["pred_ae"] = [int(item["pred"]) for item in ae_outputs]
    predictions_df["score_ae"] = [float(item["raw_score"]) for item in ae_outputs]
    predictions_df["score_ae_log"] = [float(item["log_score"]) for item in ae_outputs]
    predictions_df["score_ae_normalized"] = [
        float(item["normalized_score"]) for item in ae_outputs
    ]
    predictions_df["ae_confidence"] = [float(item["confidence"]) for item in ae_outputs]

    predictions_df["pred_heuristic"] = [
        int(bool(item["heuristic_detected_attack"])) for item in heuristic_outputs
    ]
    predictions_df["heuristic_attack_type"] = [
        str(item["attack_type"]) for item in heuristic_outputs
    ]
    predictions_df["heuristic_confidence"] = [
        float(item["heuristic_confidence"]) for item in heuristic_outputs
    ]
    predictions_df["heuristic_reason"] = [
        str(item["heuristic_reason"]) for item in heuristic_outputs
    ]

    predictions_df["pred_ensemble"] = [int(item["pred"]) for item in ensemble_outputs]
    predictions_df["score_ensemble"] = [float(item["score"]) for item in ensemble_outputs]
    predictions_df["ensemble_score"] = [float(item["score"]) for item in ensemble_outputs]
    predictions_df["ensemble_threshold"] = [
        float(item["threshold"]) for item in ensemble_outputs
    ]
    predictions_df["ensemble_ae_risk_band"] = [
        str(item["ae_risk_band"]) for item in ensemble_outputs
    ]
    predictions_df["runtime_profile"] = [str(item["runtime_profile"]) for item in ensemble_outputs]

    predictions_df["pred_decision_engine"] = [
        int(bool(item["is_anomaly"])) for item in decision_outputs
    ]
    predictions_df["is_anomaly"] = [bool(item["is_anomaly"]) for item in decision_outputs]
    predictions_df["decision_is_anomaly"] = [
        bool(item["is_anomaly"]) for item in decision_outputs
    ]
    predictions_df["final_label"] = [str(item["final_label"]) for item in decision_outputs]
    predictions_df["decision_final_label"] = [
        str(item["final_label"]) for item in decision_outputs
    ]
    predictions_df["attack_type"] = [str(item["attack_type"]) for item in decision_outputs]
    predictions_df["confidence"] = [float(item["confidence"]) for item in decision_outputs]
    predictions_df["decision_confidence_final"] = [
        float(item["confidence"]) for item in decision_outputs
    ]
    predictions_df["explanation"] = [str(item["explanation"]) for item in decision_outputs]
    predictions_df["decision_explanation"] = [
        str(item["explanation"]) for item in decision_outputs
    ]
    predictions_df["isolation_score"] = [
        float(item["isolation_score"]) for item in decision_outputs
    ]
    predictions_df["autoencoder_score"] = [
        float(item["autoencoder_score"]) for item in decision_outputs
    ]
    predictions_df["decision_attack_type"] = [
        str(item["attack_type"]) for item in decision_outputs
    ]
    predictions_df["decision_confidence"] = [
        float(item["confidence"]) for item in decision_outputs
    ]
    predictions_df["decision_source"] = [
        str(item["decision_source"]) for item in decision_outputs
    ]
    predictions_df["agreement_level"] = [
        str(item["agreement_level"]) for item in decision_outputs
    ]
    predictions_df["decision_reason"] = [
        str(item["decision_reason"]) for item in decision_outputs
    ]
    predictions_df["risk_level"] = [
        str(item["risk_level"]) for item in decision_outputs
    ]
    predictions_df["decision_risk_level"] = [
        str(item["risk_level"]) for item in decision_outputs
    ]
    predictions_df["decision_runtime_profile"] = [
        str(item["runtime_profile"]) for item in decision_outputs
    ]

    profile_metrics: dict[str, dict[str, Any]] = {
        runtime_profile: build_metrics_for_profile(predictions_df, y_true)
    }
    profile_module_summaries: dict[str, dict[str, Any]] = {
        runtime_profile: build_module_summary(
            predictions_df,
            runtime_profile=runtime_profile,
        )
    }

    for comparison_profile in comparison_profiles:
        if comparison_profile == runtime_profile:
            continue

        comparison_ensemble_outputs = predict_ensemble_details(
            X,
            config=ensemble_config,
            detection_bundle=detection_bundle,
            autoencoder_bundle=autoencoder_bundle,
            runtime_profile=comparison_profile,
        )
        comparison_decision_outputs = decide_attack_batch(
            if_outputs=if_outputs,
            ae_outputs=ae_outputs,
            heuristic_outputs=heuristic_outputs,
            ensemble_outputs=comparison_ensemble_outputs,
            runtime_profile=comparison_profile,
        )
        append_profile_outputs(
            predictions_df,
            profile_name=comparison_profile,
            ensemble_outputs=comparison_ensemble_outputs,
            decision_outputs=comparison_decision_outputs,
        )
        prefix = f"{comparison_profile}_"
        profile_metrics[comparison_profile] = build_metrics_for_profile(
            predictions_df,
            y_true,
            ensemble_prefix=prefix,
            decision_prefix=prefix,
        )
        profile_module_summaries[comparison_profile] = build_module_summary(
            predictions_df,
            ensemble_prefix=prefix,
            decision_prefix=prefix,
            runtime_profile=comparison_profile,
        )

    return {
        "split": split_name,
        "runtime_profile": runtime_profile,
        "metrics": profile_metrics[runtime_profile],
        "profile_metrics": profile_metrics,
        "predictions": predictions_df,
        "context_columns": context_columns,
        "context_summary": build_context_summary(X_df, context_columns),
        "module_summary": profile_module_summaries[runtime_profile],
        "profile_module_summaries": profile_module_summaries,
        "final_output_fields": FINAL_DECISION_FIELDS.copy(),
    }
