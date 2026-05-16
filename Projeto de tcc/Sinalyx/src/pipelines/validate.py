"""
Pipeline de validacao do Sinalyx.

Este script recarrega os artefatos atuais do projeto e compara o desempenho
dos modelos e da decisao final em treino, validacao e teste.
"""

from __future__ import annotations

import argparse

import pandas as pd

from src.core.evaluation import (
    save_json_report,
    split_train_validation_test,
    summarize_target_distribution,
)
from src.core.paths import VALIDATION_PREDICTIONS_FILE, VALIDATION_REPORT_FILE
from src.features.constants import FEATURE_COLUMNS, describe_active_features
from src.features.dataset_loader import load_features_csv, load_training_dataframe
from src.models.ensemble import describe_runtime_profile, load_all_models
from src.pipelines.reporting import evaluate_models_on_split


PRIMARY_RUNTIME_PROFILE = "balanced"
COMPARISON_RUNTIME_PROFILES = ("conservative",)


def build_split_comparison(metrics: dict) -> list[dict]:
    """
    Ordena os modelos por recall dentro de um mesmo split.
    """
    comparison = []
    for model_name, values in metrics.items():
        comparison.append(
            {
                "model": model_name,
                "recall": float(values["recall"]),
                "precision": float(values["precision"]),
                "f1_score": float(values["f1_score"]),
                "false_positive_rate": float(values["false_positive_rate"]),
            }
        )

    return sorted(
        comparison,
        key=lambda item: (
            item["recall"],
            item["f1_score"],
            -item["false_positive_rate"],
        ),
        reverse=True,
    )


def build_final_system_evaluation(reports: dict[str, dict]) -> dict[str, dict]:
    """
    Destaca as metricas finais do Decision Engine por split.
    """
    return {
        split_name: report["metrics"]["decision_engine"]
        for split_name, report in reports.items()
    }


def build_profile_evaluation(
    reports: dict[str, dict],
) -> dict[str, dict[str, dict[str, dict]]]:
    """
    Organiza as metricas por perfil e por split.
    """
    profile_names: set[str] = set()
    for report in reports.values():
        profile_names.update(report.get("profile_metrics", {}).keys())

    evaluation: dict[str, dict[str, dict[str, dict]]] = {}
    for profile_name in sorted(profile_names):
        evaluation[profile_name] = {}
        for split_name, report in reports.items():
            evaluation[profile_name][split_name] = report["profile_metrics"][profile_name]
    return evaluation


def build_profile_comparison(reports: dict[str, dict]) -> dict[str, dict]:
    """
    Compara o perfil balanced com o conservative em cada split.
    """
    comparison: dict[str, dict] = {}
    for split_name, report in reports.items():
        profile_metrics = report.get("profile_metrics", {})
        balanced = profile_metrics.get("balanced", {})
        conservative = profile_metrics.get("conservative", {})
        if not balanced or not conservative:
            continue

        comparison[split_name] = {}
        for module_name in ("ensemble", "decision_engine"):
            balanced_metrics = balanced.get(module_name, {})
            conservative_metrics = conservative.get(module_name, {})
            comparison[split_name][module_name] = {
                "balanced": balanced_metrics,
                "conservative": conservative_metrics,
                "delta_balanced_minus_conservative": {
                    metric_name: float(balanced_metrics.get(metric_name, 0.0))
                    - float(conservative_metrics.get(metric_name, 0.0))
                    for metric_name in (
                        "recall",
                        "precision",
                        "f1_score",
                        "false_positive_rate",
                        "accuracy",
                    )
                },
            }

    return comparison


def main() -> None:
    """
    Valida os artefatos atuais do Sinalyx em treino, validacao e teste.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--validation-size", type=float, default=0.15)
    parser.add_argument("--test-size", type=float, default=0.15)
    parser.add_argument("--random-state", type=int, default=42)
    args = parser.parse_args()

    raw_df = load_features_csv(args.input)
    X_df, y_series = load_training_dataframe(args.input)
    if y_series is None:
        raise ValueError(
            "A validacao exige uma coluna de rotulo, como 'target' ou 'label'."
        )

    missing = [column for column in FEATURE_COLUMNS if column not in X_df.columns]
    if missing:
        raise ValueError(
            "As features esperadas para validacao nao foram encontradas. "
            f"Ausentes: {missing}"
        )

    if len(raw_df) != len(X_df):
        raise ValueError(
            "A validacao nao conseguiu alinhar o CSV original com a matriz de features."
        )

    context_columns = [column for column in raw_df.columns if column not in FEATURE_COLUMNS]
    validation_input_df = X_df.copy().reset_index(drop=True)
    for column in context_columns:
        validation_input_df[column] = raw_df[column].reset_index(drop=True)

    print(f"[INFO] Validando com {describe_active_features()}")
    print(f"[INFO] Shape final da matriz de validacao: {X_df[FEATURE_COLUMNS].shape}")

    splits = split_train_validation_test(
        validation_input_df,
        y_series.astype(int),
        validation_size=args.validation_size,
        test_size=args.test_size,
        random_state=args.random_state,
    )

    load_all_models()

    train_report = evaluate_models_on_split(
        "train",
        splits["X_train"],
        splits["y_train"],
        runtime_profile=PRIMARY_RUNTIME_PROFILE,
        comparison_profiles=COMPARISON_RUNTIME_PROFILES,
    )
    validation_report = evaluate_models_on_split(
        "validation",
        splits["X_validation"],
        splits["y_validation"],
        runtime_profile=PRIMARY_RUNTIME_PROFILE,
        comparison_profiles=COMPARISON_RUNTIME_PROFILES,
    )
    test_report = evaluate_models_on_split(
        "test",
        splits["X_test"],
        splits["y_test"],
        runtime_profile=PRIMARY_RUNTIME_PROFILE,
        comparison_profiles=COMPARISON_RUNTIME_PROFILES,
    )

    predictions_df = pd.concat(
        [
            train_report["predictions"],
            validation_report["predictions"],
            test_report["predictions"],
        ],
        ignore_index=True,
    )
    VALIDATION_PREDICTIONS_FILE.parent.mkdir(parents=True, exist_ok=True)
    predictions_df.to_csv(VALIDATION_PREDICTIONS_FILE, index=False)

    reports = {
        "train": train_report,
        "validation": validation_report,
        "test": test_report,
    }

    report_payload = {
        "project_name": "Sinalyx",
        "feature_mode": describe_active_features(),
        "features": FEATURE_COLUMNS,
        "input_file": args.input,
        "context_columns": context_columns,
        "runtime_profiles": {
            "primary": PRIMARY_RUNTIME_PROFILE,
            "comparison": list(COMPARISON_RUNTIME_PROFILES),
        },
        "runtime_profile_configs": {
            PRIMARY_RUNTIME_PROFILE: describe_runtime_profile(
                runtime_profile=PRIMARY_RUNTIME_PROFILE
            ),
            **{
                profile_name: describe_runtime_profile(runtime_profile=profile_name)
                for profile_name in COMPARISON_RUNTIME_PROFILES
            },
        },
        "decision_engine_output_fields": test_report["final_output_fields"],
        "prediction_columns": predictions_df.columns.tolist(),
        "dataset_summary": {
            "full_dataset": summarize_target_distribution(y_series),
            "train": summarize_target_distribution(splits["y_train"]),
            "validation": summarize_target_distribution(splits["y_validation"]),
            "test": summarize_target_distribution(splits["y_test"]),
        },
        "evaluation": {
            "train": train_report["metrics"],
            "validation": validation_report["metrics"],
            "test": test_report["metrics"],
        },
        "profile_evaluation": build_profile_evaluation(reports),
        "final_system_evaluation": build_final_system_evaluation(reports),
        "comparison": {
            "train": build_split_comparison(train_report["metrics"]),
            "validation": build_split_comparison(validation_report["metrics"]),
            "test": build_split_comparison(test_report["metrics"]),
        },
        "runtime_profile_comparison": build_profile_comparison(reports),
        "module_summaries": {
            "train": train_report["module_summary"],
            "validation": validation_report["module_summary"],
            "test": test_report["module_summary"],
        },
        "profile_module_summaries": {
            "train": train_report["profile_module_summaries"],
            "validation": validation_report["profile_module_summaries"],
            "test": test_report["profile_module_summaries"],
        },
        "context_summaries": {
            "train": train_report["context_summary"],
            "validation": validation_report["context_summary"],
            "test": test_report["context_summary"],
        },
        "artifacts": {
            "predictions_file": str(VALIDATION_PREDICTIONS_FILE),
            "report_file": str(VALIDATION_REPORT_FILE),
            "predictions_rows": int(len(predictions_df)),
        },
    }
    save_json_report(VALIDATION_REPORT_FILE, report_payload)

    print(f"[INFO] Previsoes salvas em: {VALIDATION_PREDICTIONS_FILE}")
    print(f"[INFO] Relatorio salvo em: {VALIDATION_REPORT_FILE}")
    print(
        "[INFO] Metricas finais do decision engine no teste: "
        f"{test_report['metrics']['decision_engine']}"
    )


if __name__ == "__main__":
    main()
