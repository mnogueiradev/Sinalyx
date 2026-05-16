"""
Pipeline de treino do Sinalyx.

Este script coordena:
- carga do dataset oficial em data/processed/features.csv
- validacao das 13 features oficiais
- tuning opcional com split estruturado
- treino final dos modelos
- persistencia dos artefatos alinhados com a inferencia
- geracao de manifest.json e validation_report.json
"""

from __future__ import annotations

import argparse
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any

import pandas as pd

from src.core.artifacts import MANIFEST_FILE, clear_model_artifacts, save_manifest
from src.core.evaluation import (
    apply_balance_strategy,
    candidate_ranking_key,
    save_json_report,
    split_train_validation_test,
    summarize_target_distribution,
)
from src.core.paths import (
    AUTOENCODER_STATS_FILE,
    AUTOENCODER_MODEL_FILE,
    AUTOENCODER_THRESHOLD_FILE,
    ENSEMBLE_CONFIG_FILE,
    FEATURES_FILE,
    ISOLATION_STATS_FILE,
    ISOLATION_MODEL_FILE,
    SCALER_FILE,
    VALIDATION_PREDICTIONS_FILE,
    VALIDATION_REPORT_FILE,
)
from src.features.constants import FEATURE_COLUMNS, describe_active_features
from src.features.dataset_loader import load_training_dataframe
from src.features.engineering import to_feature_matrix
from src.models.autoencoder import (
    AutoencoderConfig,
    predict_autoencoder,
    train_autoencoder,
    tune_autoencoder,
)
from src.models.detection import (
    IsolationForestConfig,
    build_candidate_configs as build_detection_candidate_configs,
    predict,
    train_model,
    tune_model,
)
from src.models.ensemble import (
    DEFAULT_ENSEMBLE_CONFIG,
    build_ensemble_config_from_scores,
    save_ensemble_config,
    tune_ensemble,
)
from src.pipelines.reporting import evaluate_models_on_split


def resolve_balance_strategies(balance_strategy: str) -> list[str]:
    """
    Resolve as estrategias de balanceamento testadas no tuning.
    """
    strategy_key = balance_strategy.strip().lower()
    if strategy_key == "auto":
        return ["none", "undersample_normal", "oversample_attack"]
    return [strategy_key]


def build_standard_detection_candidates() -> list[IsolationForestConfig]:
    """
    Constroi o grid oficial do Isolation Forest travado em StandardScaler.
    """
    return build_detection_candidate_configs(scaler_options=("standard",))


def maybe_limit_rows(
    X_df: pd.DataFrame,
    y_series: pd.Series,
    *,
    max_rows: int | None,
    random_state: int,
) -> tuple[pd.DataFrame, pd.Series]:
    """
    Opcionalmente reduz o dataset para acelerar experimentos.
    """
    if max_rows is None or len(X_df) <= max_rows:
        return X_df.reset_index(drop=True), y_series.reset_index(drop=True)

    frame = X_df.copy()
    frame["target"] = y_series.values
    sampled_groups = []
    for _, group in frame.groupby("target"):
        group_size = max(1, int(round(max_rows * len(group) / len(frame))))
        sampled_groups.append(
            group.sample(
                n=min(group_size, len(group)),
                random_state=random_state,
                replace=False,
            )
        )

    sampled = pd.concat(sampled_groups, ignore_index=True)
    if len(sampled) > max_rows:
        sampled = sampled.sample(n=max_rows, random_state=random_state).reset_index(drop=True)

    y_sampled = sampled.pop("target").astype(int)
    return sampled.reset_index(drop=True), y_sampled.reset_index(drop=True)


def pick_best_strategy_result(strategy_results: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Seleciona a melhor estrategia considerando a metrica do ensemble.
    """
    if not strategy_results:
        raise ValueError("Nenhuma estrategia de tuning foi executada.")

    return max(
        strategy_results,
        key=lambda item: candidate_ranking_key(
            {"metrics": item["ensemble"]["best_result"]["metrics"]}
        ),
    )


def serialize_strategy_result(result: dict[str, Any]) -> dict[str, Any]:
    """
    Remove objetos nao serializaveis do resultado interno do tuning.
    """
    return {
        "balance_strategy": result["balance_strategy"],
        "train_distribution_before": result["train_distribution_before"],
        "train_distribution_after": result["train_distribution_after"],
        "detection": {
            "best_result": result["detection"]["best_result"],
            "results": result["detection"]["results"],
        },
        "autoencoder": {
            "best_result": result["autoencoder"]["best_result"],
            "results": result["autoencoder"]["results"],
        },
        "ensemble": {
            "best_result": result["ensemble"]["best_result"],
            "results": result["ensemble"]["results"],
        },
    }


def build_artifact_snapshot(
    *,
    detection_bundle: dict[str, Any],
    autoencoder_bundle: dict[str, Any],
    ensemble_config,
) -> dict[str, Any]:
    """
    Resume os artefatos persistidos e as estatisticas esperadas pela inferencia.
    """
    return {
        "feature_mode": describe_active_features(),
        "feature_columns": FEATURE_COLUMNS.copy(),
        "n_features": len(FEATURE_COLUMNS),
        "paths": {
            "isolation_model": str(ISOLATION_MODEL_FILE),
            "isolation_stats": str(ISOLATION_STATS_FILE),
            "scaler": str(SCALER_FILE),
            "autoencoder_model": str(AUTOENCODER_MODEL_FILE),
            "autoencoder_threshold": str(AUTOENCODER_THRESHOLD_FILE),
            "autoencoder_stats": str(AUTOENCODER_STATS_FILE),
            "ensemble_config": str(ENSEMBLE_CONFIG_FILE),
            "manifest": str(MANIFEST_FILE),
        },
        "isolation_forest": {
            "config": detection_bundle.get("config"),
            "score_stats_present": bool(detection_bundle.get("score_stats")),
            "score_stats": detection_bundle.get("score_stats"),
        },
        "autoencoder": {
            "config": autoencoder_bundle.get("config"),
            "threshold": float(autoencoder_bundle["threshold"]),
            "threshold_transformed": float(autoencoder_bundle["threshold_transformed"]),
            "score_stats_present": bool(autoencoder_bundle.get("score_stats")),
            "score_stats": autoencoder_bundle.get("score_stats"),
        },
        "ensemble": asdict(ensemble_config),
    }


def save_score_stat_reports(
    *,
    detection_bundle: dict[str, Any],
    autoencoder_bundle: dict[str, Any],
) -> None:
    """
    Materializa score_stats em JSON auditavel sem alterar o runtime atual.
    """
    isolation_payload = {
        "model": "isolation_forest",
        "feature_mode": describe_active_features(),
        "feature_columns": FEATURE_COLUMNS.copy(),
        "config": detection_bundle.get("config"),
        "score_stats": detection_bundle.get("score_stats"),
    }
    autoencoder_payload = {
        "model": "autoencoder",
        "feature_mode": describe_active_features(),
        "feature_columns": FEATURE_COLUMNS.copy(),
        "config": autoencoder_bundle.get("config"),
        "threshold_raw": float(autoencoder_bundle["threshold"]),
        "threshold_transformed": float(autoencoder_bundle["threshold_transformed"]),
        "score_stats": autoencoder_bundle.get("score_stats"),
        "train_error_stats": autoencoder_bundle.get("train_error_stats"),
    }
    save_json_report(ISOLATION_STATS_FILE, isolation_payload)
    save_json_report(AUTOENCODER_STATS_FILE, autoencoder_payload)


def build_manifest_payload(
    *,
    input_file: str,
    X_df: pd.DataFrame,
    y_series: pd.Series,
    tuning_enabled: bool,
    random_state: int,
    balance_strategy_selected: str,
    detection_bundle: dict[str, Any],
    autoencoder_bundle: dict[str, Any],
    ensemble_config,
    evaluation: dict[str, Any] | None,
) -> dict[str, Any]:
    """
    Monta o manifesto final do treino alinhado com a inferencia atual.
    """
    metrics = evaluation or {}
    return {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "project_name": "Sinalyx",
        "input_file": input_file,
        "feature_mode": describe_active_features(),
        "feature_columns": FEATURE_COLUMNS.copy(),
        "n_features": len(FEATURE_COLUMNS),
        "n_rows_total": int(len(X_df)),
        "n_rows_train": int(len(X_df)),
        "has_labels": True,
        "tuning_enabled": bool(tuning_enabled),
        "balance_strategy_selected": balance_strategy_selected,
        "seed": int(random_state),
        "contamination": float(
            detection_bundle.get("config", {}).get("contamination", 0.0)
        ),
        "autoencoder_threshold": float(autoencoder_bundle["threshold"]),
        "isolation_config": detection_bundle.get("config"),
        "autoencoder_config": autoencoder_bundle.get("config"),
        "ensemble_config": asdict(ensemble_config),
        "isolation_score_stats": detection_bundle.get("score_stats"),
        "autoencoder_score_stats": autoencoder_bundle.get("score_stats"),
        "artifacts": build_artifact_snapshot(
            detection_bundle=detection_bundle,
            autoencoder_bundle=autoencoder_bundle,
            ensemble_config=ensemble_config,
        ),
        "metrics": metrics,
    }


def validate_training_input(X_df: pd.DataFrame, y_series: pd.Series | None) -> pd.Series:
    """
    Garante que o dataset tenha target e as 13 features oficiais.
    """
    missing = [column for column in FEATURE_COLUMNS if column not in X_df.columns]
    if missing:
        raise ValueError(
            "As features esperadas para treino nao foram encontradas. "
            f"Ausentes: {missing}"
        )

    if y_series is None:
        raise ValueError(
            "O dataset de treino precisa conter target/label para manter a "
            "reprodutibilidade e a auditoria do pipeline."
        )

    return y_series.astype(int).reset_index(drop=True)


def fit_final_models(
    X_train_df: pd.DataFrame,
    *,
    detection_config: IsolationForestConfig,
    autoencoder_config: AutoencoderConfig,
) -> tuple[dict[str, Any], dict[str, Any], Any]:
    """
    Treina os modelos finais e persiste os artefatos oficiais.
    """
    clear_model_artifacts()

    X_train_matrix = to_feature_matrix(X_train_df)
    detection_bundle = train_model(
        X_train_matrix,
        config=detection_config,
        save_artifacts=True,
    )
    autoencoder_bundle = train_autoencoder(
        X_train_matrix,
        config=autoencoder_config,
        scaler=detection_bundle["scaler"],
        save_artifacts=True,
    )

    _, if_scores = predict(X_train_matrix, bundle=detection_bundle)
    _, ae_scores = predict_autoencoder(X_train_matrix, bundle=autoencoder_bundle)
    ensemble_config = build_ensemble_config_from_scores(
        if_scores,
        ae_scores,
        if_weight=DEFAULT_ENSEMBLE_CONFIG.if_weight,
        ae_weight=DEFAULT_ENSEMBLE_CONFIG.ae_weight,
        threshold=DEFAULT_ENSEMBLE_CONFIG.threshold,
        ae_reference_threshold_raw=float(autoencoder_bundle["threshold"]),
    )
    save_ensemble_config(ensemble_config)
    save_score_stat_reports(
        detection_bundle=detection_bundle,
        autoencoder_bundle=autoencoder_bundle,
    )

    return detection_bundle, autoencoder_bundle, ensemble_config


def fit_tuned_models(
    *,
    X_train_final_df: pd.DataFrame,
    detection_best_result: dict[str, Any],
    autoencoder_best_result: dict[str, Any],
    ensemble_best_result: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], Any]:
    """
    Treina os modelos finais usando as melhores configuracoes do tuning.
    """
    clear_model_artifacts()

    X_train_matrix = to_feature_matrix(X_train_final_df)
    detection_config = IsolationForestConfig(**detection_best_result["config"])
    autoencoder_config = AutoencoderConfig(**autoencoder_best_result["config"])

    detection_bundle = train_model(
        X_train_matrix,
        config=detection_config,
        save_artifacts=True,
    )
    autoencoder_bundle = train_autoencoder(
        X_train_matrix,
        config=autoencoder_config,
        scaler=detection_bundle["scaler"],
        save_artifacts=True,
    )

    _, if_scores = predict(X_train_matrix, bundle=detection_bundle)
    _, ae_scores = predict_autoencoder(X_train_matrix, bundle=autoencoder_bundle)
    best_config = ensemble_best_result["config"]
    ensemble_config = build_ensemble_config_from_scores(
        if_scores,
        ae_scores,
        if_weight=float(best_config["if_weight"]),
        ae_weight=float(best_config["ae_weight"]),
        threshold=float(best_config["threshold"]),
        ae_reference_threshold_raw=float(autoencoder_bundle["threshold"]),
    )
    save_ensemble_config(ensemble_config)
    save_score_stat_reports(
        detection_bundle=detection_bundle,
        autoencoder_bundle=autoencoder_bundle,
    )

    return detection_bundle, autoencoder_bundle, ensemble_config


def save_full_dataset_report(
    *,
    X_df: pd.DataFrame,
    y_series: pd.Series,
    detection_bundle: dict[str, Any],
    autoencoder_bundle: dict[str, Any],
    ensemble_config,
    input_file: str,
    tuning_enabled: bool,
    balance_strategy_selected: str,
) -> dict[str, Any]:
    """
    Gera um relatorio completo quando o treino e executado sem tuning.
    """
    full_report = evaluate_models_on_split(
        "full",
        X_df,
        y_series,
        detection_bundle=detection_bundle,
        autoencoder_bundle=autoencoder_bundle,
        ensemble_config=ensemble_config,
    )

    VALIDATION_PREDICTIONS_FILE.parent.mkdir(parents=True, exist_ok=True)
    full_report["predictions"].to_csv(VALIDATION_PREDICTIONS_FILE, index=False)

    report_payload = {
        "project_name": "Sinalyx",
        "feature_mode": describe_active_features(),
        "features": FEATURE_COLUMNS.copy(),
        "input_file": input_file,
        "tuning_enabled": bool(tuning_enabled),
        "balance_strategy_selected": balance_strategy_selected,
        "dataset_summary": {
            "full_dataset": summarize_target_distribution(y_series),
        },
        "final_evaluation": {
            "full": full_report["metrics"],
        },
        "artifacts": build_artifact_snapshot(
            detection_bundle=detection_bundle,
            autoencoder_bundle=autoencoder_bundle,
            ensemble_config=ensemble_config,
        ),
    }
    save_json_report(VALIDATION_REPORT_FILE, report_payload)
    return report_payload


def main() -> None:
    """
    Executa o treinamento dos modelos oficiais do Sinalyx pela CLI.

    Args:
        Nenhum parametro direto; os argumentos sao lidos de ``argparse``.

    Returns:
        None. Persiste modelos, estatisticas, manifest e relatorios em
        ``data/models`` conforme os caminhos oficiais do projeto.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default=str(FEATURES_FILE))
    parser.add_argument("--tune", action="store_true")
    parser.add_argument(
        "--balance-strategy",
        default="auto",
        choices=["auto", "none", "undersample_normal", "oversample_attack"],
    )
    parser.add_argument("--validation-size", type=float, default=0.15)
    parser.add_argument("--test-size", type=float, default=0.15)
    parser.add_argument("--random-state", type=int, default=42)
    parser.add_argument("--max-rows", type=int, default=None)
    args = parser.parse_args()

    print("[INFO] Carregando dataset de treino...")
    X_df, y_series = load_training_dataframe(args.input)
    y_series = validate_training_input(X_df, y_series)
    X_df, y_series = maybe_limit_rows(
        X_df,
        y_series,
        max_rows=args.max_rows,
        random_state=args.random_state,
    )

    print(f"[INFO] Features ativas no treino: {describe_active_features()}")
    print(f"[INFO] Shape final da matriz de treino: {X_df[FEATURE_COLUMNS].shape}")

    if not args.tune:
        print("[INFO] Executando treino sem tuning...")
        detection_bundle, autoencoder_bundle, ensemble_config = fit_final_models(
            X_df,
            detection_config=IsolationForestConfig(scaler_type="standard"),
            autoencoder_config=AutoencoderConfig(threshold_percentile=80),
        )

        report_payload = save_full_dataset_report(
            X_df=X_df,
            y_series=y_series,
            detection_bundle=detection_bundle,
            autoencoder_bundle=autoencoder_bundle,
            ensemble_config=ensemble_config,
            input_file=args.input,
            tuning_enabled=False,
            balance_strategy_selected="none",
        )

        manifest_payload = build_manifest_payload(
            input_file=args.input,
            X_df=X_df,
            y_series=y_series,
            tuning_enabled=False,
            random_state=args.random_state,
            balance_strategy_selected="none",
            detection_bundle=detection_bundle,
            autoencoder_bundle=autoencoder_bundle,
            ensemble_config=ensemble_config,
            evaluation=report_payload["final_evaluation"],
        )
        save_manifest(manifest_payload)

        print(f"[INFO] Previsoes salvas em: {VALIDATION_PREDICTIONS_FILE}")
        print(f"[INFO] Relatorio salvo em: {VALIDATION_REPORT_FILE}")
        print(f"[INFO] Manifesto salvo em: {MANIFEST_FILE}")
        return

    splits = split_train_validation_test(
        X_df,
        y_series,
        validation_size=args.validation_size,
        test_size=args.test_size,
        random_state=args.random_state,
    )

    print(f"[INFO] Split train: {summarize_target_distribution(splits['y_train'])}")
    print(f"[INFO] Split validation: {summarize_target_distribution(splits['y_validation'])}")
    print(f"[INFO] Split test: {summarize_target_distribution(splits['y_test'])}")

    X_validation_matrix = to_feature_matrix(splits["X_validation"])
    y_validation = splits["y_validation"].astype(int).tolist()

    strategy_results: list[dict[str, Any]] = []
    for balance_strategy in resolve_balance_strategies(args.balance_strategy):
        print(f"[INFO] Iniciando tuning com balance_strategy='{balance_strategy}'")
        X_train_balanced, y_train_balanced = apply_balance_strategy(
            splits["X_train"],
            splits["y_train"],
            strategy=balance_strategy,
            random_state=args.random_state,
        )

        X_train_matrix = to_feature_matrix(X_train_balanced)
        print(
            "[INFO] Distribuicao treino antes/depois do balanceamento: "
            f"{summarize_target_distribution(splits['y_train'])} -> "
            f"{summarize_target_distribution(y_train_balanced)}"
        )

        detection_tuning = tune_model(
            X_train_matrix,
            y_train_balanced,
            X_validation_matrix,
            y_validation,
            candidate_configs=build_standard_detection_candidates(),
        )
        autoencoder_tuning = tune_autoencoder(
            X_train_matrix,
            y_train_balanced,
            X_validation_matrix,
            y_validation,
            scaler=detection_tuning["best_bundle"]["scaler"],
        )
        ensemble_tuning = tune_ensemble(
            X_validation_matrix,
            y_validation,
            detection_bundle=detection_tuning["best_bundle"],
            autoencoder_bundle=autoencoder_tuning["best_bundle"],
        )

        strategy_results.append(
            {
                "balance_strategy": balance_strategy,
                "train_distribution_before": summarize_target_distribution(
                    splits["y_train"]
                ),
                "train_distribution_after": summarize_target_distribution(
                    y_train_balanced
                ),
                "detection": detection_tuning,
                "autoencoder": autoencoder_tuning,
                "ensemble": ensemble_tuning,
            }
        )

    best_strategy = pick_best_strategy_result(strategy_results)
    print(
        "[INFO] Melhor estrategia encontrada: "
        f"{best_strategy['balance_strategy']} "
        f"com metricas do ensemble={best_strategy['ensemble']['best_result']['metrics']}"
    )

    X_train_final = pd.concat(
        [splits["X_train"], splits["X_validation"]],
        ignore_index=True,
    )
    y_train_final = pd.concat(
        [splits["y_train"], splits["y_validation"]],
        ignore_index=True,
    )
    X_train_final_balanced, y_train_final_balanced = apply_balance_strategy(
        X_train_final,
        y_train_final,
        strategy=best_strategy["balance_strategy"],
        random_state=args.random_state,
    )

    detection_bundle, autoencoder_bundle, ensemble_config = fit_tuned_models(
        X_train_final_df=X_train_final_balanced,
        detection_best_result=best_strategy["detection"]["best_result"],
        autoencoder_best_result=best_strategy["autoencoder"]["best_result"],
        ensemble_best_result=best_strategy["ensemble"]["best_result"],
    )

    train_report = evaluate_models_on_split(
        "train",
        splits["X_train"],
        splits["y_train"],
        detection_bundle=detection_bundle,
        autoencoder_bundle=autoencoder_bundle,
        ensemble_config=ensemble_config,
    )
    validation_report = evaluate_models_on_split(
        "validation",
        splits["X_validation"],
        splits["y_validation"],
        detection_bundle=detection_bundle,
        autoencoder_bundle=autoencoder_bundle,
        ensemble_config=ensemble_config,
    )
    test_report = evaluate_models_on_split(
        "test",
        splits["X_test"],
        splits["y_test"],
        detection_bundle=detection_bundle,
        autoencoder_bundle=autoencoder_bundle,
        ensemble_config=ensemble_config,
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

    report_payload = {
        "project_name": "Sinalyx",
        "feature_mode": describe_active_features(),
        "features": FEATURE_COLUMNS.copy(),
        "input_file": args.input,
        "tuning_enabled": True,
        "balance_strategy_selected": best_strategy["balance_strategy"],
        "dataset_summary": {
            "full_dataset": summarize_target_distribution(y_series),
            "train": summarize_target_distribution(splits["y_train"]),
            "validation": summarize_target_distribution(splits["y_validation"]),
            "test": summarize_target_distribution(splits["y_test"]),
            "train_balanced_final": summarize_target_distribution(
                y_train_final_balanced
            ),
        },
        "tuning_results": [
            serialize_strategy_result(result)
            for result in strategy_results
        ],
        "best_configuration": {
            "balance_strategy": best_strategy["balance_strategy"],
            "isolation_forest": best_strategy["detection"]["best_result"],
            "autoencoder": best_strategy["autoencoder"]["best_result"],
            "ensemble": best_strategy["ensemble"]["best_result"],
            "saved_ensemble_config": asdict(ensemble_config),
        },
        "final_evaluation": {
            "train": train_report["metrics"],
            "validation": validation_report["metrics"],
            "test": test_report["metrics"],
        },
        "artifacts": build_artifact_snapshot(
            detection_bundle=detection_bundle,
            autoencoder_bundle=autoencoder_bundle,
            ensemble_config=ensemble_config,
        ),
    }
    save_json_report(VALIDATION_REPORT_FILE, report_payload)

    manifest_payload = build_manifest_payload(
        input_file=args.input,
        X_df=X_df,
        y_series=y_series,
        tuning_enabled=True,
        random_state=args.random_state,
        balance_strategy_selected=best_strategy["balance_strategy"],
        detection_bundle=detection_bundle,
        autoencoder_bundle=autoencoder_bundle,
        ensemble_config=ensemble_config,
        evaluation=report_payload["final_evaluation"],
    )
    save_manifest(manifest_payload)

    print(f"[INFO] Previsoes salvas em: {VALIDATION_PREDICTIONS_FILE}")
    print(f"[INFO] Relatorio salvo em: {VALIDATION_REPORT_FILE}")
    print(f"[INFO] Manifesto salvo em: {MANIFEST_FILE}")
    print(
        "[INFO] Metricas finais do decision engine no teste: "
        f"{test_report['metrics']['decision_engine']}"
    )


if __name__ == "__main__":
    main()
