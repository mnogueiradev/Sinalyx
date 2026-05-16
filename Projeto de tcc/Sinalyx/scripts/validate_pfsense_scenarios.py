"""
Valida os cenarios reais de pfSense do Sinalyx em pastas isoladas.

O script executa:
1. parse do log bruto
2. geracao do sinalyx_features.csv
3. inferencia oficial do lote
4. consolidacao de um resumo final por cenario
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.pipelines.infer_pfsense_batch import run_inference
from src.pipelines.parse_pfsense_logs import run_pipeline as run_parse_pipeline


SCENARIO_FILES = {
    "normal_firewall": Path("data/raw/pfsense/normal_firewall.log"),
    "port_scan": Path("data/raw/pfsense/port_scan.log"),
    "brute_force": Path("data/raw/pfsense/brute_force.log"),
    "syn_flood": Path("data/raw/pfsense/syn_flood.log"),
}

DEFAULT_OUTPUT_ROOT = Path("data/processed/pfsense/validation_runs")


def parse_args() -> argparse.Namespace:
    """
    Resolve argumentos do validador.
    """
    parser = argparse.ArgumentParser(
        description="Valida os quatro cenarios reais de pfSense em pastas isoladas.",
    )
    parser.add_argument("--output-root", default=str(DEFAULT_OUTPUT_ROOT))
    parser.add_argument("--window", default="5s")
    parser.add_argument("--runtime-profile", default="balanced")
    return parser.parse_args()


def _counter(series: pd.Series) -> dict[str, int]:
    """
    Conta valores de uma serie em formato serializavel.
    """
    return {
        str(key): int(value)
        for key, value in Counter(series.astype(str).tolist()).items()
    }


def _build_observation(
    scenario_name: str,
    results_df: pd.DataFrame,
) -> str:
    """
    Resume o que mais importa em cada cenario.
    """
    if results_df.empty:
        return "Sem linhas agregadas para inferencia."

    final_labels = _counter(results_df["final_label"])
    attack_types = _counter(results_df["attack_type"])
    risk_levels = _counter(results_df["risk_level"])

    dominant_label = max(final_labels, key=final_labels.get)
    dominant_attack_type = max(attack_types, key=attack_types.get)
    dominant_risk = max(risk_levels, key=risk_levels.get)

    if scenario_name == "normal_firewall":
        if dominant_label == "normal":
            return "Trafego benigno ficou majoritariamente normal."
        return "Ainda ha excesso de promocao de anomalia em trafego benigno."

    if dominant_attack_type != "normal":
        return (
            f"Cenario preservou o tipo {dominant_attack_type} com risco dominante {dominant_risk}."
        )

    return "Cenario ainda nao preservou um tipo de ataque final especifico."


def validate_scenarios(
    *,
    output_root: Path,
    window: str,
    runtime_profile: str,
) -> list[dict[str, Any]]:
    """
    Executa parse + inferencia para todos os cenarios configurados.
    """
    output_root.mkdir(parents=True, exist_ok=True)
    summary_rows: list[dict[str, Any]] = []

    for scenario_name, input_path in SCENARIO_FILES.items():
        scenario_dir = output_root / scenario_name
        scenario_dir.mkdir(parents=True, exist_ok=True)

        events_output = scenario_dir / "parsed_events.csv"
        features_output = scenario_dir / "sinalyx_features.csv"
        inference_output_csv = scenario_dir / "inference_results.csv"
        inference_output_json = scenario_dir / "inference_report.json"

        print(f"[INFO] Validando cenario {scenario_name} com runtime_profile={runtime_profile}.")
        events_df, features_df = run_parse_pipeline(
            input_path=input_path,
            events_output=events_output,
            features_output=features_output,
            window=window,
        )

        if features_df.empty:
            summary_rows.append(
                {
                    "scenario": scenario_name,
                    "parsed_lines": int(len(events_df)),
                    "aggregated_lines": 0,
                    "is_anomaly_counts": {},
                    "attack_type_counts": {},
                    "risk_level_counts": {},
                    "decision_source_counts": {},
                    "observation": "Nenhuma linha agregada foi gerada; inferencia nao executada.",
                }
            )
            continue

        results_df, _ = run_inference(
            input_path=features_output,
            output_csv=inference_output_csv,
            output_json=inference_output_json,
            runtime_profile=runtime_profile,
        )

        summary_rows.append(
            {
                "scenario": scenario_name,
                "parsed_lines": int(len(events_df)),
                "aggregated_lines": int(len(features_df)),
                "is_anomaly_counts": _counter(results_df["is_anomaly"]),
                "attack_type_counts": _counter(results_df["attack_type"]),
                "risk_level_counts": _counter(results_df["risk_level"]),
                "decision_source_counts": _counter(results_df["decision_source"]),
                "observation": _build_observation(scenario_name, results_df),
            }
        )

    return summary_rows


def main() -> None:
    """
    Executa a validacao dos quatro cenarios e salva um resumo consolidado.
    """
    args = parse_args()
    output_root = Path(args.output_root)
    summary_rows = validate_scenarios(
        output_root=output_root,
        window=args.window,
        runtime_profile=str(args.runtime_profile),
    )

    summary_df = pd.DataFrame(summary_rows)
    output_root.mkdir(parents=True, exist_ok=True)
    summary_csv = output_root / "validation_summary.csv"
    summary_json = output_root / "validation_summary.json"

    summary_df.to_csv(summary_csv, index=False)
    summary_json.write_text(
        json.dumps(summary_rows, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    print("[INFO] Resumo final dos cenarios reais:")
    print(summary_df.to_string(index=False))
    print(f"[INFO] Summary CSV: {summary_csv}")
    print(f"[INFO] Summary JSON: {summary_json}")


if __name__ == "__main__":
    main()
