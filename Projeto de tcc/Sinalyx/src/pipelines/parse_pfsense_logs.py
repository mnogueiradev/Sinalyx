"""
Pipeline oficial de ingestao e agregacao de logs reais do pfSense.

Fluxo implementado:
1. le o arquivo bruto de log
2. parseia linha a linha com o PfSenseLogParser
3. salva todos os eventos parseados em CSV
4. agrega eventos validos em janelas temporais fixas
5. gera features compativeis com o Sinalyx

A estrategia oficial atual usa janela fixa de 5 segundos por `src_ip`.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

import pandas as pd

from src.features.constants import describe_active_features
from src.parsers import PfSenseLogParser
from src.pipelines.window_aggregator import (
    DEFAULT_WINDOW_FREQUENCY,
    WINDOW_METADATA_COLUMNS,
    build_windowed_feature_frame,
    ensure_parent_dir,
)


DEFAULT_EVENTS_OUTPUT = Path("data/processed/pfsense/parsed_events.csv")
DEFAULT_FEATURES_OUTPUT = Path("data/processed/pfsense/sinalyx_features.csv")
METADATA_COLUMNS = WINDOW_METADATA_COLUMNS.copy()


def parse_args() -> argparse.Namespace:
    """
    Define os argumentos de linha de comando do pipeline.
    """
    parser = argparse.ArgumentParser(
        description="Parseia logs do pfSense e gera features compativeis com o Sinalyx.",
    )
    parser.add_argument(
        "--input",
        required=True,
        help="Caminho do arquivo bruto de log do pfSense.",
    )
    parser.add_argument(
        "--events-output",
        default=str(DEFAULT_EVENTS_OUTPUT),
        help="CSV de saida com todos os eventos parseados.",
    )
    parser.add_argument(
        "--features-output",
        default=str(DEFAULT_FEATURES_OUTPUT),
        help="CSV de saida com as features agregadas para o Sinalyx.",
    )
    parser.add_argument(
        "--window",
        default=DEFAULT_WINDOW_FREQUENCY,
        help="Janela fixa de agregacao. Padrao oficial: 5s.",
    )
    return parser.parse_args()


def events_to_dataframe(events: list[Any]) -> pd.DataFrame:
    """
    Converte a lista de eventos parseados em DataFrame.
    """
    rows: list[dict[str, Any]] = []
    for event in events:
        if hasattr(event, "to_dict"):
            rows.append(event.to_dict())
        else:
            rows.append(dict(event))
    return pd.DataFrame(rows)


def build_sinalyx_features(
    events_df: pd.DataFrame,
    *,
    window: str = DEFAULT_WINDOW_FREQUENCY,
) -> pd.DataFrame:
    """
    Wrapper de compatibilidade para a agregacao oficial por janela.
    """
    return build_windowed_feature_frame(events_df, window=window)


def run_pipeline(
    *,
    input_path: str | Path,
    events_output: str | Path,
    features_output: str | Path,
    window: str = DEFAULT_WINDOW_FREQUENCY,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """
    Executa o pipeline completo de parse + agregacao.
    """
    parser = PfSenseLogParser()
    parsed_events = parser.parse_file(input_path)

    events_df = events_to_dataframe(parsed_events)
    features_df = build_sinalyx_features(events_df, window=window)

    ensure_parent_dir(events_output)
    ensure_parent_dir(features_output)

    events_df.to_csv(events_output, index=False)
    features_df.to_csv(features_output, index=False)

    return events_df, features_df


def main() -> None:
    """
    Ponto de entrada do script via CLI.
    """
    args = parse_args()
    events_df, features_df = run_pipeline(
        input_path=args.input,
        events_output=args.events_output,
        features_output=args.features_output,
        window=args.window,
    )

    total_lines = len(events_df)
    parsed_ok = (
        int(events_df["parsed_successfully"].fillna(False).astype(bool).sum())
        if not events_df.empty
        else 0
    )
    parsed_failed = total_lines - parsed_ok

    print("[INFO] Pipeline de logs pfSense concluido.")
    print(f"[INFO] Arquivo de entrada: {args.input}")
    print(f"[INFO] Eventos parseados salvos em: {args.events_output}")
    print(f"[INFO] Features salvas em: {args.features_output}")
    print(f"[INFO] Janela oficial utilizada: {args.window}")
    print(f"[INFO] Total de linhas processadas: {total_lines}")
    print(f"[INFO] Linhas parseadas com sucesso: {parsed_ok}")
    print(f"[INFO] Linhas com falha de parsing: {parsed_failed}")
    if "parse_status" in events_df.columns:
        parse_status_counts = events_df["parse_status"].fillna("failed").value_counts(dropna=False)
        for status, count in parse_status_counts.items():
            print(f"[INFO] parse_status={status}: {int(count)}")
    print(f"[INFO] Total de linhas agregadas para o Sinalyx: {len(features_df)}")
    print(f"[INFO] Features ativas no projeto: {describe_active_features()}")


if __name__ == "__main__":
    main()
