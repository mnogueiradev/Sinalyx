"""
Processador tail-like de logs pfSense para inferencia quase em tempo real.

Fluxo:
1. le novas linhas do arquivo
2. parseia cada linha com o parser oficial
3. agrega por janelas fixas de 5 segundos por src_ip
4. quando uma janela fecha, executa a inferencia existente
5. preserva metadados da janela na saida final
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any

import pandas as pd

from src.models.ensemble import load_all_models
from src.parsers import PfSenseLogParser
from src.pipelines.infer_pfsense_batch import run_inference_from_frame
from src.pipelines.window_aggregator import (
    DEFAULT_WINDOW_SECONDS,
    PfSenseWindowAggregator,
    build_window_dataframe,
    ensure_parent_dir,
)


DEFAULT_STREAM_OUTPUT_DIR = Path("data/processed/pfsense/stream")


class PfSenseStreamProcessor:
    """
    Orquestra parser, agregador e inferencia em modo de fluxo.
    """

    def __init__(
        self,
        *,
        input_path: str | Path,
        output_dir: str | Path = DEFAULT_STREAM_OUTPUT_DIR,
        runtime_profile: str | None = "balanced",
        window_seconds: int = DEFAULT_WINDOW_SECONDS,
        poll_interval: float = 1.0,
        start_at_end: bool = False,
    ) -> None:
        self.input_path = Path(input_path)
        self.output_dir = Path(output_dir)
        self.runtime_profile = runtime_profile
        self.poll_interval = float(poll_interval)
        self.start_at_end = bool(start_at_end)
        self.parser = PfSenseLogParser()
        self.aggregator = PfSenseWindowAggregator(window_seconds=window_seconds)
        self._models_loaded = False

        self.features_output = self.output_dir / "stream_windows.csv"
        self.results_output = self.output_dir / "stream_inference_results.csv"
        self.reports_output = self.output_dir / "stream_inference_reports.jsonl"

    def ensure_models_ready(self) -> None:
        """
        Carrega os modelos uma unica vez para o fluxo.
        """
        if self._models_loaded:
            return
        load_all_models()
        self._models_loaded = True

    def _append_dataframe(self, df: pd.DataFrame, path: Path) -> None:
        """
        Faz append de um DataFrame a um CSV sem perder cabecalho.
        """
        if df.empty:
            return

        ensure_parent_dir(path)
        header = not path.exists()
        df.to_csv(path, mode="a", header=header, index=False)

    def _append_report(self, report_payload: dict[str, Any]) -> None:
        """
        Salva relatarios parciais em JSONL.
        """
        ensure_parent_dir(self.reports_output)
        with self.reports_output.open("a", encoding="utf-8") as file:
            file.write(
                json.dumps(report_payload, ensure_ascii=False, default=str) + "\n"
            )

    def _infer_closed_records(self, closed_records: list[dict[str, Any]]) -> dict[str, Any] | None:
        """
        Converte janelas fechadas em DataFrame e executa a inferencia.
        """
        if not closed_records:
            return None

        features_df = build_window_dataframe(closed_records)
        if features_df.empty:
            return None

        self.ensure_models_ready()
        results_df, report_payload = run_inference_from_frame(
            raw_df=features_df,
            input_label=f"stream:{self.input_path}",
            output_csv=None,
            output_json=None,
            runtime_profile=self.runtime_profile,
            load_models=False,
        )

        self._append_dataframe(features_df, self.features_output)
        self._append_dataframe(results_df, self.results_output)
        self._append_report(report_payload)

        return {
            "features_df": features_df,
            "results_df": results_df,
            "report": report_payload,
        }

    def process_event(self, event: Any) -> dict[str, Any] | None:
        """
        Processa um evento ja parseado.
        """
        closed_records = self.aggregator.add_event(event)
        return self._infer_closed_records(closed_records)

    def process_line(self, line: str, *, line_number: int | None = None) -> dict[str, Any] | None:
        """
        Parseia e processa uma linha bruta do arquivo de log.
        """
        event = self.parser.parse_line(line, line_number=line_number)
        return self.process_event(event)

    def flush_pending(self) -> dict[str, Any] | None:
        """
        Fecha todas as janelas pendentes ao final do replay.
        """
        pending_records = self.aggregator.flush_all()
        return self._infer_closed_records(pending_records)

    def process_existing_file(self) -> list[dict[str, Any]]:
        """
        Executa um replay completo do arquivo atual e fecha o que restar.
        """
        batches: list[dict[str, Any]] = []
        for line_number, line in enumerate(
            self.parser.read_log_file(self.input_path),
            start=1,
        ):
            if not line.strip():
                continue
            result = self.process_line(line, line_number=line_number)
            if result is not None:
                batches.append(result)

        final_result = self.flush_pending()
        if final_result is not None:
            batches.append(final_result)
        return batches

    def follow_file(
        self,
        *,
        stop_when_eof: bool = False,
    ) -> list[dict[str, Any]]:
        """
        Acompanha o arquivo em modo tail-like.

        Quando `stop_when_eof=True`, o metodo funciona como replay controlado
        e fecha as janelas restantes ao terminar de ler o arquivo.
        """
        batches: list[dict[str, Any]] = []
        line_number = 0

        with self.input_path.open("r", encoding="utf-8", errors="replace") as file:
            if self.start_at_end:
                file.seek(0, 2)

            while True:
                position = file.tell()
                line = file.readline()
                if line:
                    line_number += 1
                    normalized_line = line.rstrip("\n")
                    if not normalized_line.strip():
                        continue
                    result = self.process_line(normalized_line, line_number=line_number)
                    if result is not None:
                        batches.append(result)
                    continue

                if stop_when_eof:
                    break

                file.seek(position)
                time.sleep(self.poll_interval)

        if stop_when_eof:
            final_result = self.flush_pending()
            if final_result is not None:
                batches.append(final_result)
        return batches


def parse_args() -> argparse.Namespace:
    """
    Resolve argumentos CLI do processador de fluxo.
    """
    parser = argparse.ArgumentParser(
        description="Processa logs pfSense em modo replay ou tail-like com janela fixa de 5 segundos.",
    )
    parser.add_argument("--input", required=True, help="Arquivo de log pfSense a acompanhar.")
    parser.add_argument(
        "--output-dir",
        default=str(DEFAULT_STREAM_OUTPUT_DIR),
        help="Diretorio onde as janelas e resultados serao persistidos.",
    )
    parser.add_argument(
        "--runtime-profile",
        default="balanced",
        help="Perfil operacional da inferencia.",
    )
    parser.add_argument(
        "--poll-interval",
        type=float,
        default=1.0,
        help="Intervalo de polling em segundos no modo tail-like.",
    )
    parser.add_argument(
        "--start-at-end",
        action="store_true",
        help="Comeca acompanhando o arquivo a partir do fim atual.",
    )
    parser.add_argument(
        "--stop-when-eof",
        action="store_true",
        help="Processa o arquivo atual ate o EOF e encerra, fechando as janelas pendentes.",
    )
    return parser.parse_args()


def main() -> None:
    """
    Executa o processador de fluxo por CLI.
    """
    args = parse_args()
    processor = PfSenseStreamProcessor(
        input_path=args.input,
        output_dir=args.output_dir,
        runtime_profile=args.runtime_profile,
        window_seconds=DEFAULT_WINDOW_SECONDS,
        poll_interval=args.poll_interval,
        start_at_end=args.start_at_end,
    )

    if args.stop_when_eof:
        batches = processor.follow_file(stop_when_eof=True)
    else:
        batches = processor.follow_file(stop_when_eof=False)

    emitted_windows = sum(
        len(batch["results_df"])
        for batch in batches
        if batch is not None
    )
    print(f"[INFO] Arquivo monitorado: {args.input}")
    print(f"[INFO] Diretoria de saida: {processor.output_dir}")
    print(f"[INFO] Lotes emitidos: {len(batches)}")
    print(f"[INFO] Janelas inferidas: {emitted_windows}")
    print(f"[INFO] CSV de janelas: {processor.features_output}")
    print(f"[INFO] CSV de inferencia: {processor.results_output}")
    print(f"[INFO] Relatorios JSONL: {processor.reports_output}")


if __name__ == "__main__":
    main()
