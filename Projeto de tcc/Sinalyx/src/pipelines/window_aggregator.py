"""
Agregacao oficial de janelas para inferencia quase em tempo real do Sinalyx.

Regras centrais deste modulo:
- bucket temporal fixo de 5 segundos por padrao
- chave de agregacao principal = (src_ip, bucket_start)
- cada janela fechada gera 1 linha com metadados + 13 features do projeto

O modulo foi desenhado para ser reutilizado tanto pelo parse batch atual
quanto pelo processador de fluxo tail-like.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pandas as pd

from src.features.constants import FEATURE_COLUMNS
from src.features.engineering import select_active_feature_frame


DEFAULT_WINDOW_SECONDS = 5
DEFAULT_WINDOW_FREQUENCY = f"{DEFAULT_WINDOW_SECONDS}s"
WINDOW_METADATA_COLUMNS = [
    "window_id",
    "window_start",
    "window_end",
    "time_window",
    "src_ip",
    "source_ip",
    "event_count",
    "protocol",
    "action",
    "interface",
    "destination_ip_count",
    "destination_ip_sample",
    "destination_port_min",
    "destination_port_max",
    "destination_port_count",
    "common_destination_ports",
    "tcp_syn_count",
    "tcp_pa_count",
    "tcp_flags_summary",
    "blocked_count",
    "passed_count",
]
WINDOW_OUTPUT_COLUMNS = [*WINDOW_METADATA_COLUMNS, *FEATURE_COLUMNS]


def _resolve_window_seconds(window: str | int | float | None) -> int:
    """
    Resolve a duracao da janela em segundos inteiros.
    """
    if window is None:
        return DEFAULT_WINDOW_SECONDS

    if isinstance(window, (int, float)):
        seconds = float(window)
    else:
        seconds = float(pd.to_timedelta(str(window)).total_seconds())

    if seconds <= 0:
        raise ValueError("A janela precisa ser positiva.")

    rounded_seconds = int(round(seconds))
    if abs(seconds - rounded_seconds) > 1e-9:
        raise ValueError(
            "A janela precisa ser expressa em segundos inteiros para o agregador atual."
        )
    return rounded_seconds


def _normalize_text(value: Any, default: str) -> str:
    """
    Padroniza textos livres com fallback seguro.
    """
    if value is None:
        return default

    text = str(value).strip()
    return text if text else default


def _normalize_flag(value: Any) -> str:
    """
    Padroniza flags TCP em caixa alta.
    """
    if value is None:
        return ""
    return str(value).strip().upper()


def _safe_float(value: Any, default: float = 0.0) -> float:
    """
    Converte qualquer valor para float resiliente.
    """
    try:
        return float(value)
    except (TypeError, ValueError):
        return float(default)


def _safe_timestamp(value: Any) -> pd.Timestamp | None:
    """
    Converte timestamps para pandas.Timestamp quando possivel.
    """
    timestamp = pd.to_datetime(value, errors="coerce")
    if pd.isna(timestamp):
        return None
    return timestamp


def _safe_port(value: Any) -> int | None:
    """
    Normaliza uma porta quando ela estiver em faixa valida.
    """
    try:
        candidate = int(float(value))
    except (TypeError, ValueError):
        return None

    if 0 <= candidate <= 65535:
        return candidate
    return None


def _top_counter_key(counter: Counter[str], default: str) -> str:
    """
    Retorna a chave mais comum de um Counter textual.
    """
    if not counter:
        return default
    return str(counter.most_common(1)[0][0])


def _summarize_int_counter(counter: Counter[int], *, limit: int = 10) -> str:
    """
    Resume um Counter de portas em formato estavel para CSV/JSON.
    """
    if not counter:
        return ""
    return ",".join(str(value) for value, _ in counter.most_common(limit))


def _summarize_text_counter(counter: Counter[str], *, limit: int = 5) -> str:
    """
    Resume um Counter textual em formato chave:contagem.
    """
    if not counter:
        return ""
    return ",".join(
        f"{key}:{int(count)}"
        for key, count in counter.most_common(limit)
    )


def _record_is_eligible(record: dict[str, Any]) -> bool:
    """
    Decide se o evento pode entrar na agregacao.
    """
    if "parse_status" in record and str(record.get("parse_status") or "") != "full":
        return False
    if "parse_status" not in record and "parsed_successfully" in record:
        if not bool(record.get("parsed_successfully", False)):
            return False
    if "log_type" in record and str(record.get("log_type") or "") != "firewall":
        return False
    return True


def normalize_event_record(record: Any) -> dict[str, Any] | None:
    """
    Normaliza um evento parseado em um registro pronto para agregacao.
    """
    if hasattr(record, "to_dict"):
        raw = record.to_dict()
    elif isinstance(record, dict):
        raw = dict(record)
    else:
        raw = dict(record)

    if not _record_is_eligible(raw):
        return None

    timestamp = _safe_timestamp(raw.get("timestamp"))
    if timestamp is None:
        return None

    return {
        "timestamp": timestamp,
        "source_ip": _normalize_text(raw.get("source_ip"), "unknown_source"),
        "protocol": _normalize_text(raw.get("protocol"), "unknown_protocol").lower(),
        "action": _normalize_text(raw.get("action"), "unknown_action").lower(),
        "interface": _normalize_text(raw.get("interface"), "unknown_interface"),
        "destination_ip": _normalize_text(
            raw.get("destination_ip"),
            "unknown_destination",
        ),
        "destination_port": _safe_port(raw.get("destination_port")),
        "tcp_flags": _normalize_flag(raw.get("tcp_flags")),
        "bytes": max(_safe_float(raw.get("bytes"), 0.0), 0.0),
        "packets": max(_safe_float(raw.get("packets"), 1.0), 0.0),
    }


def prepare_events_dataframe(events_df: pd.DataFrame) -> pd.DataFrame:
    """
    Filtra e normaliza um DataFrame de eventos para a camada de janelas.
    """
    if events_df.empty:
        return pd.DataFrame(
            columns=[
                "timestamp",
                "source_ip",
                "protocol",
                "action",
                "interface",
                "destination_ip",
                "destination_port",
                "tcp_flags",
                "bytes",
                "packets",
            ]
        )

    normalized_records: list[dict[str, Any]] = []
    for record in events_df.to_dict(orient="records"):
        normalized = normalize_event_record(record)
        if normalized is not None:
            normalized_records.append(normalized)

    if not normalized_records:
        return pd.DataFrame(
            columns=[
                "timestamp",
                "source_ip",
                "protocol",
                "action",
                "interface",
                "destination_ip",
                "destination_port",
                "tcp_flags",
                "bytes",
                "packets",
            ]
        )

    prepared_df = pd.DataFrame(normalized_records)
    prepared_df = prepared_df.sort_values(
        by=["timestamp", "source_ip", "destination_ip"],
        kind="stable",
    ).reset_index(drop=True)
    return prepared_df


@dataclass
class WindowAggregateState:
    """
    Estado acumulado de uma janela fixa por `src_ip`.
    """

    source_ip: str
    window_start: pd.Timestamp
    window_seconds: int
    event_count: int = 0
    total_bytes: float = 0.0
    total_packets: float = 0.0
    protocol_counts: Counter[str] = field(default_factory=Counter)
    action_counts: Counter[str] = field(default_factory=Counter)
    interface_counts: Counter[str] = field(default_factory=Counter)
    destination_ip_counts: Counter[str] = field(default_factory=Counter)
    destination_port_counts: Counter[int] = field(default_factory=Counter)
    tcp_flag_counts: Counter[str] = field(default_factory=Counter)
    blocked_count: int = 0
    passed_count: int = 0

    @property
    def window_end(self) -> pd.Timestamp:
        """
        Limite superior exclusivo da janela.
        """
        return self.window_start + pd.Timedelta(seconds=self.window_seconds)

    def add_record(self, record: dict[str, Any]) -> None:
        """
        Incorpora um evento normalizado ao acumulador atual.
        """
        self.event_count += 1
        self.total_bytes += max(_safe_float(record.get("bytes"), 0.0), 0.0)
        self.total_packets += max(_safe_float(record.get("packets"), 0.0), 0.0)

        protocol = _normalize_text(record.get("protocol"), "unknown_protocol").lower()
        action = _normalize_text(record.get("action"), "unknown_action").lower()
        interface = _normalize_text(record.get("interface"), "unknown_interface")
        destination_ip = _normalize_text(
            record.get("destination_ip"),
            "unknown_destination",
        )
        tcp_flag = _normalize_flag(record.get("tcp_flags"))
        destination_port = _safe_port(record.get("destination_port"))

        self.protocol_counts[protocol] += 1
        self.action_counts[action] += 1
        self.interface_counts[interface] += 1
        self.destination_ip_counts[destination_ip] += 1
        if destination_port is not None:
            self.destination_port_counts[destination_port] += 1
        if tcp_flag:
            self.tcp_flag_counts[tcp_flag] += 1

        if action == "block":
            self.blocked_count += 1
        elif action == "pass":
            self.passed_count += 1

    def to_output_record(self) -> dict[str, Any]:
        """
        Converte o estado acumulado em 1 linha pronta para inferencia.
        """
        destination_ports = sorted(self.destination_port_counts.keys())
        destination_port_count = len(destination_ports)
        packet_size = (
            self.total_bytes / self.total_packets
            if self.total_packets > 0
            else 0.0
        )

        base_feature_row = {
            "connections": float(self.event_count),
            "bytes": float(self.total_bytes),
            "packets": float(self.total_packets),
            "packet_size": float(packet_size),
            "ports": float(destination_port_count),
        }
        feature_frame = select_active_feature_frame(pd.DataFrame([base_feature_row]))
        feature_values = feature_frame.iloc[0].to_dict()

        protocol = _top_counter_key(self.protocol_counts, "unknown_protocol")
        action = _top_counter_key(self.action_counts, "unknown_action")
        interface = _top_counter_key(self.interface_counts, "unknown_interface")
        destination_ip_sample = _top_counter_key(
            self.destination_ip_counts,
            "unknown_destination",
        )
        window_id = f"{self.source_ip}|{self.window_start.isoformat()}|{self.window_seconds}s"

        output = {
            "window_id": window_id,
            "window_start": self.window_start,
            "window_end": self.window_end,
            "time_window": self.window_start,
            "src_ip": self.source_ip,
            "source_ip": self.source_ip,
            "event_count": int(self.event_count),
            "protocol": protocol,
            "action": action,
            "interface": interface,
            "destination_ip_count": int(len(self.destination_ip_counts)),
            "destination_ip_sample": destination_ip_sample,
            "destination_port_min": (
                int(destination_ports[0]) if destination_ports else None
            ),
            "destination_port_max": (
                int(destination_ports[-1]) if destination_ports else None
            ),
            "destination_port_count": int(destination_port_count),
            "common_destination_ports": _summarize_int_counter(
                self.destination_port_counts,
                limit=10,
            ),
            "tcp_syn_count": int(
                self.tcp_flag_counts.get("S", 0) + self.tcp_flag_counts.get("SYN", 0)
            ),
            "tcp_pa_count": int(self.tcp_flag_counts.get("PA", 0)),
            "tcp_flags_summary": _summarize_text_counter(self.tcp_flag_counts, limit=5),
            "blocked_count": int(self.blocked_count),
            "passed_count": int(self.passed_count),
        }
        output.update(feature_values)
        return output


class PfSenseWindowAggregator:
    """
    Agregador incremental de janelas fixas por `src_ip`.
    """

    def __init__(self, window_seconds: int = DEFAULT_WINDOW_SECONDS) -> None:
        self.window_seconds = _resolve_window_seconds(window_seconds)
        self.window_frequency = f"{self.window_seconds}s"
        self._states: dict[tuple[str, pd.Timestamp], WindowAggregateState] = {}

    def _bucket_start(self, timestamp: pd.Timestamp) -> pd.Timestamp:
        """
        Resolve o inicio do bucket fixo para o timestamp informado.
        """
        return timestamp.floor(self.window_frequency)

    def _close_ready_states(
        self,
        *,
        reference_window_start: pd.Timestamp,
    ) -> list[dict[str, Any]]:
        """
        Fecha janelas cujo limite superior ja ficou para tras.
        """
        ready_keys = [
            key
            for key, state in self._states.items()
            if state.window_end <= reference_window_start
        ]
        ready_keys = sorted(ready_keys, key=lambda item: (item[1], item[0]))

        closed_records: list[dict[str, Any]] = []
        for key in ready_keys:
            state = self._states.pop(key)
            closed_records.append(state.to_output_record())
        return closed_records

    def add_event(self, event: Any) -> list[dict[str, Any]]:
        """
        Recebe um evento bruto/parseado e devolve janelas fechadas, se houver.
        """
        normalized = normalize_event_record(event)
        if normalized is None:
            return []

        return self.add_prepared_record(normalized)

    def add_prepared_record(self, record: dict[str, Any]) -> list[dict[str, Any]]:
        """
        Recebe um registro ja normalizado e atualiza a janela correspondente.
        """
        timestamp = _safe_timestamp(record.get("timestamp"))
        if timestamp is None:
            return []

        bucket_start = self._bucket_start(timestamp)
        source_ip = _normalize_text(record.get("source_ip"), "unknown_source")
        key = (source_ip, bucket_start)

        state = self._states.get(key)
        if state is None:
            state = WindowAggregateState(
                source_ip=source_ip,
                window_start=bucket_start,
                window_seconds=self.window_seconds,
            )
            self._states[key] = state

        state.add_record(record)
        return self._close_ready_states(reference_window_start=bucket_start)

    def flush_all(self) -> list[dict[str, Any]]:
        """
        Fecha e devolve todas as janelas restantes em ordem deterministica.
        """
        pending_keys = sorted(self._states.keys(), key=lambda item: (item[1], item[0]))
        flushed_records: list[dict[str, Any]] = []
        for key in pending_keys:
            state = self._states.pop(key)
            flushed_records.append(state.to_output_record())
        return flushed_records

    def build_dataframe(self, records: list[dict[str, Any]]) -> pd.DataFrame:
        """
        Converte linhas agregadas em DataFrame com colunas ordenadas.
        """
        return build_window_dataframe(records)


def build_window_dataframe(records: list[dict[str, Any]]) -> pd.DataFrame:
    """
    Converte registros agregados em DataFrame padronizado.
    """
    if not records:
        return pd.DataFrame(columns=WINDOW_OUTPUT_COLUMNS)

    output = pd.DataFrame(records)
    for column in WINDOW_OUTPUT_COLUMNS:
        if column not in output.columns:
            output[column] = pd.NA if column not in FEATURE_COLUMNS else 0.0
    return output[WINDOW_OUTPUT_COLUMNS].copy()


def build_windowed_feature_frame(
    events_df: pd.DataFrame,
    *,
    window: str | int | float | None = DEFAULT_WINDOW_FREQUENCY,
) -> pd.DataFrame:
    """
    Executa a agregacao oficial por janela fixa sobre um DataFrame de eventos.
    """
    prepared_df = prepare_events_dataframe(events_df)
    if prepared_df.empty:
        return pd.DataFrame(columns=WINDOW_OUTPUT_COLUMNS)

    aggregator = PfSenseWindowAggregator(_resolve_window_seconds(window))
    closed_records: list[dict[str, Any]] = []

    for record in prepared_df.to_dict(orient="records"):
        closed_records.extend(aggregator.add_prepared_record(record))

    closed_records.extend(aggregator.flush_all())
    return build_window_dataframe(closed_records)


def ensure_parent_dir(path: str | Path) -> None:
    """
    Garante que o diretorio pai exista antes de salvar saidas.
    """
    Path(path).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)
