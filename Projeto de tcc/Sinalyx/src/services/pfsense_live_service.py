"""
Servico live/quase em tempo real do pfSense para o Sinalyx.

Este modulo orquestra:
- coleta opcional do filter.log via SSH/SFTP
- leitura incremental por offset local
- agregacao por janelas de 1 minuto
- inferencia oficial do Sinalyx em memoria
- persistencia das janelas no PostgreSQL

Entrada:
- data/runtime/pfsense/live/filter.log ou arquivo configurado por ambiente.

Saida:
- estados JSON do coletor/parser
- artefatos por execucao em data/runtime/pfsense/live/runs/
- registros de janelas live no PostgreSQL
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

import pandas as pd

from src.collectors.pfsense_collector import (
    PfSenseCollectorConfig,
    collect_filter_log,
    read_collector_state,
)
from src.core.paths import BASE_DIR, DATA_DIR
from src.db.repository import (
    list_live_alerts as list_live_alerts_from_database,
    is_database_available,
    list_live_windows as list_live_windows_from_database,
    save_live_windows as save_live_windows_to_database,
    summarize_live_windows as summarize_live_windows_from_database,
)
from src.features.constants import FEATURE_COLUMNS
from src.parsers import PfSenseLogParser
from src.pipelines.parse_pfsense_logs import events_to_dataframe
from src.pipelines.window_aggregator import (
    WINDOW_OUTPUT_COLUMNS,
    build_windowed_feature_frame,
    prepare_events_dataframe,
)


LIVE_RUNTIME_DIR = DATA_DIR / "runtime" / "pfsense" / "live"
LIVE_RUNS_DIR = LIVE_RUNTIME_DIR / "runs"
DEFAULT_PARSER_STATE_PATH = LIVE_RUNTIME_DIR / "parser_state.json"
DEFAULT_LIVE_WINDOW = "1min"
PARSER_STATE_VERSION = 1


def _now_iso() -> str:
    """
    Retorna timestamp local com timezone.
    """
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _resolve_project_path(value: str | None, default: Path) -> Path:
    """
    Resolve caminhos relativos a partir da raiz do projeto.
    """
    if value is None or not str(value).strip():
        return default
    path = Path(value).expanduser()
    if path.is_absolute():
        return path
    return BASE_DIR / path


def _parser_state_path(local_log_path: Path | None = None) -> Path:
    """
    Resolve o caminho do estado incremental do parser live.
    """
    env_path = os.getenv("SINALYX_PFSENSE_PARSER_STATE_PATH")
    if env_path:
        return _resolve_project_path(env_path, DEFAULT_PARSER_STATE_PATH)
    if local_log_path is not None:
        return local_log_path.parent / "parser_state.json"
    return DEFAULT_PARSER_STATE_PATH


def _runtime_profile(runtime_profile: str | None = None) -> str | None:
    """
    Resolve o perfil de runtime usado na inferencia.
    """
    if runtime_profile is not None:
        return runtime_profile
    value = os.getenv("SINALYX_RUNTIME_PROFILE")
    return value if value else None


def _to_builtin(value: Any) -> Any:
    """
    Converte valores pandas/numpy/timestamp para JSON/SQLAlchemy.
    """
    if hasattr(value, "item"):
        value = value.item()
    if isinstance(value, pd.Timestamp):
        return value.isoformat()
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(key): _to_builtin(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_to_builtin(item) for item in value]
    if isinstance(value, float) and (pd.isna(value) or value in {float("inf"), float("-inf")}):
        return None
    if pd.isna(value) if not isinstance(value, (dict, list, tuple, str, bytes)) else False:
        return None
    return value


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    """
    Persiste payload JSON UTF-8.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(_to_builtin(payload), ensure_ascii=False, indent=2), encoding="utf-8")


def _read_json(path: Path) -> dict[str, Any]:
    """
    Le JSON de forma defensiva.
    """
    if not path.exists():
        return {}
    try:
        with path.open("r", encoding="utf-8") as file:
            payload = json.load(file)
        return payload if isinstance(payload, dict) else {}
    except Exception:
        return {}


def _json_object_or_empty(value: Any) -> dict[str, Any]:
    """
    Converte JSON textual em dicionario quando possivel.
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


def _safe_pagination(limit: int = 50, offset: int = 0) -> tuple[int, int]:
    """
    Normaliza parametros de paginacao expostos pela API live.
    """
    safe_limit = max(1, min(int(limit), 500))
    safe_offset = max(0, int(offset))
    return safe_limit, safe_offset


def _pagination_meta(
    *,
    total: int,
    limit: int,
    offset: int,
    returned: int,
) -> dict[str, int]:
    """
    Monta o bloco meta padronizado dos endpoints live.
    """
    return {
        "total": int(total),
        "limit": int(limit),
        "offset": int(offset),
        "returned": int(returned),
    }


def _display_path(path: Path) -> str:
    """
    Exibe caminhos relativos ao projeto quando possivel.
    """
    try:
        return str(path.resolve().relative_to(BASE_DIR))
    except ValueError:
        return str(path)


def ensure_live_runtime_dirs() -> None:
    """
    Garante as pastas usadas pelo fluxo live.
    """
    LIVE_RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    LIVE_RUNS_DIR.mkdir(parents=True, exist_ok=True)


def _default_parser_state(local_log_path: Path) -> dict[str, Any]:
    """
    Estado inicial do parser incremental.
    """
    return {
        "state_version": PARSER_STATE_VERSION,
        "local_path": str(local_log_path),
        "parser_state_path": str(_parser_state_path(local_log_path)),
        "offset": 0,
        "file_size": 0,
        "total_lines_processed": 0,
        "pending_events": [],
        "pending_events_count": 0,
        "last_run_at": None,
        "last_execution_id": None,
        "last_run_status": "never_run",
        "last_processing_mode": None,
        "last_error": None,
        "last_rotation_detected": False,
        "last_lines_new": 0,
        "last_windows_generated": 0,
    }


def get_parser_status() -> dict[str, Any]:
    """
    Retorna o estado atual do parser incremental live.
    """
    config = PfSenseCollectorConfig.from_env()
    local_log_path = config.local_path
    state_path = _parser_state_path(local_log_path)
    state = _default_parser_state(local_log_path)
    state.update(_read_json(state_path))
    state["local_path"] = str(local_log_path)
    state["parser_state_path"] = str(state_path)
    state["local_file_exists"] = local_log_path.exists()
    state["current_file_size"] = int(local_log_path.stat().st_size) if local_log_path.exists() else 0
    return _to_builtin(state)


def get_collector_status() -> dict[str, Any]:
    """
    Retorna o estado atual do coletor pfSense.
    """
    return read_collector_state(PfSenseCollectorConfig.from_env())


def _load_parser_state(local_log_path: Path) -> dict[str, Any]:
    """
    Carrega o estado incremental do parser.
    """
    state = _default_parser_state(local_log_path)
    state.update(_read_json(_parser_state_path(local_log_path)))
    pending = state.get("pending_events")
    if not isinstance(pending, list):
        pending = []
    state["pending_events"] = pending
    state["pending_events_count"] = len(pending)
    return state


def _save_parser_state(local_log_path: Path, state: dict[str, Any]) -> None:
    """
    Salva o estado incremental do parser.
    """
    pending = state.get("pending_events") or []
    state["pending_events_count"] = len(pending) if isinstance(pending, list) else 0
    state["local_path"] = str(local_log_path)
    state["parser_state_path"] = str(_parser_state_path(local_log_path))
    state["state_version"] = PARSER_STATE_VERSION
    _write_json(_parser_state_path(local_log_path), state)


def _read_new_lines(local_log_path: Path, state: dict[str, Any]) -> tuple[list[str], dict[str, Any]]:
    """
    Le apenas bytes ainda nao consumidos do arquivo local.
    """
    previous_offset = int(state.get("offset") or 0)
    previous_size = int(state.get("file_size") or 0)
    previous_total_lines = int(state.get("total_lines_processed") or 0)

    if not local_log_path.exists():
        return [], {
            "status": "error",
            "error": "Arquivo local do filter.log nao encontrado.",
            "offset_before": previous_offset,
            "offset_after": previous_offset,
            "file_size_before": previous_size,
            "file_size_after": 0,
            "rotation_detected": False,
            "lines_new": 0,
            "total_lines_before": previous_total_lines,
            "total_lines_after": previous_total_lines,
        }

    current_size = int(local_log_path.stat().st_size)
    rotation_detected = current_size < previous_offset or current_size < previous_size
    offset_before = 0 if rotation_detected else min(previous_offset, current_size)

    with local_log_path.open("rb") as file:
        file.seek(offset_before)
        raw_chunk = file.read()
        offset_after = int(file.tell())

    text = raw_chunk.decode("utf-8", errors="replace")
    lines = [line for line in text.splitlines() if line.strip()]
    total_lines_after = previous_total_lines + len(lines)
    if rotation_detected:
        total_lines_after = len(lines)

    return lines, {
        "status": "success",
        "error": None,
        "offset_before": int(offset_before),
        "offset_after": int(offset_after),
        "file_size_before": int(previous_size),
        "file_size_after": int(current_size),
        "rotation_detected": bool(rotation_detected),
        "lines_new": int(len(lines)),
        "total_lines_before": 0 if rotation_detected else previous_total_lines,
        "total_lines_after": int(total_lines_after),
    }


def _parse_new_lines(lines: list[str], *, start_line_number: int) -> tuple[pd.DataFrame, dict[str, Any]]:
    """
    Parseia as novas linhas usando o parser canonico do pfSense.
    """
    parser = PfSenseLogParser()
    parsed_events = [
        parser.parse_line(line, line_number=start_line_number + index)
        for index, line in enumerate(lines, start=1)
    ]
    events_df = events_to_dataframe(parsed_events)

    total_events = int(len(events_df))
    parsed_ok = (
        int(events_df["parsed_successfully"].fillna(False).astype(bool).sum())
        if not events_df.empty and "parsed_successfully" in events_df.columns
        else 0
    )
    parse_status_counts: dict[str, int] = {}
    if not events_df.empty and "parse_status" in events_df.columns:
        parse_status_counts = {
            str(key): int(value)
            for key, value in events_df["parse_status"].fillna("failed").value_counts().items()
        }

    return events_df, {
        "total_events": total_events,
        "parsed_successfully": parsed_ok,
        "parse_failures": total_events - parsed_ok,
        "parse_status_counts": parse_status_counts,
    }


def _split_closed_and_pending_events(
    prepared_df: pd.DataFrame,
    *,
    window: str,
    flush_pending: bool,
) -> tuple[pd.DataFrame, list[dict[str, Any]]]:
    """
    Separa janelas fechadas de eventos ainda pendentes.
    """
    if prepared_df.empty:
        return prepared_df, []

    prepared = prepared_df.copy()
    prepared["timestamp"] = pd.to_datetime(prepared["timestamp"], errors="coerce")
    prepared = prepared.dropna(subset=["timestamp"]).sort_values("timestamp", kind="stable")
    if prepared.empty:
        return pd.DataFrame(columns=prepared_df.columns), []

    if flush_pending:
        return prepared, []

    bucket = prepared["timestamp"].dt.floor(window)
    newest_bucket = bucket.max()
    closed_df = prepared[bucket < newest_bucket].copy()
    pending_df = prepared[bucket >= newest_bucket].copy()
    return closed_df, [
        _to_builtin(record)
        for record in pending_df.to_dict(orient="records")
    ]


def _save_dataframe(path: Path, dataframe: pd.DataFrame) -> None:
    """
    Salva DataFrame em CSV mesmo quando vazio.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    dataframe.to_csv(path, index=False)


def _normalize_feature_metadata_for_inference(features_df: pd.DataFrame) -> pd.DataFrame:
    """
    Converte metadados temporais para string antes do JSON de inferencia.

    No fluxo batch, essa normalizacao acontece naturalmente ao ler o CSV.
    No fluxo live em memoria, fazemos explicitamente para preservar o mesmo
    contrato sem alterar as 13 features numericas.
    """
    normalized = features_df.copy()
    for column in ("window_start", "window_end", "time_window"):
        if column not in normalized.columns:
            continue
        normalized[column] = normalized[column].map(
            lambda value: value.isoformat()
            if isinstance(value, (pd.Timestamp, datetime))
            else _to_builtin(value)
        )
    return normalized


def _extract_model_outputs(record: dict[str, Any]) -> dict[str, Any]:
    """
    Extrai scores e saidas relevantes dos modelos para persistencia.
    """
    return {
        "isolation_forest": {
            "pred": _to_builtin(record.get("pred_if")),
            "label": _to_builtin(record.get("label_if")),
            "raw_score": _to_builtin(record.get("score_if")),
            "normalized_score": _to_builtin(record.get("score_if_normalized")),
            "confidence": _to_builtin(record.get("if_confidence")),
        },
        "autoencoder": {
            "pred": _to_builtin(record.get("pred_ae")),
            "label": _to_builtin(record.get("label_ae")),
            "raw_score": _to_builtin(record.get("score_ae")),
            "log_score": _to_builtin(record.get("score_ae_log")),
            "normalized_score": _to_builtin(record.get("score_ae_normalized")),
            "confidence": _to_builtin(record.get("ae_confidence")),
            "threshold_raw": _to_builtin(record.get("ae_threshold_raw")),
            "threshold_log": _to_builtin(record.get("ae_threshold_log")),
        },
        "heuristic": {
            "pred": _to_builtin(record.get("pred_heuristic")),
            "attack_type": _to_builtin(record.get("heuristic_attack_type")),
            "confidence": _to_builtin(record.get("heuristic_confidence")),
            "reason": _to_builtin(record.get("heuristic_reason")),
        },
        "ensemble": {
            "pred": _to_builtin(record.get("pred_ensemble")),
            "score": _to_builtin(record.get("score_ensemble")),
            "threshold": _to_builtin(record.get("ensemble_threshold")),
            "runtime_profile": _to_builtin(record.get("runtime_profile")),
            "if_weight": _to_builtin(record.get("ensemble_if_weight")),
            "ae_weight": _to_builtin(record.get("ensemble_ae_weight")),
        },
        "ai_support": {
            "enabled": _to_builtin(record.get("ai_support")),
            "conservative": _to_builtin(record.get("ai_support_conservative")),
            "type": _to_builtin(record.get("ai_support_type")),
            "level": _to_builtin(record.get("ai_support_level")),
            "reason": _to_builtin(record.get("ai_support_reason")),
            "signals": _json_object_or_empty(record.get("ai_support_signals")),
        },
        "decision_engine": {
            "pred": _to_builtin(record.get("pred_decision_engine")),
            "is_anomaly": _to_builtin(record.get("is_anomaly")),
            "final_label": _to_builtin(record.get("final_label")),
            "attack_type": _to_builtin(record.get("attack_type")),
            "risk_level": _to_builtin(record.get("risk_level")),
            "confidence": _to_builtin(record.get("confidence")),
            "decision_source": _to_builtin(record.get("decision_source")),
            "decision_reason": _to_builtin(record.get("decision_reason")),
            "explanation": _to_builtin(record.get("explanation")),
        },
    }


def _window_uid(
    *,
    local_log_path: Path,
    parser_read: dict[str, Any],
    record: dict[str, Any],
) -> str:
    """
    Cria identificador deterministico para evitar persistencia duplicada.
    """
    payload = {
        "local_path": str(local_log_path),
        "window_id": _to_builtin(record.get("window_id")),
        "window_start": _to_builtin(record.get("window_start")),
        "window_end": _to_builtin(record.get("window_end")),
        "offset_before": parser_read.get("offset_before"),
        "offset_after": parser_read.get("offset_after"),
    }
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _build_live_window_records(
    *,
    execution_id: str,
    local_log_path: Path,
    remote_path: str,
    results_df: pd.DataFrame,
    parser_read: dict[str, Any],
    artifacts: dict[str, str],
    run_metadata: dict[str, Any],
) -> list[dict[str, Any]]:
    """
    Monta payloads persistiveis por janela live.
    """
    records: list[dict[str, Any]] = []
    for record in results_df.to_dict(orient="records"):
        features = {
            column: _to_builtin(record.get(column))
            for column in FEATURE_COLUMNS
            if column in record
        }
        model_outputs = _extract_model_outputs(record)
        metadata = {
            "window_id": _to_builtin(record.get("window_id")),
            "event_count": _to_builtin(record.get("event_count")),
            "src_ip": _to_builtin(record.get("src_ip") or record.get("source_ip")),
            "protocol": _to_builtin(record.get("protocol")),
            "action": _to_builtin(record.get("action")),
            "interface": _to_builtin(record.get("interface")),
            "destination_ip_count": _to_builtin(record.get("destination_ip_count")),
            "destination_ip_sample": _to_builtin(record.get("destination_ip_sample")),
            "destination_port_count": _to_builtin(record.get("destination_port_count")),
            "common_destination_ports": _to_builtin(record.get("common_destination_ports")),
            "tcp_syn_count": _to_builtin(record.get("tcp_syn_count")),
            "tcp_pa_count": _to_builtin(record.get("tcp_pa_count")),
            "tcp_flags_summary": _to_builtin(record.get("tcp_flags_summary")),
            "blocked_count": _to_builtin(record.get("blocked_count")),
            "passed_count": _to_builtin(record.get("passed_count")),
            "ai_support": model_outputs.get("ai_support", {}),
            "artifacts": artifacts,
            "run": run_metadata,
        }
        records.append(
            {
                "window_uid": _window_uid(
                    local_log_path=local_log_path,
                    parser_read=parser_read,
                    record=record,
                ),
                "execution_id": execution_id,
                "created_at": _now_iso(),
                "status": "success",
                "local_log_path": str(local_log_path),
                "remote_path": remote_path,
                "parser_start_offset": parser_read.get("offset_before"),
                "parser_end_offset": parser_read.get("offset_after"),
                "window_id": _to_builtin(record.get("window_id")),
                "window_timestamp": _to_builtin(record.get("window_start")),
                "window_start": _to_builtin(record.get("window_start")),
                "window_end": _to_builtin(record.get("window_end")),
                "features": features,
                "model_outputs": model_outputs,
                "final_label": _to_builtin(record.get("final_label")),
                "attack_type": _to_builtin(record.get("attack_type")),
                "risk_level": _to_builtin(record.get("risk_level")),
                "decision_source": _to_builtin(record.get("decision_source")),
                "confidence": _to_builtin(record.get("confidence")),
                "ensemble_score": _to_builtin(record.get("ensemble_score")),
                "autoencoder_score": _to_builtin(record.get("autoencoder_score")),
                "isolation_score": _to_builtin(record.get("isolation_score")),
                "metadata": metadata,
                "raw": _to_builtin(record),
            }
        )
    return records


def _compact_live_window(window: dict[str, Any]) -> dict[str, Any]:
    """
    Converte a janela persistida em um item previsivel para frontend.
    """
    model_outputs = window.get("model_outputs") or {}
    metadata = window.get("metadata") or {}
    ai_support_payload = (
        model_outputs.get("ai_support")
        or metadata.get("ai_support")
        or {}
    )

    return {
        "id": int(window.get("id") or 0),
        "execution_id": _to_builtin(window.get("execution_id")),
        "window_id": _to_builtin(window.get("window_id")),
        "window_start": _to_builtin(window.get("window_start")),
        "window_end": _to_builtin(window.get("window_end")),
        "final_label": _to_builtin(window.get("final_label")),
        "attack_type": _to_builtin(window.get("attack_type")),
        "risk_level": _to_builtin(window.get("risk_level")),
        "decision_source": _to_builtin(window.get("decision_source")),
        "ai_support": _to_builtin(ai_support_payload.get("enabled")),
        "ai_support_conservative": _to_builtin(
            ai_support_payload.get("conservative")
        ),
        "scores": {
            "ensemble": _to_builtin(window.get("ensemble_score")),
            "autoencoder": _to_builtin(window.get("autoencoder_score")),
            "isolation": _to_builtin(window.get("isolation_score")),
        },
        "features": _to_builtin(window.get("features") or {}),
        "metadata": _to_builtin(metadata),
    }


def _compact_recent_live_window(window: dict[str, Any]) -> dict[str, Any]:
    """
    Monta item resumido para cards/listas de dashboard.
    """
    compact = _compact_live_window(window)
    return {
        "id": compact["id"],
        "execution_id": compact["execution_id"],
        "window_id": compact["window_id"],
        "window_start": compact["window_start"],
        "window_end": compact["window_end"],
        "final_label": compact["final_label"],
        "attack_type": compact["attack_type"],
        "risk_level": compact["risk_level"],
        "decision_source": compact["decision_source"],
        "ai_support": compact["ai_support"],
        "ai_support_conservative": compact["ai_support_conservative"],
        "scores": compact["scores"],
    }


def _empty_live_run_response(
    *,
    execution_id: str,
    status: str,
    message: str,
    collector: dict[str, Any] | None,
    parser: dict[str, Any],
    processing_mode: str = "continuous",
    artifacts: dict[str, str] | None = None,
) -> dict[str, Any]:
    """
    Monta resposta comum para execucoes sem inferencia.
    """
    return {
        "status": status,
        "execution_id": execution_id,
        "processing_mode": processing_mode,
        "message": message,
        "collector": collector,
        "parser": parser,
        "window": {
            "frequency": parser.get("window_frequency", DEFAULT_LIVE_WINDOW),
            "generated": 0,
            "pending_events": parser.get("pending_events_count", 0),
            "processing_mode": processing_mode,
        },
        "persistence": {
            "database_saved": False,
            "saved": 0,
            "skipped_duplicates": 0,
            "errors": [],
        },
        "artifacts": artifacts or {},
    }


def process_live_pfsense(
    *,
    collect: bool = True,
    persist: bool = True,
    window: str = DEFAULT_LIVE_WINDOW,
    finite_file: bool = False,
    flush_pending: bool = False,
    runtime_profile: str | None = None,
) -> dict[str, Any]:
    """
    Executa uma rodada do fluxo live do pfSense.

    Args:
        collect: Quando true, copia primeiro o filter.log remoto via SFTP.
        persist: Quando true, salva janelas processadas no PostgreSQL.
        window: Janela temporal de agregacao. Padrao: 1min.
        finite_file: Modo oficial para replay/teste local de arquivo finito.
            Quando true, fecha tambem a ultima janela pendente.
        flush_pending: Compatibilidade com o comportamento tecnico anterior.
            Use `finite_file` para novas execucoes de replay local.
        runtime_profile: Perfil opcional do ensemble/decision engine.

    Returns:
        Resumo serializavel da execucao.
    """
    ensure_live_runtime_dirs()
    execution_id = str(uuid4())
    effective_flush_pending = bool(finite_file or flush_pending)
    processing_mode = "finite_file" if effective_flush_pending else "continuous"
    legacy_flush_pending_requested = bool(flush_pending and not finite_file)
    config = PfSenseCollectorConfig.from_env()
    local_log_path = config.local_path
    state = _load_parser_state(local_log_path)
    collector_state: dict[str, Any] | None = None

    if collect:
        collector_state = collect_filter_log(config)
        if collector_state.get("last_fetch_status") != "success":
            parser_status = {
                "last_run_at": _now_iso(),
                "last_execution_id": execution_id,
                "last_run_status": "collector_error",
                "last_processing_mode": processing_mode,
                "last_error": collector_state.get("error"),
                "window_frequency": window,
                "finite_file": bool(finite_file),
                "flush_pending": bool(effective_flush_pending),
                "pending_events_count": len(state.get("pending_events") or []),
            }
            return _empty_live_run_response(
                execution_id=execution_id,
                status="error",
                message="Coleta do filter.log falhou; parser incremental nao foi executado.",
                collector=collector_state,
                parser=parser_status,
                processing_mode=processing_mode,
            )

    lines, parser_read = _read_new_lines(local_log_path, state)
    if parser_read["status"] != "success":
        state.update(
            {
                "last_run_at": _now_iso(),
                "last_execution_id": execution_id,
                "last_run_status": "parser_error",
                "last_processing_mode": processing_mode,
                "last_error": parser_read.get("error"),
                "last_rotation_detected": parser_read.get("rotation_detected", False),
                "last_lines_new": 0,
                "last_windows_generated": 0,
            }
        )
        _save_parser_state(local_log_path, state)
        return _empty_live_run_response(
            execution_id=execution_id,
            status="error",
            message="Arquivo local do filter.log nao esta disponivel para leitura.",
            collector=collector_state,
            parser=parser_read,
            processing_mode=processing_mode,
        )

    run_dir = LIVE_RUNS_DIR / execution_id
    events_output = run_dir / "parsed_events.csv"
    features_output = run_dir / "sinalyx_live_features.csv"
    results_output = run_dir / "sinalyx_live_inference_results.csv"
    report_output = run_dir / "sinalyx_live_inference_report.json"
    summary_output = run_dir / "sinalyx_live_summary.json"

    events_df, parse_stats = _parse_new_lines(
        lines,
        start_line_number=int(parser_read.get("total_lines_before") or 0),
    )
    _save_dataframe(events_output, events_df)

    previous_pending = state.get("pending_events") or []
    if not isinstance(previous_pending, list):
        previous_pending = []

    prepared_new = prepare_events_dataframe(events_df)
    combined_prepared = pd.concat(
        [pd.DataFrame(previous_pending), prepared_new],
        ignore_index=True,
    )
    if not combined_prepared.empty:
        for column in ["timestamp", "source_ip", "protocol", "action", "interface"]:
            if column not in combined_prepared.columns:
                combined_prepared[column] = None

    closed_events_df, pending_events = _split_closed_and_pending_events(
        combined_prepared,
        window=window,
        flush_pending=effective_flush_pending,
    )
    features_df = build_windowed_feature_frame(closed_events_df, window=window)
    if features_df.empty:
        features_df = pd.DataFrame(columns=WINDOW_OUTPUT_COLUMNS)
    else:
        features_df = _normalize_feature_metadata_for_inference(features_df)
    _save_dataframe(features_output, features_df)

    parser_summary = {
        **parser_read,
        "parse_stats": parse_stats,
        "pending_events_carried_in": len(previous_pending),
        "pending_events_count": len(pending_events),
        "window_frequency": window,
        "processing_mode": processing_mode,
        "finite_file": bool(finite_file),
        "flush_pending": bool(effective_flush_pending),
        "legacy_flush_pending_requested": legacy_flush_pending_requested,
        "closed_events": int(len(closed_events_df)),
        "windows_generated": int(len(features_df)),
    }

    if features_df.empty:
        state.update(
            {
                "offset": parser_read["offset_after"],
                "file_size": parser_read["file_size_after"],
                "total_lines_processed": parser_read["total_lines_after"],
                "pending_events": pending_events,
                "last_run_at": _now_iso(),
                "last_execution_id": execution_id,
                "last_run_status": "success",
                "last_processing_mode": processing_mode,
                "last_error": None,
                "last_rotation_detected": parser_read["rotation_detected"],
                "last_lines_new": parser_read["lines_new"],
                "last_windows_generated": 0,
            }
        )
        _save_parser_state(local_log_path, state)
        artifacts = {
            "parsed_events_csv": _display_path(events_output),
            "features_csv": _display_path(features_output),
        }
        response = _empty_live_run_response(
            execution_id=execution_id,
            status="success",
            message="Nenhuma janela fechada foi gerada nesta execucao live.",
            collector=collector_state,
            parser=parser_summary,
            processing_mode=processing_mode,
            artifacts=artifacts,
        )
        _write_json(summary_output, response)
        return response

    try:
        from src.pipelines.infer_pfsense_batch import run_inference_from_frame

        results_df, report_payload = run_inference_from_frame(
            raw_df=features_df,
            input_label=f"live_pfsense:{_display_path(local_log_path)}",
            output_csv=results_output,
            output_json=report_output,
            runtime_profile=_runtime_profile(runtime_profile),
        )
    except Exception as exc:
        parser_summary["inference_error"] = str(exc)
        state.update(
            {
                "last_run_at": _now_iso(),
                "last_execution_id": execution_id,
                "last_run_status": "inference_error",
                "last_processing_mode": processing_mode,
                "last_error": str(exc),
                "last_rotation_detected": parser_read["rotation_detected"],
                "last_lines_new": parser_read["lines_new"],
                "last_windows_generated": int(len(features_df)),
            }
        )
        _save_parser_state(local_log_path, state)
        response = _empty_live_run_response(
            execution_id=execution_id,
            status="error",
            message="A inferencia live falhou; offset nao foi avancado para permitir retry.",
            collector=collector_state,
            parser=parser_summary,
            processing_mode=processing_mode,
            artifacts={
                "parsed_events_csv": _display_path(events_output),
                "features_csv": _display_path(features_output),
            },
        )
        _write_json(summary_output, response)
        return response

    artifacts = {
        "parsed_events_csv": _display_path(events_output),
        "features_csv": _display_path(features_output),
        "inference_results_csv": _display_path(results_output),
        "inference_report_json": _display_path(report_output),
        "summary_json": _display_path(summary_output),
    }
    run_metadata = {
        "pipeline": "process_live_pfsense",
        "window": window,
        "processing_mode": processing_mode,
        "finite_file": bool(finite_file),
        "flush_pending": bool(effective_flush_pending),
        "legacy_flush_pending_requested": legacy_flush_pending_requested,
        "runtime_profile": _runtime_profile(runtime_profile),
        "parser": parser_summary,
    }
    live_records = _build_live_window_records(
        execution_id=execution_id,
        local_log_path=local_log_path,
        remote_path=config.remote_path,
        results_df=results_df,
        parser_read=parser_read,
        artifacts=artifacts,
        run_metadata=run_metadata,
    )

    persistence = {
        "database_saved": False,
        "saved": 0,
        "skipped_duplicates": 0,
        "errors": [],
    }
    should_advance_state = not persist
    if persist:
        if not is_database_available():
            persistence["errors"] = ["PostgreSQL indisponivel para persistencia live."]
        else:
            try:
                from src.db.init_db import create_tables

                create_tables()
                persistence = save_live_windows_to_database(live_records)
                should_advance_state = len(persistence.get("errors", [])) == 0
            except Exception as exc:
                persistence["errors"] = [str(exc)]
    else:
        persistence["database_saved"] = False

    if should_advance_state:
        state.update(
            {
                "offset": parser_read["offset_after"],
                "file_size": parser_read["file_size_after"],
                "total_lines_processed": parser_read["total_lines_after"],
                "pending_events": pending_events,
                "last_run_at": _now_iso(),
                "last_execution_id": execution_id,
                "last_run_status": "success",
                "last_processing_mode": processing_mode,
                "last_error": None,
                "last_rotation_detected": parser_read["rotation_detected"],
                "last_lines_new": parser_read["lines_new"],
                "last_windows_generated": int(len(results_df)),
            }
        )
    else:
        state.update(
            {
                "last_run_at": _now_iso(),
                "last_execution_id": execution_id,
                "last_run_status": "persistence_error",
                "last_processing_mode": processing_mode,
                "last_error": "; ".join(str(item) for item in persistence.get("errors", [])),
                "last_rotation_detected": parser_read["rotation_detected"],
                "last_lines_new": parser_read["lines_new"],
                "last_windows_generated": int(len(results_df)),
            }
        )
    _save_parser_state(local_log_path, state)

    response = {
        "status": "success" if should_advance_state else "error",
        "execution_id": execution_id,
        "processing_mode": processing_mode,
        "message": (
            "Fluxo live do Sinalyx concluido."
            if should_advance_state
            else "Janelas processadas, mas persistencia falhou; offset nao foi avancado."
        ),
        "collector": collector_state,
        "parser": parser_summary,
        "window": {
            "frequency": window,
            "generated": int(len(results_df)),
            "pending_events": len(pending_events),
            "processing_mode": processing_mode,
        },
        "persistence": persistence,
        "artifacts": artifacts,
        "summary": report_payload.get("summary", {}),
        "results_preview": [
            _to_builtin(record)
            for record in results_df.head(10).to_dict(orient="records")
        ],
    }
    _write_json(summary_output, response)
    return response


def list_recent_live_windows(limit: int = 50, offset: int = 0) -> dict[str, Any]:
    """
    Lista as janelas live persistidas no PostgreSQL.
    """
    safe_limit, safe_offset = _safe_pagination(limit, offset)
    if not is_database_available():
        meta = _pagination_meta(
            total=0,
            limit=safe_limit,
            offset=safe_offset,
            returned=0,
        )
        return {
            "status": "error",
            "total_windows": 0,
            "windows": [],
            "data": {"windows": []},
            "meta": meta,
            "error": {
                "code": "database_unavailable",
                "message": "PostgreSQL indisponivel para listar janelas live.",
                "details": {},
            },
        }

    try:
        page = list_live_windows_from_database(
            limit=safe_limit,
            offset=safe_offset,
        )
    except Exception as exc:
        meta = _pagination_meta(
            total=0,
            limit=safe_limit,
            offset=safe_offset,
            returned=0,
        )
        return {
            "status": "error",
            "total_windows": 0,
            "windows": [],
            "data": {"windows": []},
            "meta": meta,
            "error": {
                "code": "live_windows_query_failed",
                "message": "Falha ao listar janelas live no PostgreSQL.",
                "details": {"exception": str(exc)},
            },
        }

    windows = [
        _compact_live_window(window)
        for window in page.get("windows", [])
    ]
    total = int(page.get("total", len(windows)))
    meta = _pagination_meta(
        total=total,
        limit=safe_limit,
        offset=safe_offset,
        returned=len(windows),
    )
    return {
        "status": "success",
        "total_windows": total,
        "windows": windows,
        "data": {"windows": windows},
        "meta": meta,
        "error": None,
    }


def get_dashboard_summary(recent_limit: int = 5) -> dict[str, Any]:
    """
    Resume o estado atual das janelas live para o dashboard.
    """
    safe_limit, _ = _safe_pagination(recent_limit, 0)
    if not is_database_available():
        return {
            "status": "error",
            "data": {},
            "meta": {
                "recent_limit": safe_limit,
                "source": "live_pfsense_windows",
            },
            "error": {
                "code": "database_unavailable",
                "message": "PostgreSQL indisponivel para gerar resumo do dashboard.",
                "details": {},
            },
        }

    try:
        summary = summarize_live_windows_from_database(recent_limit=safe_limit)
    except Exception as exc:
        return {
            "status": "error",
            "data": {},
            "meta": {
                "recent_limit": safe_limit,
                "source": "live_pfsense_windows",
            },
            "error": {
                "code": "dashboard_summary_query_failed",
                "message": "Falha ao gerar resumo live no PostgreSQL.",
                "details": {"exception": str(exc)},
            },
        }

    final_label_distribution = summary.get("final_label_distribution") or {}
    recent_windows = [
        _compact_recent_live_window(window)
        for window in summary.get("recent_windows", [])
    ]
    data = {
        "total_windows": int(summary.get("total", 0)),
        "total_normal": int(final_label_distribution.get("normal", 0)),
        "total_anomalies": int(final_label_distribution.get("anomaly", 0)),
        "attack_type_distribution": _to_builtin(
            summary.get("attack_type_distribution") or {}
        ),
        "risk_level_distribution": _to_builtin(
            summary.get("risk_level_distribution") or {}
        ),
        "ai_support_count": int(summary.get("ai_support_count", 0)),
        "ai_support_conservative_count": int(
            summary.get("ai_support_conservative_count", 0)
        ),
        "recent_windows": recent_windows,
    }
    return {
        "status": "success",
        "data": data,
        "meta": {
            "source": "live_pfsense_windows",
            "recent_limit": safe_limit,
            "returned_recent": len(recent_windows),
        },
        "error": None,
    }


def list_recent_alerts(limit: int = 50, offset: int = 0) -> dict[str, Any]:
    """
    Lista janelas live anomalas para a tela de alertas.
    """
    safe_limit, safe_offset = _safe_pagination(limit, offset)
    if not is_database_available():
        meta = _pagination_meta(
            total=0,
            limit=safe_limit,
            offset=safe_offset,
            returned=0,
        )
        return {
            "status": "error",
            "data": {"alerts": []},
            "meta": meta,
            "error": {
                "code": "database_unavailable",
                "message": "PostgreSQL indisponivel para listar alertas live.",
                "details": {},
            },
        }

    try:
        page = list_live_alerts_from_database(
            limit=safe_limit,
            offset=safe_offset,
        )
    except Exception as exc:
        meta = _pagination_meta(
            total=0,
            limit=safe_limit,
            offset=safe_offset,
            returned=0,
        )
        return {
            "status": "error",
            "data": {"alerts": []},
            "meta": meta,
            "error": {
                "code": "live_alerts_query_failed",
                "message": "Falha ao listar alertas live no PostgreSQL.",
                "details": {"exception": str(exc)},
            },
        }

    alerts = [
        _compact_live_window(window)
        for window in page.get("alerts", [])
    ]
    total = int(page.get("total", len(alerts)))
    meta = _pagination_meta(
        total=total,
        limit=safe_limit,
        offset=safe_offset,
        returned=len(alerts),
    )
    return {
        "status": "success",
        "data": {"alerts": alerts},
        "meta": meta,
        "error": None,
    }
