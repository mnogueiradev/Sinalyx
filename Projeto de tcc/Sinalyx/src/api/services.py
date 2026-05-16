"""
Servicos reutilizaveis da API do Sinalyx.

Este modulo orquestra o fluxo oficial do pfSense sem duplicar a logica
central dos pipelines ja validados no projeto.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

import pandas as pd
from fastapi import UploadFile

from src.core.paths import BASE_DIR, DATA_DIR
from src.db.repository import (
    get_analysis as get_analysis_from_database,
    get_analysis_results as get_analysis_results_from_database,
    get_history_window_by_id as get_history_window_by_id_from_database,
    list_history_alerts as list_history_alerts_from_database,
    list_history_executions as list_history_executions_from_database,
    list_history_windows as list_history_windows_from_database,
    is_database_available,
    list_analyses as list_analyses_from_database,
    save_analysis as save_analysis_to_database,
    summarize_history as summarize_history_from_database,
)
from src.pipelines.infer_pfsense_batch import run_inference
from src.pipelines.parse_pfsense_logs import run_pipeline


ALLOWED_PFSENSE_SUFFIXES = {".log"}
API_RUNTIME_DIR = DATA_DIR / "runtime"
API_UPLOADS_DIR = API_RUNTIME_DIR / "api_uploads"
API_RESULTS_DIR = API_RUNTIME_DIR / "api_results"
ANALYSIS_SUMMARY_FILE = "analysis_summary.json"
ANALYSIS_RESULTS_FILE = "analysis_results.json"


class ApiServiceError(Exception):
    """
    Erro controlado de servico com dados suficientes para virar resposta HTTP.
    """

    def __init__(
        self,
        *,
        status_code: int,
        error_code: str,
        message: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.error_code = error_code
        self.message = message
        self.details = details or {}

    def to_http_detail(self) -> dict[str, Any]:
        """
        Converte o erro para o formato padrao da API.
        """
        return {
            "status": "error",
            "error_code": self.error_code,
            "message": self.message,
            "details": self.details,
        }


def ensure_api_runtime_dirs() -> None:
    """
    Garante a existencia das pastas usadas pela API.
    """
    API_UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
    API_RESULTS_DIR.mkdir(parents=True, exist_ok=True)


def _save_json(path: Path, payload: dict[str, Any]) -> None:
    """
    Persiste um JSON UTF-8 identado.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _load_json(path: Path) -> dict[str, Any]:
    """
    Carrega um JSON persistido pela camada da API.
    """
    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def _display_path(path: Path) -> str:
    """
    Tenta devolver caminhos relativos ao projeto para respostas mais limpas.
    """
    try:
        return str(path.relative_to(BASE_DIR))
    except ValueError:
        return str(path)


def _validate_analysis_id(analysis_id: str) -> str:
    """
    Garante que o identificador nao contenha componentes de caminho.
    """
    clean = analysis_id.strip()
    if not clean or Path(clean).name != clean:
        raise ApiServiceError(
            status_code=400,
            error_code="invalid_analysis_id",
            message="O identificador da analise informado e invalido.",
        )
    return clean


def _safe_pagination(limit: int = 50, offset: int = 0) -> tuple[int, int]:
    """
    Normaliza parametros de paginacao expostos pela API.
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
    Monta o bloco meta padronizado para endpoints paginados.
    """
    return {
        "total": int(total),
        "limit": int(limit),
        "offset": int(offset),
        "returned": int(returned),
    }


def _history_filters(
    *,
    final_label: str | None = None,
    attack_type: str | None = None,
    risk_level: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    ai_support: bool | str | None = None,
) -> dict[str, Any]:
    """
    Monta filtros historicos descartando parametros vazios.
    """
    filters: dict[str, Any] = {}
    for key, value in (
        ("final_label", final_label),
        ("attack_type", attack_type),
        ("risk_level", risk_level),
        ("date_from", date_from),
        ("date_to", date_to),
    ):
        if value is not None and str(value).strip():
            filters[key] = str(value).strip()
    if ai_support is not None:
        filters["ai_support"] = ai_support
    return filters


def _history_meta(
    *,
    total: int,
    limit: int,
    offset: int,
    returned: int,
    filters: dict[str, Any],
) -> dict[str, Any]:
    """
    Monta metadados paginados com filtros aplicados.
    """
    meta = _pagination_meta(
        total=total,
        limit=limit,
        offset=offset,
        returned=returned,
    )
    return {
        **meta,
        "filters": filters,
    }


def _history_error_response(
    *,
    code: str,
    message: str,
    filters: dict[str, Any],
    limit: int | None = None,
    offset: int | None = None,
    details: dict[str, Any] | None = None,
    data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Envelope padrao para falhas controladas dos endpoints historicos.
    """
    meta: dict[str, Any] = {"filters": filters}
    if limit is not None and offset is not None:
        meta.update(
            _pagination_meta(
                total=0,
                limit=limit,
                offset=offset,
                returned=0,
            )
        )
    return {
        "status": "error",
        "data": data or {},
        "meta": meta,
        "error": {
            "code": code,
            "message": message,
            "details": details or {},
        },
    }


def _compact_history_window(window: dict[str, Any]) -> dict[str, Any]:
    """
    Converte uma janela live persistida em item historico para frontend.
    """
    model_outputs = window.get("model_outputs") or {}
    metadata = window.get("metadata") or {}
    raw = window.get("raw") or {}
    ai_support_payload = (
        model_outputs.get("ai_support")
        or metadata.get("ai_support")
        or {}
    )
    decision_payload = (
        model_outputs.get("decision_engine")
        or raw.get("decision_engine")
        or {}
    )
    decision_reason = (
        window.get("decision_reason")
        or raw.get("decision_reason")
        or raw.get("explanation")
        or decision_payload.get("decision_reason")
        or decision_payload.get("reason")
        or decision_payload.get("explanation")
    )
    src_ip = metadata.get("src_ip") or raw.get("src_ip")
    dst_ip = (
        metadata.get("dst_ip")
        or metadata.get("destination_ip")
        or metadata.get("destination_ip_sample")
        or raw.get("dst_ip")
        or raw.get("destination_ip")
    )
    dst_port = (
        metadata.get("dst_port")
        or metadata.get("destination_port")
        or metadata.get("common_destination_ports")
        or raw.get("dst_port")
        or raw.get("destination_port")
    )
    protocol = metadata.get("protocol") or raw.get("protocol")
    action = metadata.get("action") or raw.get("action")
    ensemble_score = window.get("ensemble_score")
    autoencoder_score = window.get("autoencoder_score")
    isolation_score = window.get("isolation_score")

    return {
        "id": int(window.get("id") or 0),
        "window_uid": window.get("window_uid"),
        "execution_id": window.get("execution_id"),
        "created_at": window.get("created_at"),
        "status": window.get("status"),
        "local_log_path": window.get("local_log_path"),
        "remote_path": window.get("remote_path"),
        "parser_start_offset": window.get("parser_start_offset"),
        "parser_end_offset": window.get("parser_end_offset"),
        "window_id": window.get("window_id"),
        "window_timestamp": window.get("window_timestamp"),
        "window_start": window.get("window_start"),
        "window_end": window.get("window_end"),
        "final_label": window.get("final_label"),
        "attack_type": window.get("attack_type"),
        "risk_level": window.get("risk_level"),
        "decision_source": window.get("decision_source"),
        "decision_reason": decision_reason,
        "explanation": decision_reason,
        "confidence": window.get("confidence"),
        "ai_support": ai_support_payload.get("enabled"),
        "ai_support_conservative": ai_support_payload.get("conservative"),
        "ensemble_score": ensemble_score,
        "autoencoder_score": autoencoder_score,
        "isolation_score": isolation_score,
        "scores": {
            "ensemble": ensemble_score,
            "autoencoder": autoencoder_score,
            "isolation": isolation_score,
        },
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "protocol": protocol,
        "action": action,
        "features": window.get("features") or {},
        "model_outputs": model_outputs,
        "metadata": metadata,
    }


def _compact_history_summary(summary: dict[str, Any]) -> dict[str, Any]:
    """
    Compacta janelas recentes dentro do resumo historico.
    """
    live = dict(summary.get("live") or {})
    latest_window = live.get("latest_window")
    latest_alert = live.get("latest_alert")
    live["latest_window"] = (
        _compact_history_window(latest_window)
        if isinstance(latest_window, dict)
        else None
    )
    live["latest_alert"] = (
        _compact_history_window(latest_alert)
        if isinstance(latest_alert, dict)
        else None
    )

    return {
        "analyses": summary.get("analyses") or {},
        "live": live,
    }


def _sanitize_filename(filename: str) -> tuple[str, str]:
    """
    Normaliza o nome do arquivo e valida a extensao suportada.
    """
    clean_name = Path(filename).name.strip()
    if not clean_name:
        raise ApiServiceError(
            status_code=400,
            error_code="internal_error",
            message="O arquivo enviado precisa ter um nome valido.",
        )

    suffix = Path(clean_name).suffix.lower()
    if suffix not in ALLOWED_PFSENSE_SUFFIXES:
        raise ApiServiceError(
            status_code=415,
            error_code="invalid_extension",
            message="Somente arquivos .log sao aceitos.",
            details={"allowed_extensions": sorted(ALLOWED_PFSENSE_SUFFIXES)},
        )

    safe_stem = re.sub(r"[^A-Za-z0-9_-]+", "_", Path(clean_name).stem).strip("_")
    return clean_name, safe_stem or "upload"


def _build_analysis_paths(filename: str) -> dict[str, Any]:
    """
    Define caminhos temporarios e de saida para uma analise isolada.
    """
    clean_name, safe_stem = _sanitize_filename(filename)
    analysis_id = str(uuid4())
    created_at = datetime.now().astimezone().isoformat(timespec="seconds")
    suffix = Path(clean_name).suffix.lower()

    upload_path = API_UPLOADS_DIR / f"{safe_stem}_{analysis_id}{suffix}"
    result_dir = API_RESULTS_DIR / analysis_id

    return {
        "analysis_id": analysis_id,
        "created_at": created_at,
        "upload_path": upload_path,
        "result_dir": result_dir,
        "events_output": result_dir / f"{safe_stem}_parsed_events.csv",
        "features_output": result_dir / f"{safe_stem}_sinalyx_features.csv",
        "results_output": result_dir / f"{safe_stem}_inference_results.csv",
        "report_output": result_dir / f"{safe_stem}_inference_report.json",
        "summary_output": result_dir / ANALYSIS_SUMMARY_FILE,
        "api_results_output": result_dir / ANALYSIS_RESULTS_FILE,
    }


def _to_builtin(value: Any) -> Any:
    """
    Converte valores pandas/numpy para tipos nativos serializaveis.
    """
    if hasattr(value, "item"):
        return value.item()
    if isinstance(value, Path):
        return str(value)
    return value


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


def _parse_stats(events_df: pd.DataFrame) -> dict[str, int]:
    """
    Resume o resultado do parse para a resposta da API.
    """
    total_lines = int(len(events_df))
    if events_df.empty or "parsed_successfully" not in events_df.columns:
        parsed_successfully = 0
    else:
        parsed_successfully = int(
            events_df["parsed_successfully"].fillna(False).astype(bool).sum()
        )

    return {
        "total_lines": total_lines,
        "parsed_successfully": parsed_successfully,
        "parse_failures": total_lines - parsed_successfully,
    }


def _extract_parser_details(events_df: pd.DataFrame) -> dict[str, Any]:
    """
    Extrai algumas mensagens uteis quando o arquivo nao gera eventos validos.
    """
    details: dict[str, Any] = {}
    if "parse_status" in events_df.columns:
        details["parse_status_counts"] = {
            str(key): int(value)
            for key, value in events_df["parse_status"].fillna("failed").value_counts().items()
        }
    if "error" in events_df.columns:
        messages = [str(item) for item in events_df["error"].dropna().head(5).tolist()]
        if messages:
            details["sample_errors"] = messages
    return details


def _build_summary_counts(report_payload: dict[str, Any]) -> dict[str, int]:
    """
    Monta um resumo curto no formato esperado pelo endpoint.
    """
    summary = report_payload.get("summary", {})
    final_counts = summary.get("final_label_counts", {})
    risk_counts = summary.get("risk_level_counts", {})

    return {
        "normal": int(final_counts.get("normal", 0)),
        "anomaly": int(final_counts.get("anomaly", 0)),
        "high": int(risk_counts.get("high", 0)),
        "medium": int(risk_counts.get("medium", 0)),
        "low": int(risk_counts.get("low", 0)),
    }


def _build_counts(report_payload: dict[str, Any]) -> dict[str, dict[str, int]]:
    """
    Organiza os contadores principais da resposta.
    """
    summary = report_payload.get("summary", {})
    return {
        "prediction_counts": {
            str(key): int(value)
            for key, value in summary.get("final_label_counts", {}).items()
        },
        "attack_type_counts": {
            str(key): int(value)
            for key, value in summary.get("attack_type_counts", {}).items()
        },
        "risk_level_counts": {
            str(key): int(value)
            for key, value in summary.get("risk_level_counts", {}).items()
        },
        "decision_source_counts": {
            str(key): int(value)
            for key, value in summary.get("decision_source_counts", {}).items()
        },
        "ai_support_counts": {
            str(key): int(value)
            for key, value in summary.get("ai_support_counts", {}).items()
        },
        "ai_support_conservative_counts": {
            str(key): int(value)
            for key, value in summary.get("ai_support_conservative_counts", {}).items()
        },
        "ai_support_type_counts": {
            str(key): int(value)
            for key, value in summary.get("ai_support_type_counts", {}).items()
        },
        "ai_support_level_counts": {
            str(key): int(value)
            for key, value in summary.get("ai_support_level_counts", {}).items()
        },
    }


def _build_classification(results_df: pd.DataFrame) -> dict[str, Any]:
    """
    Calcula a classificacao predominante da analise.
    """
    final_counts = Counter(results_df["final_label"].astype(str).tolist())
    final_status = "anomaly" if final_counts.get("anomaly", 0) > 0 else "normal"

    attack_series = results_df["attack_type"].astype(str)
    risk_series = results_df["risk_level"].astype(str)
    confidence_avg = float(pd.to_numeric(results_df["confidence"], errors="coerce").fillna(0.0).mean())

    if final_status == "anomaly":
        anomalous_df = results_df[results_df["final_label"].astype(str) == "anomaly"]
        attack_candidates = anomalous_df["attack_type"].astype(str).tolist()
        risk_candidates = anomalous_df["risk_level"].astype(str).tolist()
    else:
        attack_candidates = attack_series.tolist()
        risk_candidates = risk_series.tolist()

    non_normal_attacks = [item for item in attack_candidates if item != "normal"]
    predominant_attack_type = (
        Counter(non_normal_attacks).most_common(1)[0][0]
        if non_normal_attacks
        else "normal"
    )
    predominant_risk_level = (
        Counter(risk_candidates).most_common(1)[0][0]
        if risk_candidates
        else "low"
    )

    return {
        "final_status": final_status,
        "predominant_attack_type": predominant_attack_type,
        "predominant_risk_level": predominant_risk_level,
        "confidence_avg": round(confidence_avg, 4),
    }


def _build_results_payload(results_df: pd.DataFrame) -> list[dict[str, Any]]:
    """
    Converte o DataFrame final em uma lista amigavel para a API.
    """
    ordered_columns = [
        "window_id",
        "window_start",
        "window_end",
        "src_ip",
        "event_count",
        "protocol",
        "action",
        "interface",
        "destination_ip_count",
        "destination_port_count",
        "common_destination_ports",
        "tcp_syn_count",
        "tcp_pa_count",
        "tcp_flags_summary",
        "connections",
        "bytes",
        "packets",
        "packet_size",
        "ports",
        "bytes_per_packet",
        "bytes_per_connection",
        "packets_per_connection",
        "log1p_connections",
        "log1p_bytes",
        "log1p_packets",
        "log1p_packet_size",
        "log1p_ports",
        "is_anomaly",
        "final_label",
        "attack_type",
        "risk_level",
        "confidence",
        "explanation",
        "decision_source",
        "decision_reason",
        "ensemble_score",
        "autoencoder_score",
        "isolation_score",
        "ai_support",
        "ai_support_conservative",
        "ai_support_type",
        "ai_support_level",
        "ai_support_reason",
        "ai_support_signals",
    ]

    records: list[dict[str, Any]] = []
    for record in results_df.to_dict(orient="records"):
        item = {
            column: _to_builtin(record.get(column))
            for column in ordered_columns
            if column in record
        }
        if "ai_support_signals" in item:
            item["ai_support_signals"] = _json_object_or_empty(
                item["ai_support_signals"]
            )
        records.append(item)
    return records


def _build_artifacts(paths: dict[str, Any]) -> dict[str, str]:
    """
    Monta o bloco de artefatos retornado pela API.
    """
    return {
        "uploaded_file": _display_path(paths["upload_path"]),
        "parsed_events_csv": _display_path(paths["events_output"]),
        "features_csv": _display_path(paths["features_output"]),
        "inference_results_csv": _display_path(paths["results_output"]),
        "inference_report_json": _display_path(paths["report_output"]),
        "analysis_summary_json": _display_path(paths["summary_output"]),
        "analysis_results_json": _display_path(paths["api_results_output"]),
    }


def _build_summary_payload(
    *,
    analysis_id: str,
    filename: str,
    created_at: str,
    parse_stats: dict[str, int],
    report_payload: dict[str, Any],
    results_df: pd.DataFrame,
    artifacts: dict[str, str],
) -> dict[str, Any]:
    """
    Monta a resposta resumida e persistivel da analise.
    """
    return {
        "status": "success",
        "analysis_id": analysis_id,
        "filename": filename,
        "created_at": created_at,
        "total_windows": int(len(results_df)),
        "summary": _build_summary_counts(report_payload),
        "classification": _build_classification(results_df),
        "counts": _build_counts(report_payload),
        "parse_stats": parse_stats,
        "artifacts": artifacts,
    }


def _build_results_response(
    summary_payload: dict[str, Any],
    results_payload: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    Combina resumo e resultados detalhados para o POST principal.
    """
    response = dict(summary_payload)
    response["results"] = results_payload
    return response


def _analysis_dir(analysis_id: str) -> Path:
    """
    Resolve o diretorio persistido de uma analise.
    """
    return API_RESULTS_DIR / _validate_analysis_id(analysis_id)


def _analysis_summary_path(analysis_id: str) -> Path:
    """
    Resolve o caminho do resumo persistido da analise.
    """
    return _analysis_dir(analysis_id) / ANALYSIS_SUMMARY_FILE


def _analysis_results_path(analysis_id: str) -> Path:
    """
    Resolve o caminho dos resultados detalhados persistidos da analise.
    """
    return _analysis_dir(analysis_id) / ANALYSIS_RESULTS_FILE


def _load_local_analysis_summary(analysis_id: str) -> dict[str, Any]:
    """
    Le o resumo persistido de uma analise anterior.
    """
    path = _analysis_summary_path(analysis_id)
    if not path.exists():
        raise ApiServiceError(
            status_code=404,
            error_code="analysis_not_found",
            message="Analise nao encontrada.",
            details={"analysis_id": analysis_id},
        )
    return _load_json(path)


def _load_local_analysis_results(
    analysis_id: str,
    *,
    limit: int = 50,
    offset: int = 0,
) -> dict[str, Any]:
    """
    Le os resultados detalhados persistidos de uma analise anterior.
    """
    path = _analysis_results_path(analysis_id)
    if not path.exists():
        raise ApiServiceError(
            status_code=404,
            error_code="analysis_not_found",
            message="Resultados da analise nao encontrados.",
            details={"analysis_id": analysis_id},
        )
    payload = _load_json(path)
    results = list(payload.get("results", []))
    safe_limit, safe_offset = _safe_pagination(limit, offset)
    page = results[safe_offset : safe_offset + safe_limit]
    return {
        **payload,
        "total_windows": int(payload.get("total_windows", len(results))),
        "results": page,
        "data": {"results": page},
        "meta": _pagination_meta(
            total=len(results),
            limit=safe_limit,
            offset=safe_offset,
            returned=len(page),
        ),
        "error": None,
    }


def _list_local_saved_analyses(limit: int = 50, offset: int = 0) -> dict[str, Any]:
    """
    Lista as analises persistidas localmente em disco.
    """
    safe_limit, safe_offset = _safe_pagination(limit, offset)
    ensure_api_runtime_dirs()
    items: list[dict[str, Any]] = []

    for directory in API_RESULTS_DIR.iterdir():
        if not directory.is_dir():
            continue
        summary_path = directory / ANALYSIS_SUMMARY_FILE
        if not summary_path.exists():
            continue
        try:
            summary = _load_json(summary_path)
        except Exception:
            continue

        classification = summary.get("classification", {})
        items.append(
            {
                "analysis_id": str(summary.get("analysis_id", directory.name)),
                "filename": str(summary.get("filename", "")),
                "created_at": str(summary.get("created_at", "")),
                "total_windows": int(summary.get("total_windows", 0)),
                "final_status": str(classification.get("final_status", "unknown")),
                "predominant_attack_type": str(
                    classification.get("predominant_attack_type", "unknown")
                ),
                "predominant_risk_level": str(
                    classification.get("predominant_risk_level", "unknown")
                ),
            }
        )

    items.sort(key=lambda item: item.get("created_at", ""), reverse=True)
    total = len(items)
    page = items[safe_offset : safe_offset + safe_limit]
    return {
        "status": "success",
        "total_analyses": total,
        "analyses": page,
        "data": {"analyses": page},
        "meta": _pagination_meta(
            total=total,
            limit=safe_limit,
            offset=safe_offset,
            returned=len(page),
        ),
        "error": None,
    }


def load_analysis_summary(analysis_id: str) -> dict[str, Any]:
    """
    Prioriza o PostgreSQL e usa os arquivos locais como fallback.
    """
    _validate_analysis_id(analysis_id)

    if is_database_available():
        try:
            summary = get_analysis_from_database(analysis_id)
        except Exception:
            summary = None
        if summary is not None:
            return summary

    return _load_local_analysis_summary(analysis_id)


def load_analysis_results(
    analysis_id: str,
    *,
    limit: int = 50,
    offset: int = 0,
) -> dict[str, Any]:
    """
    Prioriza o PostgreSQL e usa os arquivos locais como fallback.
    """
    _validate_analysis_id(analysis_id)
    safe_limit, safe_offset = _safe_pagination(limit, offset)

    if is_database_available():
        try:
            summary = get_analysis_from_database(analysis_id)
            result_page = get_analysis_results_from_database(
                analysis_id,
                limit=safe_limit,
                offset=safe_offset,
            )
        except Exception:
            summary = None
            result_page = {"total": 0, "results": []}
        if summary is not None:
            results = list(result_page.get("results", []))
            return {
                "status": "success",
                "analysis_id": str(summary["analysis_id"]),
                "filename": str(summary["filename"]),
                "created_at": str(summary["created_at"]),
                "total_windows": int(result_page.get("total", summary["total_windows"])),
                "results": results,
                "data": {"results": results},
                "meta": _pagination_meta(
                    total=int(result_page.get("total", len(results))),
                    limit=safe_limit,
                    offset=safe_offset,
                    returned=len(results),
                ),
                "error": None,
            }

    return _load_local_analysis_results(
        analysis_id,
        limit=safe_limit,
        offset=safe_offset,
    )


def list_saved_analyses(limit: int = 50, offset: int = 0) -> dict[str, Any]:
    """
    Prioriza o PostgreSQL e usa os arquivos locais como fallback.
    """
    safe_limit, safe_offset = _safe_pagination(limit, offset)
    if is_database_available():
        try:
            page = list_analyses_from_database(
                limit=safe_limit,
                offset=safe_offset,
            )
        except Exception:
            pass
        else:
            items = list(page.get("analyses", []))
            return {
                "status": "success",
                "total_analyses": int(page.get("total", len(items))),
                "analyses": items,
                "data": {"analyses": items},
                "meta": _pagination_meta(
                    total=int(page.get("total", len(items))),
                    limit=safe_limit,
                    offset=safe_offset,
                    returned=len(items),
                ),
                "error": None,
            }

    return _list_local_saved_analyses(limit=safe_limit, offset=safe_offset)


def get_history_summary(
    *,
    final_label: str | None = None,
    attack_type: str | None = None,
    risk_level: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    ai_support: bool | str | None = None,
) -> dict[str, Any]:
    """
    Retorna resumo historico estruturado para dashboard/frontend.
    """
    filters = _history_filters(
        final_label=final_label,
        attack_type=attack_type,
        risk_level=risk_level,
        date_from=date_from,
        date_to=date_to,
        ai_support=ai_support,
    )
    if not is_database_available():
        return _history_error_response(
            code="database_unavailable",
            message="PostgreSQL indisponivel para consultar historico.",
            filters=filters,
        )

    try:
        summary = summarize_history_from_database(filters)
    except Exception as exc:
        return _history_error_response(
            code="history_summary_query_failed",
            message="Falha ao consultar resumo historico no PostgreSQL.",
            filters=filters,
            details={"exception": str(exc)},
        )

    return {
        "status": "success",
        "data": _compact_history_summary(summary),
        "meta": {
            "source_tables": [
                "analyses",
                "analysis_results",
                "live_pfsense_windows",
            ],
            "filters": filters,
        },
        "error": None,
    }


def list_history_windows(
    *,
    limit: int = 50,
    offset: int = 0,
    final_label: str | None = None,
    attack_type: str | None = None,
    risk_level: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    ai_support: bool | str | None = None,
) -> dict[str, Any]:
    """
    Lista janelas live historicas com filtros estruturados.
    """
    safe_limit, safe_offset = _safe_pagination(limit, offset)
    filters = _history_filters(
        final_label=final_label,
        attack_type=attack_type,
        risk_level=risk_level,
        date_from=date_from,
        date_to=date_to,
        ai_support=ai_support,
    )
    if not is_database_available():
        return _history_error_response(
            code="database_unavailable",
            message="PostgreSQL indisponivel para listar janelas historicas.",
            filters=filters,
            limit=safe_limit,
            offset=safe_offset,
            data={"windows": []},
        )

    try:
        page = list_history_windows_from_database(
            limit=safe_limit,
            offset=safe_offset,
            filters=filters,
        )
    except Exception as exc:
        return _history_error_response(
            code="history_windows_query_failed",
            message="Falha ao listar janelas historicas no PostgreSQL.",
            filters=filters,
            limit=safe_limit,
            offset=safe_offset,
            details={"exception": str(exc)},
            data={"windows": []},
        )

    windows = [
        _compact_history_window(window)
        for window in page.get("windows", [])
    ]
    total = int(page.get("total", len(windows)))
    return {
        "status": "success",
        "data": {"windows": windows},
        "meta": _history_meta(
            total=total,
            limit=safe_limit,
            offset=safe_offset,
            returned=len(windows),
            filters=filters,
        ),
        "error": None,
    }


def get_history_window(window_id: int) -> dict[str, Any]:
    """
    Retorna uma janela historica especifica pelo ID primario.
    """
    clean_window_id = int(window_id)
    if clean_window_id <= 0:
        raise ApiServiceError(
            status_code=400,
            error_code="invalid_window_id",
            message="O identificador da janela informado e invalido.",
            details={"window_id": window_id},
        )

    if not is_database_available():
        raise ApiServiceError(
            status_code=503,
            error_code="database_unavailable",
            message="PostgreSQL indisponivel para consultar a janela historica.",
            details={"window_id": clean_window_id},
        )

    try:
        window = get_history_window_by_id_from_database(clean_window_id)
    except Exception as exc:
        raise ApiServiceError(
            status_code=500,
            error_code="history_window_query_failed",
            message="Falha ao consultar a janela historica no PostgreSQL.",
            details={"window_id": clean_window_id, "exception": str(exc)},
        ) from exc

    if window is None:
        raise ApiServiceError(
            status_code=404,
            error_code="history_window_not_found",
            message="Janela historica nao encontrada.",
            details={"window_id": clean_window_id},
        )

    return {
        "status": "success",
        "data": {"window": _compact_history_window(window)},
        "meta": {
            "source_table": "live_pfsense_windows",
            "window_id": clean_window_id,
        },
        "error": None,
    }


def list_history_alerts(
    *,
    limit: int = 50,
    offset: int = 0,
    final_label: str | None = None,
    attack_type: str | None = None,
    risk_level: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    ai_support: bool | str | None = None,
) -> dict[str, Any]:
    """
    Lista alertas historicos derivados das janelas live anomalas.
    """
    safe_limit, safe_offset = _safe_pagination(limit, offset)
    filters = _history_filters(
        final_label=final_label,
        attack_type=attack_type,
        risk_level=risk_level,
        date_from=date_from,
        date_to=date_to,
        ai_support=ai_support,
    )
    if not is_database_available():
        return _history_error_response(
            code="database_unavailable",
            message="PostgreSQL indisponivel para listar alertas historicos.",
            filters=filters,
            limit=safe_limit,
            offset=safe_offset,
            data={"alerts": []},
        )

    try:
        page = list_history_alerts_from_database(
            limit=safe_limit,
            offset=safe_offset,
            filters=filters,
        )
    except Exception as exc:
        return _history_error_response(
            code="history_alerts_query_failed",
            message="Falha ao listar alertas historicos no PostgreSQL.",
            filters=filters,
            limit=safe_limit,
            offset=safe_offset,
            details={"exception": str(exc)},
            data={"alerts": []},
        )

    alerts = [
        _compact_history_window(window)
        for window in page.get("alerts", [])
    ]
    total = int(page.get("total", len(alerts)))
    return {
        "status": "success",
        "data": {"alerts": alerts},
        "meta": _history_meta(
            total=total,
            limit=safe_limit,
            offset=safe_offset,
            returned=len(alerts),
            filters=filters,
        ),
        "error": None,
    }


def list_history_executions(
    *,
    limit: int = 50,
    offset: int = 0,
    final_label: str | None = None,
    attack_type: str | None = None,
    risk_level: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    ai_support: bool | str | None = None,
) -> dict[str, Any]:
    """
    Lista execucoes live derivadas das janelas persistidas.
    """
    safe_limit, safe_offset = _safe_pagination(limit, offset)
    filters = _history_filters(
        final_label=final_label,
        attack_type=attack_type,
        risk_level=risk_level,
        date_from=date_from,
        date_to=date_to,
        ai_support=ai_support,
    )
    if not is_database_available():
        return _history_error_response(
            code="database_unavailable",
            message="PostgreSQL indisponivel para listar execucoes historicas.",
            filters=filters,
            limit=safe_limit,
            offset=safe_offset,
            data={"executions": []},
        )

    try:
        page = list_history_executions_from_database(
            limit=safe_limit,
            offset=safe_offset,
            filters=filters,
        )
    except Exception as exc:
        return _history_error_response(
            code="history_executions_query_failed",
            message="Falha ao listar execucoes historicas no PostgreSQL.",
            filters=filters,
            limit=safe_limit,
            offset=safe_offset,
            details={"exception": str(exc)},
            data={"executions": []},
        )

    executions = list(page.get("executions", []))
    total = int(page.get("total", len(executions)))
    return {
        "status": "success",
        "data": {"executions": executions},
        "meta": _history_meta(
            total=total,
            limit=safe_limit,
            offset=safe_offset,
            returned=len(executions),
            filters=filters,
        ),
        "error": None,
    }


async def analyze_pfsense_upload(upload: UploadFile) -> dict[str, Any]:
    """
    Salva o upload temporariamente, executa o fluxo oficial do pfSense e
    devolve a resposta consolidada da API.
    """
    ensure_api_runtime_dirs()

    original_filename = upload.filename or ""
    clean_name, _ = _sanitize_filename(original_filename)
    file_bytes = await upload.read()
    await upload.close()

    if not file_bytes or not file_bytes.strip():
        raise ApiServiceError(
            status_code=400,
            error_code="empty_file",
            message="O arquivo enviado esta vazio.",
        )

    paths = _build_analysis_paths(clean_name)
    result_dir = paths["result_dir"]
    result_dir.mkdir(parents=True, exist_ok=True)
    paths["upload_path"].write_bytes(file_bytes)

    try:
        events_df, features_df = run_pipeline(
            input_path=paths["upload_path"],
            events_output=paths["events_output"],
            features_output=paths["features_output"],
        )
    except Exception as exc:
        raise ApiServiceError(
            status_code=500,
            error_code="parser_error",
            message="Falha ao executar o parser oficial do pfSense.",
            details={"exception": str(exc)},
        ) from exc

    parse_stats = _parse_stats(events_df)
    if parse_stats["total_lines"] == 0:
        raise ApiServiceError(
            status_code=400,
            error_code="empty_file",
            message="Nenhuma linha util foi encontrada no arquivo enviado.",
        )

    if parse_stats["parsed_successfully"] == 0:
        raise ApiServiceError(
            status_code=422,
            error_code="parser_error",
            message="Nenhuma linha do arquivo foi parseada com sucesso pelo parser do pfSense.",
            details=_extract_parser_details(events_df),
        )

    if features_df.empty:
        raise ApiServiceError(
            status_code=422,
            error_code="no_windows_generated",
            message="Nenhuma janela valida de 5 segundos foi gerada a partir do arquivo enviado.",
            details={
                "parse_stats": parse_stats,
                "parser": _extract_parser_details(events_df),
            },
        )

    try:
        results_df, report_payload = run_inference(
            input_path=paths["features_output"],
            output_csv=paths["results_output"],
            output_json=paths["report_output"],
        )
    except FileNotFoundError as exc:
        raise ApiServiceError(
            status_code=503,
            error_code="model_not_found",
            message="Os artefatos de modelo do Sinalyx nao foram encontrados.",
            details={"exception": str(exc)},
        ) from exc
    except ValueError as exc:
        raise ApiServiceError(
            status_code=422,
            error_code="inference_error",
            message="Nao foi possivel validar a entrada para inferencia.",
            details={"exception": str(exc)},
        ) from exc
    except RuntimeError as exc:
        raise ApiServiceError(
            status_code=503,
            error_code="inference_error",
            message="A inferencia nao pode ser executada com os modelos atuais.",
            details={"exception": str(exc)},
        ) from exc
    except Exception as exc:
        raise ApiServiceError(
            status_code=500,
            error_code="internal_error",
            message="Falha inesperada ao executar a inferencia oficial do Sinalyx.",
            details={"exception": str(exc)},
        ) from exc

    if results_df.empty:
        raise ApiServiceError(
            status_code=422,
            error_code="inference_error",
            message="A inferencia foi executada, mas nenhuma janela retornou resultado.",
        )

    artifacts = _build_artifacts(paths)
    summary_payload = _build_summary_payload(
        analysis_id=paths["analysis_id"],
        filename=clean_name,
        created_at=paths["created_at"],
        parse_stats=parse_stats,
        report_payload=report_payload,
        results_df=results_df,
        artifacts=artifacts,
    )
    results_payload = _build_results_payload(results_df)
    response_payload = _build_results_response(summary_payload, results_payload)
    analysis_results_payload = {
        "status": "success",
        "analysis_id": summary_payload["analysis_id"],
        "filename": summary_payload["filename"],
        "created_at": summary_payload["created_at"],
        "total_windows": summary_payload["total_windows"],
        "results": results_payload,
    }

    _save_json(paths["summary_output"], summary_payload)
    _save_json(paths["api_results_output"], analysis_results_payload)

    persistence_payload: dict[str, Any]
    try:
        save_analysis_to_database(summary_payload, results_payload)
    except Exception as exc:
        persistence_payload = {
            "database_saved": False,
            "error": str(exc),
        }
    else:
        persistence_payload = {
            "database_saved": True,
            "error": None,
        }

    response_payload["persistence"] = persistence_payload
    return response_payload
