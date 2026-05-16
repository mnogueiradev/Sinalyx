"""
Repositorio SQLAlchemy para o historico de analises da API.
"""

from __future__ import annotations

import math
import os
from datetime import datetime
from typing import Any

from src.auth.security import hash_password, verify_password
from src.db.database import (
    DATABASE_ENABLED,
    DATABASE_INIT_ERROR,
    SQLALCHEMY_INSTALLED,
    SessionLocal,
    engine,
)

if SQLALCHEMY_INSTALLED:
    from sqlalchemy import func, select, text
    from sqlalchemy.exc import IntegrityError
else:
    IntegrityError = None
    func = None
    select = None
    text = None


def _database_ready() -> bool:
    return (
        DATABASE_ENABLED
        and SQLALCHEMY_INSTALLED
        and SessionLocal is not None
        and engine is not None
    )


def _require_database() -> None:
    if not _database_ready():
        raise RuntimeError(
            DATABASE_INIT_ERROR
            or "Integracao com PostgreSQL indisponivel no ambiente atual."
        )


def _normalize_value(value: Any) -> Any:
    if hasattr(value, "item"):
        value = value.item()

    if isinstance(value, dict):
        return {str(key): _normalize_value(item) for key, item in value.items()}

    if isinstance(value, (list, tuple)):
        return [_normalize_value(item) for item in value]

    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            return None
        return value

    if isinstance(value, datetime):
        return value.isoformat()

    return value


def _as_string(value: Any) -> str | None:
    value = _normalize_value(value)
    if value is None:
        return None
    return str(value)


def _as_float(value: Any) -> float | None:
    value = _normalize_value(value)
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _as_bool(value: Any) -> bool | None:
    value = _normalize_value(value)
    if value is None:
        return None
    return bool(value)


def _is_truthy_flag(value: Any) -> bool:
    """
    Normaliza flags vindas de JSON para contagem em consultas agregadas.
    """
    normalized = _normalize_value(value)
    if isinstance(normalized, str):
        return normalized.strip().lower() in {"1", "true", "yes", "sim"}
    return bool(normalized)


def _parse_created_at(value: Any) -> datetime:
    normalized = _normalize_value(value)
    if isinstance(normalized, datetime):
        return normalized
    if isinstance(normalized, str) and normalized.strip():
        try:
            return datetime.fromisoformat(normalized)
        except ValueError:
            pass
    return datetime.now().astimezone()


def _now() -> datetime:
    """
    Timestamp timezone-aware usado pelos registros administrativos.
    """
    return datetime.now().astimezone()


def _parse_optional_datetime(value: Any) -> datetime | None:
    """
    Converte valores opcionais para datetime.
    """
    normalized = _normalize_value(value)
    if normalized is None or normalized == "":
        return None
    if isinstance(normalized, datetime):
        return normalized
    if isinstance(normalized, str):
        try:
            return datetime.fromisoformat(normalized)
        except ValueError:
            return None
    return None


def _serialize_datetime(value: Any) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def _analysis_to_summary_dict(analysis: Any) -> dict[str, Any]:
    summary_json = _normalize_value(analysis.summary_json or {})
    counts_json = _normalize_value(analysis.counts_json or {})
    parse_stats_json = _normalize_value(analysis.parse_stats_json or {})
    artifacts_json = _normalize_value(analysis.artifacts_json or {})

    return {
        "status": "success",
        "analysis_id": str(analysis.id),
        "filename": str(analysis.filename),
        "created_at": _serialize_datetime(analysis.created_at),
        "total_windows": int(analysis.total_windows or 0),
        "summary": summary_json,
        "classification": {
            "final_status": str(analysis.final_status or "unknown"),
            "predominant_attack_type": str(
                analysis.predominant_attack_type or "unknown"
            ),
            "predominant_risk_level": str(
                analysis.predominant_risk_level or "unknown"
            ),
            "confidence_avg": (
                float(analysis.confidence_avg)
                if analysis.confidence_avg is not None
                else None
            ),
        },
        "counts": counts_json,
        "parse_stats": parse_stats_json,
        "artifacts": artifacts_json,
    }


def _analysis_to_list_item(analysis: Any) -> dict[str, Any]:
    return {
        "analysis_id": str(analysis.id),
        "filename": str(analysis.filename),
        "created_at": _serialize_datetime(analysis.created_at),
        "total_windows": int(analysis.total_windows or 0),
        "final_status": str(analysis.final_status or "unknown"),
        "predominant_attack_type": str(analysis.predominant_attack_type or "unknown"),
        "predominant_risk_level": str(analysis.predominant_risk_level or "unknown"),
    }


def _normalize_email(email: str) -> str:
    return str(email or "").strip().lower()


def _normalize_role(role: str | None) -> str:
    clean = str(role or "user").strip().lower()
    if clean not in {"admin", "user"}:
        raise ValueError("Papel de usuario invalido. Use admin ou user.")
    return clean


def _supreme_admin_email() -> str:
    """
    Email do administrador supremo protegido contra remocao/desativacao.
    """
    return _normalize_email(
        os.getenv("SINALYX_SUPER_ADMIN_EMAIL")
        or os.getenv("SINALYX_ADMIN_EMAIL")
        or "admin@sinalyx.local"
    )


def _is_supreme_admin(user: Any) -> bool:
    """
    Indica se o usuario e o administrador supremo do sistema.
    """
    return _normalize_email(getattr(user, "email", "")) == _supreme_admin_email()


def _has_other_active_admin(session: Any, User: Any, user_id: int) -> bool:
    """
    Verifica se existe outro administrador ativo alem do usuario informado.
    """
    count = int(
        session.execute(
            select(func.count())
            .select_from(User)
            .where(
                User.role == "admin",
                User.is_active.is_(True),
                User.id != int(user_id),
            )
        ).scalar_one()
    )
    return count > 0


def _user_to_dict(user: Any) -> dict[str, Any]:
    """
    Serializa usuario sem expor hash de senha.
    """
    return {
        "id": int(user.id),
        "name": _as_string(user.name) or "",
        "email": _as_string(user.email) or "",
        "role": _as_string(user.role) or "user",
        "is_active": bool(user.is_active),
        "is_protected": _is_supreme_admin(user),
        "created_at": _serialize_datetime(user.created_at),
        "updated_at": _serialize_datetime(user.updated_at),
    }


def _safe_limit_offset(limit: int = 50, offset: int = 0) -> tuple[int, int]:
    """
    Normaliza parametros de paginacao usados pelo PostgreSQL.
    """
    safe_limit = max(1, min(int(limit), 500))
    safe_offset = max(0, int(offset))
    return safe_limit, safe_offset


def _result_to_dict(result: Any) -> dict[str, Any]:
    payload = _normalize_value(result.raw_json or {})
    payload.update(
        {
            "window_id": _as_string(result.window_id),
            "window_start": _as_string(result.window_start),
            "window_end": _as_string(result.window_end),
            "src_ip": _as_string(result.src_ip),
            "protocol": _as_string(result.protocol),
            "action": _as_string(result.action),
            "interface": _as_string(result.interface),
            "connections": _as_float(result.connections),
            "bytes": _as_float(result.bytes),
            "packets": _as_float(result.packets),
            "packet_size": _as_float(result.packet_size),
            "ports": _as_float(result.ports),
            "is_anomaly": _as_bool(result.is_anomaly),
            "final_label": _as_string(result.final_label),
            "attack_type": _as_string(result.attack_type),
            "risk_level": _as_string(result.risk_level),
            "confidence": _as_float(result.confidence),
            "decision_source": _as_string(result.decision_source),
            "decision_reason": _as_string(result.decision_reason),
            "ensemble_score": _as_float(result.ensemble_score),
            "autoencoder_score": _as_float(result.autoencoder_score),
            "isolation_score": _as_float(result.isolation_score),
        }
    )
    return payload


def _live_window_to_dict(window: Any) -> dict[str, Any]:
    """
    Converte uma janela live ORM para payload da API.
    """
    return {
        "id": int(window.id),
        "window_uid": _as_string(window.window_uid),
        "execution_id": _as_string(window.execution_id),
        "created_at": _serialize_datetime(window.created_at),
        "status": _as_string(window.status),
        "local_log_path": _as_string(window.local_log_path),
        "remote_path": _as_string(window.remote_path),
        "parser_start_offset": int(window.parser_start_offset)
        if window.parser_start_offset is not None
        else None,
        "parser_end_offset": int(window.parser_end_offset)
        if window.parser_end_offset is not None
        else None,
        "window_id": _as_string(window.window_id),
        "window_timestamp": _serialize_datetime(window.window_timestamp)
        if window.window_timestamp is not None
        else None,
        "window_start": _as_string(window.window_start),
        "window_end": _as_string(window.window_end),
        "final_label": _as_string(window.final_label),
        "attack_type": _as_string(window.attack_type),
        "risk_level": _as_string(window.risk_level),
        "decision_source": _as_string(window.decision_source),
        "confidence": _as_float(window.confidence),
        "ensemble_score": _as_float(window.ensemble_score),
        "autoencoder_score": _as_float(window.autoencoder_score),
        "isolation_score": _as_float(window.isolation_score),
        "features": _normalize_value(window.features_json or {}),
        "model_outputs": _normalize_value(window.model_outputs_json or {}),
        "metadata": _normalize_value(window.metadata_json or {}),
        "raw": _normalize_value(window.raw_json or {}),
    }


def _distribution_from_rows(rows: list[Any]) -> dict[str, int]:
    """
    Converte linhas de agregacao SQL em dicionario serializavel.
    """
    distribution: dict[str, int] = {}
    for key, count in rows:
        label = _as_string(key) or "unknown"
        distribution[label] = int(count or 0)
    return distribution


def _count_ai_support_flags(payloads: list[Any]) -> tuple[int, int]:
    """
    Conta flags de suporte da IA armazenadas em model_outputs_json.
    """
    ai_support_count = 0
    ai_support_conservative_count = 0

    for payload in payloads:
        model_outputs = _normalize_value(payload or {})
        if not isinstance(model_outputs, dict):
            continue
        ai_support = model_outputs.get("ai_support") or {}
        if not isinstance(ai_support, dict):
            continue
        if _is_truthy_flag(ai_support.get("enabled")):
            ai_support_count += 1
        if _is_truthy_flag(ai_support.get("conservative")):
            ai_support_conservative_count += 1

    return ai_support_count, ai_support_conservative_count


def _parse_history_datetime(value: Any) -> datetime | None:
    """
    Normaliza filtros opcionais de periodo para datetime.
    """
    normalized = _normalize_value(value)
    if normalized is None or normalized == "":
        return None
    if isinstance(normalized, datetime):
        return normalized
    if isinstance(normalized, str):
        clean = normalized.strip()
        if not clean:
            return None
        if clean.endswith("Z"):
            clean = f"{clean[:-1]}+00:00"
        try:
            return datetime.fromisoformat(clean)
        except ValueError as exc:
            raise ValueError(f"Filtro de data invalido: {normalized}") from exc
    raise ValueError(f"Filtro de data invalido: {normalized}")


def _parse_optional_bool_filter(value: Any) -> bool | None:
    """
    Normaliza filtros booleanos opcionais.
    """
    normalized = _normalize_value(value)
    if normalized is None or normalized == "":
        return None
    if isinstance(normalized, bool):
        return normalized
    if isinstance(normalized, str):
        clean = normalized.strip().lower()
        if clean in {"1", "true", "yes", "sim", "on"}:
            return True
        if clean in {"0", "false", "no", "nao", "não", "off"}:
            return False
    return bool(normalized)


def _live_window_ai_support_enabled(window: Any) -> bool:
    """
    Le a flag ai_support de uma janela ORM.
    """
    model_outputs = _normalize_value(window.model_outputs_json or {})
    if not isinstance(model_outputs, dict):
        return False
    ai_support = model_outputs.get("ai_support") or {}
    if not isinstance(ai_support, dict):
        return False
    return _is_truthy_flag(ai_support.get("enabled"))


def _live_window_ai_support_conservative_enabled(window: Any) -> bool:
    """
    Le a flag conservadora de suporte da IA de uma janela ORM.
    """
    model_outputs = _normalize_value(window.model_outputs_json or {})
    if not isinstance(model_outputs, dict):
        return False
    ai_support = model_outputs.get("ai_support") or {}
    if not isinstance(ai_support, dict):
        return False
    return _is_truthy_flag(ai_support.get("conservative"))


def _live_window_time_expression(model: Any) -> Any:
    """
    Define o timestamp usado para filtros e ordenacao historica.
    """
    return func.coalesce(model.window_timestamp, model.created_at)


def _apply_live_history_filters(
    statement: Any,
    model: Any,
    filters: dict[str, Any] | None = None,
    *,
    alerts_only: bool = False,
) -> Any:
    """
    Aplica filtros historicos suportados por colunas relacionais.
    """
    filters = filters or {}
    if alerts_only:
        statement = statement.where(model.final_label == "anomaly")

    final_label = filters.get("final_label")
    if final_label:
        statement = statement.where(model.final_label == str(final_label))

    attack_type = filters.get("attack_type")
    if attack_type:
        statement = statement.where(model.attack_type == str(attack_type))

    risk_level = filters.get("risk_level")
    if risk_level:
        statement = statement.where(model.risk_level == str(risk_level))

    date_from = _parse_history_datetime(filters.get("date_from"))
    if date_from is not None:
        statement = statement.where(_live_window_time_expression(model) >= date_from)

    date_to = _parse_history_datetime(filters.get("date_to"))
    if date_to is not None:
        statement = statement.where(_live_window_time_expression(model) <= date_to)

    return statement


def _filter_live_rows_by_ai_support(
    rows: list[Any],
    filters: dict[str, Any] | None = None,
) -> list[Any]:
    """
    Aplica filtro ai_support em Python para evitar acoplamento a JSONB.
    """
    expected = _parse_optional_bool_filter((filters or {}).get("ai_support"))
    if expected is None:
        return rows
    return [
        row
        for row in rows
        if _live_window_ai_support_enabled(row) is expected
    ]


def _load_live_history_rows(
    session: Any,
    filters: dict[str, Any] | None = None,
    *,
    alerts_only: bool = False,
) -> list[Any]:
    """
    Carrega janelas live filtradas para endpoints historicos.
    """
    from src.db.models import LivePfSenseWindow

    statement = _apply_live_history_filters(
        select(LivePfSenseWindow),
        LivePfSenseWindow,
        filters,
        alerts_only=alerts_only,
    ).order_by(
        _live_window_time_expression(LivePfSenseWindow).desc(),
        LivePfSenseWindow.id.desc(),
    )
    rows = session.execute(statement).scalars().all()
    return _filter_live_rows_by_ai_support(rows, filters)


def _count_distribution(items: list[str | None]) -> dict[str, int]:
    """
    Conta valores textuais preservando chave unknown para nulos.
    """
    distribution: dict[str, int] = {}
    for item in items:
        key = str(item) if item else "unknown"
        distribution[key] = distribution.get(key, 0) + 1
    return distribution


def save_analysis(summary: dict[str, Any], results: list[dict[str, Any]]) -> None:
    """
    Salva ou atualiza uma analise completa no PostgreSQL.
    """
    _require_database()
    from src.db.models import Analysis, AnalysisResult

    analysis_id = _as_string(summary.get("analysis_id"))
    if not analysis_id:
        raise ValueError("O resumo da analise precisa conter um analysis_id valido.")

    classification = summary.get("classification", {})

    session = SessionLocal()
    try:
        analysis = session.get(Analysis, analysis_id)
        if analysis is None:
            analysis = Analysis(id=analysis_id)
            session.add(analysis)

        analysis.filename = _as_string(summary.get("filename")) or "unknown.log"
        analysis.created_at = _parse_created_at(summary.get("created_at"))
        analysis.total_windows = int(summary.get("total_windows") or len(results))
        analysis.final_status = _as_string(classification.get("final_status")) or "unknown"
        analysis.predominant_attack_type = (
            _as_string(classification.get("predominant_attack_type")) or "unknown"
        )
        analysis.predominant_risk_level = (
            _as_string(classification.get("predominant_risk_level")) or "unknown"
        )
        analysis.confidence_avg = _as_float(classification.get("confidence_avg"))
        analysis.summary_json = _normalize_value(summary.get("summary") or {})
        analysis.counts_json = _normalize_value(summary.get("counts") or {})
        analysis.parse_stats_json = _normalize_value(summary.get("parse_stats") or {})
        analysis.artifacts_json = _normalize_value(summary.get("artifacts") or {})

        analysis.results = []
        for item in results:
            analysis.results.append(
                AnalysisResult(
                    window_id=_as_string(item.get("window_id")),
                    window_start=_as_string(item.get("window_start")),
                    window_end=_as_string(item.get("window_end")),
                    src_ip=_as_string(item.get("src_ip")),
                    protocol=_as_string(item.get("protocol")),
                    action=_as_string(item.get("action")),
                    interface=_as_string(item.get("interface")),
                    connections=_as_float(item.get("connections")),
                    bytes=_as_float(item.get("bytes")),
                    packets=_as_float(item.get("packets")),
                    packet_size=_as_float(item.get("packet_size")),
                    ports=_as_float(item.get("ports")),
                    is_anomaly=_as_bool(item.get("is_anomaly")),
                    final_label=_as_string(item.get("final_label")),
                    attack_type=_as_string(item.get("attack_type")),
                    risk_level=_as_string(item.get("risk_level")),
                    confidence=_as_float(item.get("confidence")),
                    decision_source=_as_string(item.get("decision_source")),
                    decision_reason=_as_string(item.get("decision_reason")),
                    ensemble_score=_as_float(item.get("ensemble_score")),
                    autoencoder_score=_as_float(item.get("autoencoder_score")),
                    isolation_score=_as_float(item.get("isolation_score")),
                    raw_json=_normalize_value(item),
                )
            )

        session.commit()
    except Exception as exc:
        session.rollback()
        raise RuntimeError(f"Falha ao salvar analise no PostgreSQL: {exc}") from exc
    finally:
        session.close()


def list_analyses(limit: int = 50, offset: int = 0) -> dict[str, Any]:
    """
    Lista analises salvas no PostgreSQL com paginacao real.
    """
    _require_database()
    from src.db.models import Analysis

    safe_limit, safe_offset = _safe_limit_offset(limit, offset)
    session = SessionLocal()
    try:
        total = int(
            session.execute(
                select(func.count()).select_from(Analysis)
            ).scalar_one()
        )
        rows = session.execute(
            select(Analysis)
            .order_by(Analysis.created_at.desc())
            .offset(safe_offset)
            .limit(safe_limit)
        ).scalars().all()
        items = [_analysis_to_list_item(row) for row in rows]
        return {
            "total": total,
            "limit": safe_limit,
            "offset": safe_offset,
            "analyses": items,
        }
    finally:
        session.close()


def get_analysis(analysis_id: str) -> dict[str, Any] | None:
    """
    Busca o resumo de uma analise no PostgreSQL.
    """
    _require_database()
    from src.db.models import Analysis

    session = SessionLocal()
    try:
        analysis = session.get(Analysis, analysis_id)
        if analysis is None:
            return None
        return _analysis_to_summary_dict(analysis)
    finally:
        session.close()


def get_analysis_results(
    analysis_id: str,
    limit: int = 50,
    offset: int = 0,
) -> dict[str, Any]:
    """
    Busca os resultados detalhados de uma analise no PostgreSQL com paginacao.
    """
    _require_database()
    from src.db.models import AnalysisResult

    safe_limit, safe_offset = _safe_limit_offset(limit, offset)
    session = SessionLocal()
    try:
        total = int(
            session.execute(
                select(func.count())
                .select_from(AnalysisResult)
                .where(AnalysisResult.analysis_id == analysis_id)
            ).scalar_one()
        )
        rows = session.execute(
            select(AnalysisResult)
            .where(AnalysisResult.analysis_id == analysis_id)
            .order_by(AnalysisResult.id.asc())
            .offset(safe_offset)
            .limit(safe_limit)
        ).scalars().all()
        results = [_result_to_dict(row) for row in rows]
        return {
            "total": total,
            "limit": safe_limit,
            "offset": safe_offset,
            "results": results,
        }
    finally:
        session.close()


def seed_initial_admin() -> dict[str, Any]:
    """
    Cria o administrador inicial quando SINALYX_ADMIN_PASSWORD estiver definido.
    """
    _require_database()
    from src.db.models import User

    admin_email = _normalize_email(
        os.getenv("SINALYX_ADMIN_EMAIL", "admin@sinalyx.local")
    )
    admin_name = os.getenv("SINALYX_ADMIN_NAME", "Administrador Sinalyx").strip()
    admin_password = os.getenv("SINALYX_ADMIN_PASSWORD", "").strip()

    session = SessionLocal()
    try:
        existing = session.execute(
            select(User).where(User.email == admin_email)
        ).scalar_one_or_none()
        if existing is not None:
            changed = False
            if existing.role != "admin":
                existing.role = "admin"
                changed = True
            if not existing.is_active:
                existing.is_active = True
                changed = True
            if changed:
                existing.updated_at = _now()
                session.commit()
            return {
                "created": False,
                "reason": "Administrador inicial ja existe e esta protegido.",
                "user": _user_to_dict(existing),
            }

        if not admin_password:
            return {
                "created": False,
                "reason": "SINALYX_ADMIN_PASSWORD nao definido.",
            }

        now = _now()
        user = User(
            name=admin_name or "Administrador Sinalyx",
            email=admin_email,
            password_hash=hash_password(admin_password),
            role="admin",
            is_active=True,
            created_at=now,
            updated_at=now,
        )
        session.add(user)
        session.commit()
        session.refresh(user)
        return {
            "created": True,
            "reason": "Administrador inicial criado.",
            "user": _user_to_dict(user),
        }
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def authenticate_user(email: str, password: str) -> dict[str, Any] | None:
    """
    Autentica usuario por email e senha.
    """
    _require_database()
    from src.db.models import User

    session = SessionLocal()
    try:
        user = session.execute(
            select(User).where(User.email == _normalize_email(email))
        ).scalar_one_or_none()
        if user is None or not bool(user.is_active):
            return None
        if not verify_password(password, user.password_hash):
            return None
        return _user_to_dict(user)
    finally:
        session.close()


def get_user_by_id(user_id: int) -> dict[str, Any] | None:
    """
    Busca usuario pelo ID primario.
    """
    _require_database()
    from src.db.models import User

    session = SessionLocal()
    try:
        user = session.get(User, int(user_id))
        return _user_to_dict(user) if user is not None else None
    finally:
        session.close()


def list_users(limit: int = 50, offset: int = 0) -> dict[str, Any]:
    """
    Lista usuarios cadastrados para o painel admin.
    """
    _require_database()
    from src.db.models import User

    safe_limit, safe_offset = _safe_limit_offset(limit, offset)
    session = SessionLocal()
    try:
        total = int(
            session.execute(select(func.count()).select_from(User)).scalar_one()
        )
        rows = session.execute(
            select(User)
            .order_by(User.created_at.desc(), User.id.desc())
            .offset(safe_offset)
            .limit(safe_limit)
        ).scalars().all()
        return {
            "total": total,
            "limit": safe_limit,
            "offset": safe_offset,
            "users": [_user_to_dict(row) for row in rows],
        }
    finally:
        session.close()


def create_user(
    *,
    name: str,
    email: str,
    password: str,
    role: str = "user",
    is_active: bool = True,
) -> dict[str, Any]:
    """
    Cria um novo usuario.
    """
    _require_database()
    from src.db.models import User

    clean_email = _normalize_email(email)
    if not clean_email:
        raise ValueError("Email obrigatorio.")
    if not name.strip():
        raise ValueError("Nome obrigatorio.")
    if not password:
        raise ValueError("Senha obrigatoria.")

    session = SessionLocal()
    try:
        exists = session.execute(
            select(User).where(User.email == clean_email)
        ).scalar_one_or_none()
        if exists is not None:
            raise ValueError("Ja existe um usuario com este email.")

        now = _now()
        user = User(
            name=name.strip(),
            email=clean_email,
            password_hash=hash_password(password),
            role=_normalize_role(role),
            is_active=bool(is_active),
            created_at=now,
            updated_at=now,
        )
        session.add(user)
        session.commit()
        session.refresh(user)
        return _user_to_dict(user)
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def update_user(
    user_id: int,
    *,
    name: str | None = None,
    email: str | None = None,
    password: str | None = None,
    role: str | None = None,
    is_active: bool | None = None,
) -> dict[str, Any] | None:
    """
    Atualiza dados cadastrais de um usuario.
    """
    _require_database()
    from src.db.models import User

    session = SessionLocal()
    try:
        user = session.get(User, int(user_id))
        if user is None:
            return None

        protected = _is_supreme_admin(user)
        if protected:
            if email is not None and _normalize_email(email) != user.email:
                raise ValueError(
                    "O administrador supremo nao pode ter o email alterado."
                )
            if role is not None and _normalize_role(role) != "admin":
                raise ValueError("O administrador supremo nao pode ser rebaixado.")
            if is_active is not None and not bool(is_active):
                raise ValueError("O administrador supremo nao pode ser desativado.")

        final_role = _normalize_role(role) if role is not None else str(user.role)
        final_active = bool(is_active) if is_active is not None else bool(user.is_active)
        removing_active_admin = (
            user.role == "admin"
            and bool(user.is_active)
            and (final_role != "admin" or not final_active)
        )
        if removing_active_admin and not _has_other_active_admin(session, User, user.id):
            raise ValueError(
                "Nao e permitido deixar o sistema sem administrador ativo."
            )

        if name is not None and name.strip():
            user.name = name.strip()
        if email is not None and email.strip():
            clean_email = _normalize_email(email)
            duplicate = session.execute(
                select(User).where(User.email == clean_email, User.id != user.id)
            ).scalar_one_or_none()
            if duplicate is not None:
                raise ValueError("Ja existe outro usuario com este email.")
            user.email = clean_email
        if password:
            user.password_hash = hash_password(password)
        if role is not None:
            user.role = final_role
        if is_active is not None:
            user.is_active = final_active

        user.updated_at = _now()
        session.commit()
        session.refresh(user)
        return _user_to_dict(user)
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def update_user_status(user_id: int, is_active: bool) -> dict[str, Any] | None:
    """
    Ativa ou desativa um usuario.
    """
    return update_user(user_id, is_active=is_active)


def delete_user(
    user_id: int,
    *,
    current_user_id: int | None = None,
) -> dict[str, Any] | None:
    """
    Remove definitivamente um usuario do painel admin.

    Protege contra autoexclusao e contra remocao do ultimo admin ativo.
    """
    _require_database()
    from src.db.models import User

    target_id = int(user_id)
    if current_user_id is not None and target_id == int(current_user_id):
        raise ValueError("Nao e permitido remover o proprio usuario autenticado.")

    session = SessionLocal()
    try:
        user = session.get(User, target_id)
        if user is None:
            return None

        if _is_supreme_admin(user):
            raise ValueError("O administrador supremo nao pode ser removido.")

        if user.role == "admin" and bool(user.is_active):
            if not _has_other_active_admin(session, User, user.id):
                raise ValueError("Nao e permitido remover o ultimo administrador ativo.")

        payload = _user_to_dict(user)
        session.delete(user)
        session.commit()
        return payload
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def save_live_windows(records: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Salva janelas do fluxo live no PostgreSQL com idempotencia por window_uid.
    """
    _require_database()
    from src.db.models import LivePfSenseWindow

    session = SessionLocal()
    saved = 0
    skipped = 0
    errors: list[str] = []

    try:
        for record in records:
            window_uid = _as_string(record.get("window_uid"))
            if not window_uid:
                errors.append("Janela live sem window_uid valido.")
                continue

            existing = session.execute(
                select(LivePfSenseWindow).where(
                    LivePfSenseWindow.window_uid == window_uid
                )
            ).scalar_one_or_none()
            if existing is not None:
                skipped += 1
                continue

            session.add(
                LivePfSenseWindow(
                    window_uid=window_uid,
                    execution_id=_as_string(record.get("execution_id")) or "unknown",
                    created_at=_parse_created_at(record.get("created_at")),
                    status=_as_string(record.get("status")) or "success",
                    local_log_path=_as_string(record.get("local_log_path")) or "",
                    remote_path=_as_string(record.get("remote_path")),
                    parser_start_offset=(
                        int(record["parser_start_offset"])
                        if record.get("parser_start_offset") is not None
                        else None
                    ),
                    parser_end_offset=(
                        int(record["parser_end_offset"])
                        if record.get("parser_end_offset") is not None
                        else None
                    ),
                    window_id=_as_string(record.get("window_id")),
                    window_timestamp=_parse_optional_datetime(
                        record.get("window_timestamp")
                    ),
                    window_start=_as_string(record.get("window_start")),
                    window_end=_as_string(record.get("window_end")),
                    final_label=_as_string(record.get("final_label")),
                    attack_type=_as_string(record.get("attack_type")),
                    risk_level=_as_string(record.get("risk_level")),
                    decision_source=_as_string(record.get("decision_source")),
                    confidence=_as_float(record.get("confidence")),
                    ensemble_score=_as_float(record.get("ensemble_score")),
                    autoencoder_score=_as_float(record.get("autoencoder_score")),
                    isolation_score=_as_float(record.get("isolation_score")),
                    features_json=_normalize_value(record.get("features") or {}),
                    model_outputs_json=_normalize_value(
                        record.get("model_outputs") or {}
                    ),
                    metadata_json=_normalize_value(record.get("metadata") or {}),
                    raw_json=_normalize_value(record.get("raw") or record),
                )
            )
            saved += 1

        session.commit()
    except Exception as exc:
        session.rollback()
        if IntegrityError is not None and isinstance(exc, IntegrityError):
            errors.append(f"Janela live duplicada durante commit: {exc}")
        else:
            errors.append(f"Falha ao salvar janelas live no PostgreSQL: {exc}")
    finally:
        session.close()

    return {
        "database_saved": len(errors) == 0,
        "saved": int(saved) if len(errors) == 0 else 0,
        "skipped_duplicates": int(skipped),
        "errors": errors,
    }


def list_live_windows(limit: int = 50, offset: int = 0) -> dict[str, Any]:
    """
    Lista as ultimas janelas live persistidas com paginacao real.
    """
    _require_database()
    from src.db.models import LivePfSenseWindow

    safe_limit, safe_offset = _safe_limit_offset(limit, offset)
    session = SessionLocal()
    try:
        total = int(
            session.execute(
                select(func.count()).select_from(LivePfSenseWindow)
            ).scalar_one()
        )
        rows = session.execute(
            select(LivePfSenseWindow)
            .order_by(LivePfSenseWindow.created_at.desc())
            .offset(safe_offset)
            .limit(safe_limit)
        ).scalars().all()
        windows = [_live_window_to_dict(row) for row in rows]
        return {
            "total": total,
            "limit": safe_limit,
            "offset": safe_offset,
            "windows": windows,
        }
    finally:
        session.close()


def summarize_live_windows(recent_limit: int = 5) -> dict[str, Any]:
    """
    Gera um resumo agregado das janelas live persistidas.
    """
    _require_database()
    from src.db.models import LivePfSenseWindow

    safe_limit, _ = _safe_limit_offset(recent_limit, 0)
    session = SessionLocal()
    try:
        total = int(
            session.execute(
                select(func.count()).select_from(LivePfSenseWindow)
            ).scalar_one()
        )
        final_label_rows = session.execute(
            select(LivePfSenseWindow.final_label, func.count())
            .group_by(LivePfSenseWindow.final_label)
        ).all()
        attack_type_rows = session.execute(
            select(LivePfSenseWindow.attack_type, func.count())
            .group_by(LivePfSenseWindow.attack_type)
        ).all()
        risk_level_rows = session.execute(
            select(LivePfSenseWindow.risk_level, func.count())
            .group_by(LivePfSenseWindow.risk_level)
        ).all()
        model_output_payloads = [
            row[0]
            for row in session.execute(
                select(LivePfSenseWindow.model_outputs_json)
            ).all()
        ]
        ai_support_count, ai_support_conservative_count = _count_ai_support_flags(
            model_output_payloads
        )
        recent_rows = session.execute(
            select(LivePfSenseWindow)
            .order_by(LivePfSenseWindow.created_at.desc(), LivePfSenseWindow.id.desc())
            .limit(safe_limit)
        ).scalars().all()

        return {
            "total": total,
            "recent_limit": safe_limit,
            "final_label_distribution": _distribution_from_rows(final_label_rows),
            "attack_type_distribution": _distribution_from_rows(attack_type_rows),
            "risk_level_distribution": _distribution_from_rows(risk_level_rows),
            "ai_support_count": int(ai_support_count),
            "ai_support_conservative_count": int(ai_support_conservative_count),
            "recent_windows": [_live_window_to_dict(row) for row in recent_rows],
        }
    finally:
        session.close()


def list_live_alerts(limit: int = 50, offset: int = 0) -> dict[str, Any]:
    """
    Lista somente janelas live anomalas com paginacao real.
    """
    _require_database()
    from src.db.models import LivePfSenseWindow

    safe_limit, safe_offset = _safe_limit_offset(limit, offset)
    session = SessionLocal()
    try:
        total = int(
            session.execute(
                select(func.count())
                .select_from(LivePfSenseWindow)
                .where(LivePfSenseWindow.final_label == "anomaly")
            ).scalar_one()
        )
        rows = session.execute(
            select(LivePfSenseWindow)
            .where(LivePfSenseWindow.final_label == "anomaly")
            .order_by(LivePfSenseWindow.created_at.desc(), LivePfSenseWindow.id.desc())
            .offset(safe_offset)
            .limit(safe_limit)
        ).scalars().all()
        alerts = [_live_window_to_dict(row) for row in rows]
        return {
            "total": total,
            "limit": safe_limit,
            "offset": safe_offset,
            "alerts": alerts,
        }
    finally:
        session.close()


def list_history_windows(
    limit: int = 50,
    offset: int = 0,
    filters: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Lista janelas live historicas com filtros opcionais.
    """
    _require_database()

    safe_limit, safe_offset = _safe_limit_offset(limit, offset)
    session = SessionLocal()
    try:
        rows = _load_live_history_rows(session, filters)
        total = len(rows)
        page = rows[safe_offset : safe_offset + safe_limit]
        return {
            "total": total,
            "limit": safe_limit,
            "offset": safe_offset,
            "windows": [_live_window_to_dict(row) for row in page],
        }
    finally:
        session.close()


def get_history_window_by_id(window_id: int) -> dict[str, Any] | None:
    """
    Busca uma janela live historica pelo ID primario usado pelo frontend.
    """
    _require_database()
    from src.db.models import LivePfSenseWindow

    session = SessionLocal()
    try:
        row = session.get(LivePfSenseWindow, int(window_id))
        if row is None:
            return None
        return _live_window_to_dict(row)
    finally:
        session.close()


def list_history_alerts(
    limit: int = 50,
    offset: int = 0,
    filters: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Lista alertas historicos a partir das janelas live anomalas.
    """
    _require_database()

    safe_limit, safe_offset = _safe_limit_offset(limit, offset)
    session = SessionLocal()
    try:
        rows = _load_live_history_rows(session, filters, alerts_only=True)
        total = len(rows)
        page = rows[safe_offset : safe_offset + safe_limit]
        return {
            "total": total,
            "limit": safe_limit,
            "offset": safe_offset,
            "alerts": [_live_window_to_dict(row) for row in page],
        }
    finally:
        session.close()


def list_history_executions(
    limit: int = 50,
    offset: int = 0,
    filters: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Deriva execucoes live a partir das janelas persistidas.
    """
    _require_database()

    safe_limit, safe_offset = _safe_limit_offset(limit, offset)
    session = SessionLocal()
    try:
        rows = _load_live_history_rows(session, filters)
        grouped: dict[str, dict[str, Any]] = {}
        for row in rows:
            execution_id = _as_string(row.execution_id) or "unknown"
            item = grouped.setdefault(
                execution_id,
                {
                    "execution_id": execution_id,
                    "first_seen_at": None,
                    "last_seen_at": None,
                    "total_windows": 0,
                    "total_anomalies": 0,
                    "ai_support_count": 0,
                    "ai_support_conservative_count": 0,
                    "final_label_distribution": {},
                    "attack_type_distribution": {},
                    "risk_level_distribution": {},
                    "status_distribution": {},
                    "local_log_path": _as_string(row.local_log_path),
                    "remote_path": _as_string(row.remote_path),
                },
            )

            created_at = row.created_at
            if item["first_seen_at"] is None or created_at < item["first_seen_at"]:
                item["first_seen_at"] = created_at
            if item["last_seen_at"] is None or created_at > item["last_seen_at"]:
                item["last_seen_at"] = created_at

            item["total_windows"] += 1
            if _as_string(row.final_label) == "anomaly":
                item["total_anomalies"] += 1
            if _live_window_ai_support_enabled(row):
                item["ai_support_count"] += 1
            if _live_window_ai_support_conservative_enabled(row):
                item["ai_support_conservative_count"] += 1

            for field, column_value in (
                ("final_label_distribution", row.final_label),
                ("attack_type_distribution", row.attack_type),
                ("risk_level_distribution", row.risk_level),
                ("status_distribution", row.status),
            ):
                key = _as_string(column_value) or "unknown"
                item[field][key] = int(item[field].get(key, 0)) + 1

        executions = list(grouped.values())
        executions.sort(
            key=lambda item: item.get("last_seen_at") or datetime.min,
            reverse=True,
        )
        for item in executions:
            item["first_seen_at"] = (
                _serialize_datetime(item["first_seen_at"])
                if item["first_seen_at"] is not None
                else None
            )
            item["last_seen_at"] = (
                _serialize_datetime(item["last_seen_at"])
                if item["last_seen_at"] is not None
                else None
            )

        total = len(executions)
        page = executions[safe_offset : safe_offset + safe_limit]
        return {
            "total": total,
            "limit": safe_limit,
            "offset": safe_offset,
            "executions": page,
        }
    finally:
        session.close()


def summarize_history(filters: dict[str, Any] | None = None) -> dict[str, Any]:
    """
    Resume historico batch e live persistido para telas do frontend.
    """
    _require_database()
    from src.db.models import Analysis, AnalysisResult

    session = SessionLocal()
    try:
        total_analyses = int(
            session.execute(
                select(func.count()).select_from(Analysis)
            ).scalar_one()
        )
        total_analysis_results = int(
            session.execute(
                select(func.count()).select_from(AnalysisResult)
            ).scalar_one()
        )
        analysis_status_rows = session.execute(
            select(Analysis.final_status, func.count())
            .group_by(Analysis.final_status)
        ).all()
        analysis_attack_rows = session.execute(
            select(Analysis.predominant_attack_type, func.count())
            .group_by(Analysis.predominant_attack_type)
        ).all()
        analysis_risk_rows = session.execute(
            select(Analysis.predominant_risk_level, func.count())
            .group_by(Analysis.predominant_risk_level)
        ).all()
        latest_analysis = session.execute(
            select(Analysis)
            .order_by(Analysis.created_at.desc())
            .limit(1)
        ).scalars().first()

        live_rows = _load_live_history_rows(session, filters)
        live_windows = [_live_window_to_dict(row) for row in live_rows]
        live_alert_rows = [
            row
            for row in live_rows
            if _as_string(row.final_label) == "anomaly"
        ]
        execution_ids = {
            _as_string(row.execution_id) or "unknown"
            for row in live_rows
        }
        ai_support_count = sum(
            1 for row in live_rows if _live_window_ai_support_enabled(row)
        )
        ai_support_conservative_count = sum(
            1
            for row in live_rows
            if _live_window_ai_support_conservative_enabled(row)
        )

        return {
            "analyses": {
                "total_analyses": total_analyses,
                "total_results": total_analysis_results,
                "final_status_distribution": _distribution_from_rows(
                    analysis_status_rows
                ),
                "attack_type_distribution": _distribution_from_rows(
                    analysis_attack_rows
                ),
                "risk_level_distribution": _distribution_from_rows(
                    analysis_risk_rows
                ),
                "latest_analysis": (
                    _analysis_to_list_item(latest_analysis)
                    if latest_analysis is not None
                    else None
                ),
            },
            "live": {
                "total_windows": len(live_rows),
                "total_alerts": len(live_alert_rows),
                "total_executions": len(execution_ids),
                "final_label_distribution": _count_distribution(
                    [_as_string(row.final_label) for row in live_rows]
                ),
                "attack_type_distribution": _count_distribution(
                    [_as_string(row.attack_type) for row in live_rows]
                ),
                "risk_level_distribution": _count_distribution(
                    [_as_string(row.risk_level) for row in live_rows]
                ),
                "ai_support_count": int(ai_support_count),
                "ai_support_conservative_count": int(
                    ai_support_conservative_count
                ),
                "latest_window": live_windows[0] if live_windows else None,
                "latest_alert": (
                    _live_window_to_dict(live_alert_rows[0])
                    if live_alert_rows
                    else None
                ),
            },
        }
    finally:
        session.close()


def is_database_available() -> bool:
    """
    Verifica se o banco esta acessivel sem derrubar a API.
    """
    if not _database_ready() or text is None:
        return False

    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        return True
    except Exception:
        return False
