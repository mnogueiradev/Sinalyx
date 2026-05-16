"""
API principal do Sinalyx.

Este modulo expoe dois fluxos:
- `/predict`: contrato legado com entrada estruturada simples
- `/analyze/pfsense`: upload de logs reais do pfSense reutilizando o
  pipeline oficial de parse, agregacao, inferencia e decision engine
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any

from fastapi import Depends, FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from src.api.schemas import (
    AnalysisListResponse,
    AlertsRecentResponse,
    ApiErrorResponse,
    ApiStatusResponse,
    AuthLoginRequest,
    AuthLoginResponse,
    AuthMeResponse,
    DashboardSummaryResponse,
    HealthResponse,
    HistoryAlertsResponse,
    HistoryExecutionsResponse,
    HistorySummaryResponse,
    HistoryWindowResponse,
    HistoryWindowsResponse,
    LiveRunResponse,
    LiveStatusResponse,
    LiveWindowsResponse,
    NetworkInput,
    PFSenseAnalysisResponse,
    PFSenseAnalysisResultsResponse,
    PFSenseAnalysisSummaryResponse,
    SystemAuditResponse,
    UserCreateRequest,
    UserStatusRequest,
    UserUpdateRequest,
    UsersListResponse,
)
from src.api.auth import get_current_user, require_admin
from src.api.services import (
    ApiServiceError,
    analyze_pfsense_upload,
    ensure_api_runtime_dirs,
    get_history_summary,
    get_history_window,
    list_history_alerts,
    list_history_executions,
    list_history_windows,
    list_saved_analyses,
    load_analysis_results,
    load_analysis_summary,
)
from src.db.database import DATABASE_ENABLED
from src.db.init_db import create_tables
from src.auth.security import create_access_token, get_access_token_expire_minutes
from src.db.repository import (
    authenticate_user,
    create_user,
    delete_user,
    is_database_available,
    list_users,
    seed_initial_admin,
    update_user,
    update_user_status,
)
from src.features.constants import describe_active_features
from src.features.dataset_loader import prepare_inference_records
from src.features.engineering import to_feature_matrix
from src.models.autoencoder import predict_autoencoder_with_details
from src.models.classifier import analyze_behavior
from src.models.decision_engine import decide_attack
from src.models.detection import predict_with_details
from src.models.ensemble import load_all_models, predict_ensemble_details
from src.services.pfsense_live_service import (
    get_collector_status,
    get_dashboard_summary,
    get_parser_status,
    list_recent_alerts,
    list_recent_live_windows,
    process_live_pfsense,
)


LOCAL_FRONTEND_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]


def _get_cors_origins() -> list[str]:
    """
    Le origens permitidas para CORS a partir do ambiente.

    SINALYX_CORS_ORIGINS aceita lista separada por virgula. Quando nao
    informada, mantemos as origens locais usadas pelo frontend Vite.
    """
    raw_origins = os.getenv("SINALYX_CORS_ORIGINS", "")
    origins = [
        origin.strip()
        for origin in raw_origins.split(",")
        if origin.strip()
    ]
    return origins or LOCAL_FRONTEND_ORIGINS


app = FastAPI(title="Sinalyx API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=_get_cors_origins(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(ApiServiceError)
async def api_service_error_handler(
    _request: Any,
    exc: ApiServiceError,
) -> JSONResponse:
    """
    Padroniza os erros controlados da camada de API.
    """
    return JSONResponse(
        status_code=exc.status_code,
        content=exc.to_http_detail(),
    )


@app.on_event("startup")
def startup() -> None:
    """
    Prepara diretorios temporarios e tenta pre-carregar modelos da API.
    """
    print("[INFO] Iniciando API do Sinalyx...")
    print(f"[INFO] API iniciando com {describe_active_features()}")
    ensure_api_runtime_dirs()
    app.state.model_preload_error = None
    app.state.database_startup_error = None

    try:
        create_tables()
    except Exception as exc:
        app.state.database_startup_error = str(exc)
        print(
            "[WARNING] Nao foi possivel inicializar o PostgreSQL da API. "
            "A aplicacao seguira usando fallback local em JSON. "
            f"Motivo: {exc}"
        )
    else:
        print("[INFO] Tabelas do PostgreSQL verificadas com sucesso.")
        try:
            seed_result = seed_initial_admin()
        except Exception as exc:
            print(
                "[WARNING] Nao foi possivel preparar o administrador inicial. "
                f"Motivo: {exc}"
            )
        else:
            if seed_result.get("created"):
                print("[INFO] Administrador inicial do Sinalyx criado.")
            elif seed_result.get("reason"):
                print(f"[INFO] Admin seed: {seed_result['reason']}")

    try:
        load_all_models()
    except Exception as exc:
        app.state.model_preload_error = str(exc)
        print(
            "[WARNING] Nao foi possivel pre-carregar os modelos da API. "
            f"A inferencia tentara carregar sob demanda. Motivo: {exc}"
        )
    else:
        print("[INFO] Modelos carregados com sucesso.")


@app.get("/", response_model=ApiStatusResponse)
def root() -> dict[str, str]:
    """
    Status simples da API.
    """
    return {
        "app": "Sinalyx API",
        "status": "running",
    }


@app.get("/health", response_model=HealthResponse)
def health() -> dict[str, Any]:
    """
    Health check resumido para orquestracao e testes manuais.
    """
    return {
        "status": "ok",
        "database": {
            "enabled": DATABASE_ENABLED,
            "available": is_database_available(),
        },
    }


@app.get(
    "/system/audit",
    response_model=SystemAuditResponse,
    responses={401: {"model": ApiErrorResponse}, 403: {"model": ApiErrorResponse}},
)
def system_audit_endpoint(
    _admin: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    """
    Retorna um retrato operacional seguro para auditoria do Sinalyx.
    """
    database_available = is_database_available()
    history_response = get_history_summary() if database_available else {}
    history_data = history_response.get("data", {}) if isinstance(history_response, dict) else {}
    live_data = history_data.get("live", {}) if isinstance(history_data, dict) else {}
    analyses_data = history_data.get("analyses", {}) if isinstance(history_data, dict) else {}

    users_total = 0
    if database_available:
        try:
            users_page = list_users(limit=1, offset=0)
            users_total = int(users_page.get("total", 0))
        except Exception:
            users_total = 0

    parser_state = get_parser_status()
    collector_state = get_collector_status()
    last_processing = (
        parser_state.get("last_run_at")
        or parser_state.get("last_fetch_at")
        or collector_state.get("last_fetch_at")
    )

    return {
        "status": "success",
        "data": {
            "system": {
                "name": "Sinalyx",
                "version": os.getenv("SINALYX_VERSION", "v0.1.0-tcc"),
                "environment": os.getenv("SINALYX_ENV", "local"),
                "audited_at": datetime.now(timezone.utc).isoformat(),
            },
            "database": {
                "enabled": DATABASE_ENABLED,
                "available": database_available,
            },
            "counts": {
                "users": users_total,
                "live_windows": int(live_data.get("total_windows", 0) or 0),
                "alerts": int(live_data.get("total_alerts", 0) or 0),
                "executions": int(live_data.get("total_executions", 0) or 0),
                "analyses": int(analyses_data.get("total_analyses", 0) or 0),
                "analysis_results": int(analyses_data.get("total_results", 0) or 0),
            },
            "runtime": {
                "parser": parser_state,
                "collector": collector_state,
                "last_processing": last_processing,
            },
            "models": {
                "expected_features": describe_active_features(),
                "preload_error": getattr(app.state, "model_preload_error", None),
            },
        },
        "meta": {
            "source_tables": [
                "users",
                "analyses",
                "analysis_results",
                "live_pfsense_windows",
            ],
            "protected": True,
        },
        "error": None,
    }


@app.post(
    "/auth/login",
    response_model=AuthLoginResponse,
    responses={401: {"model": ApiErrorResponse}, 503: {"model": ApiErrorResponse}},
)
def auth_login_endpoint(payload: AuthLoginRequest) -> dict[str, Any]:
    """
    Autentica usuario por email e senha e retorna token Bearer.
    """
    try:
        user = authenticate_user(payload.email, payload.password)
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail={
                "status": "error",
                "error_code": "auth_database_unavailable",
                "message": "Nao foi possivel consultar usuarios no PostgreSQL.",
                "details": {"exception": str(exc)},
            },
        ) from exc

    if user is None:
        raise HTTPException(
            status_code=401,
            detail={
                "status": "error",
                "error_code": "invalid_credentials",
                "message": "Email ou senha invalidos.",
                "details": {},
            },
        )

    expires_minutes = get_access_token_expire_minutes()
    token = create_access_token(
        subject=str(user["id"]),
        email=str(user["email"]),
        role=str(user["role"]),
    )
    return {
        "status": "success",
        "data": {
            "access_token": token,
            "token_type": "bearer",
            "expires_in": expires_minutes * 60,
            "user": user,
        },
        "meta": {},
        "error": None,
    }


@app.get("/auth/me", response_model=AuthMeResponse)
def auth_me_endpoint(
    current_user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    """
    Retorna os dados do usuario autenticado.
    """
    return {
        "status": "success",
        "data": {"user": current_user},
        "meta": {},
        "error": None,
    }


@app.get("/admin/users", response_model=UsersListResponse)
def admin_users_endpoint(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    _admin: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    """
    Lista usuarios cadastrados. Requer admin.
    """
    page = list_users(limit=limit, offset=offset)
    users = list(page.get("users", []))
    return {
        "status": "success",
        "data": {"users": users},
        "meta": {
            "total": int(page.get("total", len(users))),
            "limit": int(page.get("limit", limit)),
            "offset": int(page.get("offset", offset)),
            "returned": len(users),
        },
        "error": None,
    }


@app.post("/admin/users", response_model=AuthMeResponse)
def admin_create_user_endpoint(
    payload: UserCreateRequest,
    _admin: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    """
    Cria usuario. Requer admin.
    """
    try:
        user = create_user(**payload.model_dump())
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail={
                "status": "error",
                "error_code": "invalid_user_payload",
                "message": str(exc),
                "details": {},
            },
        ) from exc
    return {
        "status": "success",
        "data": {"user": user},
        "meta": {},
        "error": None,
    }


@app.put("/admin/users/{user_id}", response_model=AuthMeResponse)
def admin_update_user_endpoint(
    user_id: int,
    payload: UserUpdateRequest,
    _admin: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    """
    Atualiza usuario. Requer admin.
    """
    try:
        user = update_user(user_id, **payload.model_dump(exclude_unset=True))
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail={
                "status": "error",
                "error_code": "invalid_user_payload",
                "message": str(exc),
                "details": {"user_id": user_id},
            },
        ) from exc
    if user is None:
        raise HTTPException(
            status_code=404,
            detail={
                "status": "error",
                "error_code": "user_not_found",
                "message": "Usuario nao encontrado.",
                "details": {"user_id": user_id},
            },
        )
    return {
        "status": "success",
        "data": {"user": user},
        "meta": {},
        "error": None,
    }


@app.patch("/admin/users/{user_id}/status", response_model=AuthMeResponse)
def admin_update_user_status_endpoint(
    user_id: int,
    payload: UserStatusRequest,
    _admin: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    """
    Ativa ou desativa usuario. Requer admin.
    """
    try:
        user = update_user_status(user_id, payload.is_active)
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail={
                "status": "error",
                "error_code": "invalid_user_status_update",
                "message": str(exc),
                "details": {"user_id": user_id},
            },
        ) from exc
    if user is None:
        raise HTTPException(
            status_code=404,
            detail={
                "status": "error",
                "error_code": "user_not_found",
                "message": "Usuario nao encontrado.",
                "details": {"user_id": user_id},
            },
        )
    return {
        "status": "success",
        "data": {"user": user},
        "meta": {},
        "error": None,
    }


@app.delete("/admin/users/{user_id}", response_model=AuthMeResponse)
def admin_delete_user_endpoint(
    user_id: int,
    _admin: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    """
    Remove usuario definitivamente. Requer admin.
    """
    try:
        user = delete_user(user_id, current_user_id=int(_admin["id"]))
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail={
                "status": "error",
                "error_code": "invalid_user_delete",
                "message": str(exc),
                "details": {"user_id": user_id},
            },
        ) from exc
    if user is None:
        raise HTTPException(
            status_code=404,
            detail={
                "status": "error",
                "error_code": "user_not_found",
                "message": "Usuario nao encontrado.",
                "details": {"user_id": user_id},
            },
        )
    return {
        "status": "success",
        "data": {"user": user},
        "meta": {},
        "error": None,
    }


@app.post(
    "/analyze/pfsense",
    response_model=PFSenseAnalysisResponse,
    responses={
        400: {"model": ApiErrorResponse},
        415: {"model": ApiErrorResponse},
        422: {"model": ApiErrorResponse},
        500: {"model": ApiErrorResponse},
        503: {"model": ApiErrorResponse},
    },
)
async def analyze_pfsense_endpoint(
    file: UploadFile = File(...),
    _user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    """
    Analisa um arquivo de log real do pfSense usando o pipeline oficial.
    """
    return await analyze_pfsense_upload(file)


@app.get(
    "/analyses",
    response_model=AnalysisListResponse,
    responses={500: {"model": ApiErrorResponse}},
)
def analyses_list_endpoint(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    _user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    """
    Lista as analises ja persistidas localmente pela API.
    """
    return list_saved_analyses(limit=limit, offset=offset)


@app.get(
    "/analyses/{analysis_id}",
    response_model=PFSenseAnalysisSummaryResponse,
    responses={404: {"model": ApiErrorResponse}},
)
def analysis_summary_endpoint(
    analysis_id: str,
    _user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    """
    Retorna o resumo persistido de uma analise ja executada.
    """
    return load_analysis_summary(analysis_id)


@app.get(
    "/analyses/{analysis_id}/results",
    response_model=PFSenseAnalysisResultsResponse,
    responses={404: {"model": ApiErrorResponse}},
)
def analysis_results_endpoint(
    analysis_id: str,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    _user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    """
    Retorna os resultados detalhados por janela de uma analise persistida.
    """
    return load_analysis_results(analysis_id, limit=limit, offset=offset)


@app.get(
    "/live/pfsense/collector/status",
    response_model=LiveStatusResponse,
)
def live_collector_status_endpoint(
    _user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    """
    Retorna o ultimo estado conhecido do coletor SSH/SFTP do pfSense.
    """
    return {
        "status": "success",
        "state": get_collector_status(),
    }


@app.get(
    "/live/pfsense/parser/status",
    response_model=LiveStatusResponse,
)
def live_parser_status_endpoint(
    _user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    """
    Retorna o estado incremental do parser live.
    """
    return {
        "status": "success",
        "state": get_parser_status(),
    }


@app.post(
    "/live/pfsense/run",
    response_model=LiveRunResponse,
)
def live_pfsense_run_endpoint(
    collect: bool = True,
    persist: bool = True,
    finite_file: bool = False,
    flush_pending: bool = False,
    window: str = "1min",
    runtime_profile: str | None = None,
    _admin: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    """
    Dispara manualmente uma execucao do fluxo live pfSense.
    """
    return process_live_pfsense(
        collect=collect,
        persist=persist,
        finite_file=finite_file,
        flush_pending=flush_pending,
        window=window,
        runtime_profile=runtime_profile,
    )


@app.get(
    "/live/pfsense/windows",
    response_model=LiveWindowsResponse,
)
def live_pfsense_windows_endpoint(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    _user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    """
    Lista as ultimas janelas live persistidas no PostgreSQL.
    """
    return list_recent_live_windows(limit=limit, offset=offset)


@app.get(
    "/dashboard/summary",
    response_model=DashboardSummaryResponse,
)
def dashboard_summary_endpoint(
    recent_limit: int = Query(5, ge=1, le=50),
    _user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    """
    Retorna contadores e ultimas janelas live para o dashboard.
    """
    return get_dashboard_summary(recent_limit=recent_limit)


@app.get(
    "/alerts/recent",
    response_model=AlertsRecentResponse,
)
def recent_alerts_endpoint(
    limit: int = Query(20, ge=1, le=500),
    offset: int = Query(0, ge=0),
    _user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    """
    Lista somente alertas live anomalos para o frontend.
    """
    return list_recent_alerts(limit=limit, offset=offset)


@app.get(
    "/history/summary",
    response_model=HistorySummaryResponse,
)
def history_summary_endpoint(
    final_label: str | None = Query(None),
    attack_type: str | None = Query(None),
    risk_level: str | None = Query(None),
    date_from: str | None = Query(None),
    date_to: str | None = Query(None),
    ai_support: bool | None = Query(None),
    _user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    """
    Retorna o resumo historico consolidado de batch e live.
    """
    return get_history_summary(
        final_label=final_label,
        attack_type=attack_type,
        risk_level=risk_level,
        date_from=date_from,
        date_to=date_to,
        ai_support=ai_support,
    )


@app.get(
    "/history/windows",
    response_model=HistoryWindowsResponse,
)
def history_windows_endpoint(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    final_label: str | None = Query(None),
    attack_type: str | None = Query(None),
    risk_level: str | None = Query(None),
    date_from: str | None = Query(None),
    date_to: str | None = Query(None),
    ai_support: bool | None = Query(None),
    _user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    """
    Lista janelas live historicas com filtros para frontend.
    """
    return list_history_windows(
        limit=limit,
        offset=offset,
        final_label=final_label,
        attack_type=attack_type,
        risk_level=risk_level,
        date_from=date_from,
        date_to=date_to,
        ai_support=ai_support,
    )


@app.get(
    "/history/windows/{window_id}",
    response_model=HistoryWindowResponse,
    responses={
        400: {"model": ApiErrorResponse},
        404: {"model": ApiErrorResponse},
        500: {"model": ApiErrorResponse},
        503: {"model": ApiErrorResponse},
    },
)
def history_window_detail_endpoint(
    window_id: int,
    _user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    """
    Retorna o detalhe de uma janela live historica pelo ID usado no frontend.
    """
    return get_history_window(window_id)


@app.get(
    "/history/alerts",
    response_model=HistoryAlertsResponse,
)
def history_alerts_endpoint(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    final_label: str | None = Query(None),
    attack_type: str | None = Query(None),
    risk_level: str | None = Query(None),
    date_from: str | None = Query(None),
    date_to: str | None = Query(None),
    ai_support: bool | None = Query(None),
    _user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    """
    Lista alertas historicos derivados das janelas live anomalas.
    """
    return list_history_alerts(
        limit=limit,
        offset=offset,
        final_label=final_label,
        attack_type=attack_type,
        risk_level=risk_level,
        date_from=date_from,
        date_to=date_to,
        ai_support=ai_support,
    )


@app.get(
    "/history/executions",
    response_model=HistoryExecutionsResponse,
)
def history_executions_endpoint(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    final_label: str | None = Query(None),
    attack_type: str | None = Query(None),
    risk_level: str | None = Query(None),
    date_from: str | None = Query(None),
    date_to: str | None = Query(None),
    ai_support: bool | None = Query(None),
    _user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    """
    Lista execucoes live derivadas das janelas persistidas.
    """
    return list_history_executions(
        limit=limit,
        offset=offset,
        final_label=final_label,
        attack_type=attack_type,
        risk_level=risk_level,
        date_from=date_from,
        date_to=date_to,
        ai_support=ai_support,
    )


def _build_response(
    *,
    payload: dict[str, Any],
    features_record: dict[str, Any],
    if_output: dict[str, Any],
    ae_output: dict[str, Any],
    heuristic_output: dict[str, Any],
    ensemble_output: dict[str, Any],
    decision_output: dict[str, Any],
) -> dict[str, Any]:
    """
    Monta a resposta completa do endpoint legado sem quebrar clientes atuais.
    """
    result = {
        "runtime_profile": str(decision_output["runtime_profile"]),
        "is_anomaly": bool(decision_output["is_anomaly"]),
        "final_label": str(decision_output["final_label"]),
        "is_attack": bool(decision_output["is_attack"]),
        "attack_type": str(decision_output["attack_type"]),
        "risk_level": str(decision_output["risk_level"]),
        "confidence": round(float(decision_output["confidence"]), 4),
        "explanation": str(decision_output["explanation"]),
        "isolation_score": float(decision_output["isolation_score"]),
        "autoencoder_score": float(decision_output["autoencoder_score"]),
        "ensemble_score": float(decision_output["ensemble_score"]),
        "heuristic_attack_type": str(decision_output["heuristic_attack_type"]),
        "decision_source": str(decision_output["decision_source"]),
        "agreement_level": str(decision_output["agreement_level"]),
        "if_pred": int(decision_output["if_pred"]),
        "ae_pred": int(decision_output["ae_pred"]),
        "heuristic_pred": bool(decision_output["heuristic_pred"]),
        "if_score": float(decision_output["if_score"]),
        "ae_score": float(decision_output["ae_score"]),
        "if_confidence": round(float(decision_output["if_confidence"]), 4),
        "ae_confidence": round(float(decision_output["ae_confidence"]), 4),
        "heuristic_confidence": round(float(decision_output["heuristic_confidence"]), 4),
        "decision_reason": str(decision_output["decision_reason"]),
        "conflict_winner": str(decision_output["conflict_winner"]),
    }

    return {
        "resultado_final": result,
        "modelos": {
            "isolation_forest": {
                "pred": int(if_output["pred"]),
                "score": float(if_output["raw_score"]),
                "normalized_score": round(float(if_output["normalized_score"]), 4),
                "confidence": round(float(if_output["confidence"]), 4),
            },
            "autoencoder": {
                "pred": int(ae_output["pred"]),
                "score": float(ae_output["raw_score"]),
                "log_score": float(ae_output["log_score"]),
                "normalized_score": round(float(ae_output["normalized_score"]), 4),
                "confidence": round(float(ae_output["confidence"]), 4),
                "threshold_raw": float(ae_output["threshold_raw"]),
                "threshold_log": float(ae_output["threshold_log"]),
            },
            "ensemble": {
                "runtime_profile": str(ensemble_output["runtime_profile"]),
                "pred": int(ensemble_output["pred"]),
                "score": float(ensemble_output["score"]),
                "threshold": float(ensemble_output["threshold"]),
                "if_weight": float(ensemble_output["if_weight"]),
                "ae_weight": float(ensemble_output["ae_weight"]),
                "normalized_if_score": round(float(ensemble_output["normalized_if_score"]), 4),
                "normalized_ae_score": round(float(ensemble_output["normalized_ae_score"]), 4),
            },
        },
        "classificacao_heuristica": {
            "attack_type": str(heuristic_output["attack_type"]),
            "matched": bool(heuristic_output["heuristic_detected_attack"]),
            "heuristic_detected_attack": bool(heuristic_output["heuristic_detected_attack"]),
            "heuristic_confidence": round(float(heuristic_output["heuristic_confidence"]), 4),
            "heuristic_reason": str(heuristic_output["heuristic_reason"]),
        },
        "decision_engine": decision_output,
        "input": {
            "received_payload": payload,
            "feature_mode": describe_active_features(),
            "engineered_features": features_record,
        },
    }


@app.post("/predict")
def predict_endpoint(
    data: NetworkInput,
    _user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    """
    Endpoint legado com inferencia sobre entrada estruturada simples.
    """
    payload = data.model_dump()

    try:
        x_df = prepare_inference_records([payload])
        x_matrix = to_feature_matrix(x_df)
        features_record = x_df.iloc[0].to_dict()

        if_output = predict_with_details(x_matrix)[0]
        ae_output = predict_autoencoder_with_details(x_matrix)[0]
        heuristic_output = analyze_behavior(features_record)
        ensemble_output = predict_ensemble_details(x_matrix)[0]
        decision_output = decide_attack(
            if_output=if_output,
            ae_output=ae_output,
            heuristic_output=heuristic_output,
            ensemble_output=ensemble_output,
        )

        print(
            "[INFO] Decisao final da API: "
            f"is_anomaly={decision_output['is_anomaly']}, "
            f"source={decision_output['decision_source']}, "
            f"agreement={decision_output['agreement_level']}, "
            f"reason={decision_output['explanation']}"
        )

        return _build_response(
            payload=payload,
            features_record=features_record,
            if_output=if_output,
            ae_output=ae_output,
            heuristic_output=heuristic_output,
            ensemble_output=ensemble_output,
            decision_output=decision_output,
        )

    except FileNotFoundError as exc:
        raise HTTPException(
            status_code=503,
            detail={
                "error": "model_artifact_missing",
                "message": "Os artefatos do Sinalyx nao foram encontrados.",
                "details": str(exc),
            },
        ) from exc
    except RuntimeError as exc:
        raise HTTPException(
            status_code=503,
            detail={
                "error": "model_not_ready",
                "message": "Os modelos do Sinalyx ainda nao estao prontos para inferencia.",
                "details": str(exc),
            },
        ) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail={
                "error": "invalid_input",
                "message": "Nao foi possivel preparar as features para inferencia.",
                "details": str(exc),
            },
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail={
                "error": "prediction_failure",
                "message": "Falha inesperada ao executar a inferencia do Sinalyx.",
                "details": str(exc),
            },
        ) from exc
