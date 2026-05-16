"""
Esquemas HTTP da API do Sinalyx.

Mantemos os contratos pequenos aqui para deixar o modulo principal mais
enxuto e facilitar evolucoes futuras da documentacao da API.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class ApiStatusResponse(BaseModel):
    """
    Resposta simples para status da aplicacao.
    """

    app: str
    status: str


class HealthResponse(BaseModel):
    """
    Resposta curta de health check.
    """

    status: str
    database: dict[str, bool]


class ApiErrorResponse(BaseModel):
    """
    Formato padrao de erro exposto pela API.
    """

    status: str = "error"
    error_code: str
    message: str
    details: dict[str, Any] = Field(default_factory=dict)


class ResponseErrorPayload(BaseModel):
    """
    Erro estruturado usado nos envelopes finais da API.
    """

    code: str
    message: str
    details: dict[str, Any] = Field(default_factory=dict)


class PaginationMeta(BaseModel):
    """
    Metadados reutilizaveis de paginacao.
    """

    total: int
    limit: int
    offset: int
    returned: int


class AuthLoginRequest(BaseModel):
    """
    Credenciais enviadas pela tela de login.
    """

    email: str
    password: str


class UserPayload(BaseModel):
    """
    Usuario exposto para o frontend sem hash de senha.
    """

    id: int
    name: str
    email: str
    role: str
    is_active: bool
    is_protected: bool = False
    created_at: str
    updated_at: str


class AuthLoginData(BaseModel):
    """
    Dados retornados apos autenticacao.
    """

    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserPayload


class AuthLoginResponse(BaseModel):
    """
    Envelope de resposta do login.
    """

    status: str
    data: AuthLoginData
    meta: dict[str, Any] = Field(default_factory=dict)
    error: ResponseErrorPayload | None = None


class AuthMeResponse(BaseModel):
    """
    Envelope do usuario autenticado atual.
    """

    status: str
    data: dict[str, UserPayload]
    meta: dict[str, Any] = Field(default_factory=dict)
    error: ResponseErrorPayload | None = None


class UserCreateRequest(BaseModel):
    """
    Payload para criacao de usuario pelo admin.
    """

    name: str
    email: str
    password: str
    role: str = "user"
    is_active: bool = True


class UserUpdateRequest(BaseModel):
    """
    Payload para edicao de usuario pelo admin.
    """

    name: str | None = None
    email: str | None = None
    password: str | None = None
    role: str | None = None
    is_active: bool | None = None


class UserStatusRequest(BaseModel):
    """
    Payload para ativar/desativar usuario.
    """

    is_active: bool


class UsersListResponse(BaseModel):
    """
    Envelope paginado de usuarios do painel admin.
    """

    status: str
    data: dict[str, list[UserPayload]]
    meta: PaginationMeta
    error: ResponseErrorPayload | None = None


class NetworkInput(BaseModel):
    """
    Contrato publico legado mantido por compatibilidade com clientes atuais.
    """

    connections: float
    bytes: float
    packets: float
    packet_size: float
    ports: float


class AnalysisSummaryPayload(BaseModel):
    """
    Resumo curto das predicoes finais e niveis de risco.
    """

    normal: int = 0
    anomaly: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


class AnalysisClassificationPayload(BaseModel):
    """
    Classificacao predominante da analise.
    """

    final_status: str
    predominant_attack_type: str
    predominant_risk_level: str
    confidence_avg: float | None = None


class PersistencePayload(BaseModel):
    """
    Resultado da tentativa de persistencia no PostgreSQL.
    """

    database_saved: bool
    error: str | None = None


class AnalysisCountsPayload(BaseModel):
    """
    Contadores detalhados emitidos pela analise.
    """

    prediction_counts: dict[str, int] = Field(default_factory=dict)
    attack_type_counts: dict[str, int] = Field(default_factory=dict)
    risk_level_counts: dict[str, int] = Field(default_factory=dict)
    decision_source_counts: dict[str, int] = Field(default_factory=dict)
    ai_support_counts: dict[str, int] = Field(default_factory=dict)
    ai_support_conservative_counts: dict[str, int] = Field(default_factory=dict)
    ai_support_type_counts: dict[str, int] = Field(default_factory=dict)
    ai_support_level_counts: dict[str, int] = Field(default_factory=dict)


class AnalysisParseStatsPayload(BaseModel):
    """
    Resumo do parse do arquivo enviado.
    """

    total_lines: int
    parsed_successfully: int
    parse_failures: int


class AnalysisArtifactsPayload(BaseModel):
    """
    Caminhos dos artefatos gerados para a analise.
    """

    uploaded_file: str
    parsed_events_csv: str
    features_csv: str
    inference_results_csv: str
    inference_report_json: str
    analysis_summary_json: str
    analysis_results_json: str


class AnalysisListItem(BaseModel):
    """
    Item resumido de listagem de analises locais.
    """

    analysis_id: str
    filename: str
    created_at: str
    total_windows: int
    final_status: str
    predominant_attack_type: str
    predominant_risk_level: str


class AnalysisListResponse(BaseModel):
    """
    Resposta da listagem de analises persistidas localmente.
    """

    status: str
    total_analyses: int
    analyses: list[AnalysisListItem] = Field(default_factory=list)
    data: dict[str, list[AnalysisListItem]] | None = None
    meta: PaginationMeta | None = None
    error: ResponseErrorPayload | None = None


class PFSenseAnalysisSummaryResponse(BaseModel):
    """
    Resposta resumida e persistivel de uma analise real do pfSense.
    """

    status: str
    analysis_id: str
    filename: str
    created_at: str
    total_windows: int
    summary: AnalysisSummaryPayload
    classification: AnalysisClassificationPayload
    counts: AnalysisCountsPayload
    parse_stats: AnalysisParseStatsPayload
    artifacts: AnalysisArtifactsPayload


class PFSenseAnalysisResponse(PFSenseAnalysisSummaryResponse):
    """
    Resposta completa do endpoint de analise com resultados por janela.
    """

    results: list[dict[str, Any]] = Field(default_factory=list)
    persistence: PersistencePayload


class PFSenseAnalysisResultsResponse(BaseModel):
    """
    Resposta dedicada aos resultados detalhados por janela.
    """

    status: str
    analysis_id: str
    filename: str
    created_at: str
    total_windows: int
    results: list[dict[str, Any]] = Field(default_factory=list)
    data: dict[str, list[dict[str, Any]]] | None = None
    meta: PaginationMeta | None = None
    error: ResponseErrorPayload | None = None


class LiveStatusResponse(BaseModel):
    """
    Resposta generica para estados do coletor/parser live.
    """

    status: str
    state: dict[str, Any] = Field(default_factory=dict)


class LiveRunResponse(BaseModel):
    """
    Resumo de uma execucao manual do fluxo live pfSense.
    """

    status: str
    execution_id: str
    processing_mode: str | None = None
    message: str
    collector: dict[str, Any] | None = None
    parser: dict[str, Any] = Field(default_factory=dict)
    window: dict[str, Any] = Field(default_factory=dict)
    persistence: dict[str, Any] = Field(default_factory=dict)
    artifacts: dict[str, str] = Field(default_factory=dict)
    summary: dict[str, Any] = Field(default_factory=dict)
    results_preview: list[dict[str, Any]] = Field(default_factory=list)


class ScoresPayload(BaseModel):
    """
    Scores resumidos dos modulos principais.
    """

    ensemble: float | None = None
    autoencoder: float | None = None
    isolation: float | None = None


class LiveWindowItem(BaseModel):
    """
    Item enxuto para listagem frontend das janelas live.
    """

    id: int
    execution_id: str | None = None
    window_id: str | None = None
    window_start: str | None = None
    window_end: str | None = None
    final_label: str | None = None
    attack_type: str | None = None
    risk_level: str | None = None
    decision_source: str | None = None
    ai_support: bool | None = None
    ai_support_conservative: bool | None = None
    scores: ScoresPayload = Field(default_factory=ScoresPayload)
    features: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)


class LiveWindowsData(BaseModel):
    """
    Bloco de dados paginado das janelas live.
    """

    windows: list[LiveWindowItem] = Field(default_factory=list)


class LiveWindowsResponse(BaseModel):
    """
    Listagem das ultimas janelas live persistidas.
    """

    status: str
    total_windows: int
    windows: list[LiveWindowItem] = Field(default_factory=list)
    data: LiveWindowsData | None = None
    meta: PaginationMeta | None = None
    error: ResponseErrorPayload | None = None


class DashboardRecentWindowItem(BaseModel):
    """
    Item resumido de janela recente usado pelo dashboard.
    """

    id: int
    execution_id: str | None = None
    window_id: str | None = None
    window_start: str | None = None
    window_end: str | None = None
    final_label: str | None = None
    attack_type: str | None = None
    risk_level: str | None = None
    decision_source: str | None = None
    ai_support: bool | None = None
    ai_support_conservative: bool | None = None
    scores: ScoresPayload = Field(default_factory=ScoresPayload)


class DashboardSummaryData(BaseModel):
    """
    Resumo agregado para cards e graficos do dashboard.
    """

    total_windows: int
    total_normal: int
    total_anomalies: int
    attack_type_distribution: dict[str, int] = Field(default_factory=dict)
    risk_level_distribution: dict[str, int] = Field(default_factory=dict)
    ai_support_count: int
    ai_support_conservative_count: int
    recent_windows: list[DashboardRecentWindowItem] = Field(default_factory=list)


class DashboardSummaryResponse(BaseModel):
    """
    Envelope padronizado do resumo do dashboard.
    """

    status: str
    data: DashboardSummaryData | dict[str, Any] = Field(default_factory=dict)
    meta: dict[str, Any] = Field(default_factory=dict)
    error: ResponseErrorPayload | None = None


class AlertsRecentData(BaseModel):
    """
    Bloco de dados dos alertas recentes.
    """

    alerts: list[LiveWindowItem] = Field(default_factory=list)


class AlertsRecentResponse(BaseModel):
    """
    Envelope paginado dos alertas recentes.
    """

    status: str
    data: AlertsRecentData
    meta: PaginationMeta
    error: ResponseErrorPayload | None = None


class HistoryPaginationMeta(PaginationMeta):
    """
    Metadados paginados com filtros historicos aplicados.
    """

    filters: dict[str, Any] = Field(default_factory=dict)


class HistoryWindowItem(BaseModel):
    """
    Janela historica estruturada para consultas do frontend.
    """

    id: int
    window_uid: str | None = None
    execution_id: str | None = None
    created_at: str | None = None
    status: str | None = None
    local_log_path: str | None = None
    remote_path: str | None = None
    parser_start_offset: int | None = None
    parser_end_offset: int | None = None
    window_id: str | None = None
    window_timestamp: str | None = None
    window_start: str | None = None
    window_end: str | None = None
    final_label: str | None = None
    attack_type: str | None = None
    risk_level: str | None = None
    decision_source: str | None = None
    decision_reason: str | None = None
    explanation: str | None = None
    confidence: float | None = None
    ai_support: bool | None = None
    ai_support_conservative: bool | None = None
    ensemble_score: float | None = None
    autoencoder_score: float | None = None
    isolation_score: float | None = None
    scores: ScoresPayload = Field(default_factory=ScoresPayload)
    src_ip: str | None = None
    dst_ip: str | None = None
    dst_port: str | int | None = None
    protocol: str | None = None
    action: str | None = None
    features: dict[str, Any] = Field(default_factory=dict)
    model_outputs: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)


class HistoryWindowsData(BaseModel):
    """
    Bloco de dados das janelas historicas.
    """

    windows: list[HistoryWindowItem] = Field(default_factory=list)


class HistoryWindowData(BaseModel):
    """
    Bloco de dados de uma janela historica especifica.
    """

    window: HistoryWindowItem


class HistoryAlertsData(BaseModel):
    """
    Bloco de dados dos alertas historicos.
    """

    alerts: list[HistoryWindowItem] = Field(default_factory=list)


class HistoryExecutionItem(BaseModel):
    """
    Execucao live derivada das janelas persistidas.
    """

    execution_id: str
    first_seen_at: str | None = None
    last_seen_at: str | None = None
    total_windows: int
    total_anomalies: int
    ai_support_count: int
    ai_support_conservative_count: int
    final_label_distribution: dict[str, int] = Field(default_factory=dict)
    attack_type_distribution: dict[str, int] = Field(default_factory=dict)
    risk_level_distribution: dict[str, int] = Field(default_factory=dict)
    status_distribution: dict[str, int] = Field(default_factory=dict)
    local_log_path: str | None = None
    remote_path: str | None = None


class HistoryExecutionsData(BaseModel):
    """
    Bloco de dados das execucoes historicas.
    """

    executions: list[HistoryExecutionItem] = Field(default_factory=list)


class HistorySummaryResponse(BaseModel):
    """
    Envelope do resumo historico consolidado.
    """

    status: str
    data: dict[str, Any] = Field(default_factory=dict)
    meta: dict[str, Any] = Field(default_factory=dict)
    error: ResponseErrorPayload | None = None


class HistoryWindowsResponse(BaseModel):
    """
    Envelope paginado das janelas historicas.
    """

    status: str
    data: HistoryWindowsData
    meta: HistoryPaginationMeta
    error: ResponseErrorPayload | None = None


class HistoryWindowResponse(BaseModel):
    """
    Envelope de detalhe de uma janela historica.
    """

    status: str
    data: HistoryWindowData
    meta: dict[str, Any] = Field(default_factory=dict)
    error: ResponseErrorPayload | None = None


class HistoryAlertsResponse(BaseModel):
    """
    Envelope paginado dos alertas historicos.
    """

    status: str
    data: HistoryAlertsData
    meta: HistoryPaginationMeta
    error: ResponseErrorPayload | None = None


class HistoryExecutionsResponse(BaseModel):
    """
    Envelope paginado das execucoes historicas.
    """

    status: str
    data: HistoryExecutionsData
    meta: HistoryPaginationMeta
    error: ResponseErrorPayload | None = None


class SystemAuditResponse(BaseModel):
    """
    Envelope do endpoint de auditoria operacional do sistema.
    """

    status: str
    data: dict[str, Any] = Field(default_factory=dict)
    meta: dict[str, Any] = Field(default_factory=dict)
    error: ResponseErrorPayload | None = None
