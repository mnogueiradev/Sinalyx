export interface ApiEnvelope<TData, TMeta = Record<string, unknown>> {
  status: string
  data: TData
  meta?: TMeta
  error?: ApiError | null
}

export interface ApiError {
  code?: string
  message?: string
  details?: Record<string, unknown>
}

export type UserRole = 'admin' | 'user'

export interface AuthUser {
  id: number
  name: string
  email: string
  role: UserRole
  is_active: boolean
  is_protected?: boolean
  created_at: string
  updated_at: string
}

export interface AuthLoginData {
  access_token: string
  token_type: string
  expires_in: number
  user: AuthUser
}

export interface UserPayload {
  name: string
  email: string
  password?: string
  role: UserRole
  is_active: boolean
}

export interface PaginationMeta {
  total: number
  limit: number
  offset: number
  returned: number
  filters?: Record<string, unknown>
}

export interface Scores {
  ensemble?: number | null
  autoencoder?: number | null
  isolation?: number | null
}

export interface WindowItem {
  id: number
  window_uid?: string | null
  created_at?: string | null
  status?: string | null
  local_log_path?: string | null
  remote_path?: string | null
  parser_start_offset?: number | null
  parser_end_offset?: number | null
  execution_id?: string | null
  window_id?: string | null
  window_timestamp?: string | null
  window_start?: string | null
  window_end?: string | null
  final_label?: string | null
  attack_type?: string | null
  risk_level?: string | null
  decision_source?: string | null
  decision_reason?: string | null
  explanation?: string | null
  confidence?: number | null
  ai_support?: boolean | null
  ai_support_conservative?: boolean | null
  ensemble_score?: number | null
  autoencoder_score?: number | null
  isolation_score?: number | null
  scores?: Scores
  src_ip?: string | null
  dst_ip?: string | null
  dst_port?: string | number | null
  protocol?: string | null
  action?: string | null
  features?: Record<string, unknown>
  model_outputs?: Record<string, unknown>
  metadata?: Record<string, unknown>
}

export interface DashboardSummary {
  total_windows: number
  total_normal: number
  total_anomalies: number
  attack_type_distribution: Record<string, number>
  risk_level_distribution: Record<string, number>
  ai_support_count: number
  ai_support_conservative_count: number
  recent_windows: WindowItem[]
}

export interface AlertItem extends WindowItem {
  features: Record<string, unknown>
  metadata: Record<string, unknown>
}

export interface HistorySummary {
  analyses?: {
    total_analyses?: number
    total_results?: number
    final_status_distribution?: Record<string, number>
    attack_type_distribution?: Record<string, number>
    risk_level_distribution?: Record<string, number>
    latest_analysis?: AnalysisItem | null
  }
  live?: {
    total_windows?: number
    total_alerts?: number
    total_executions?: number
    final_label_distribution?: Record<string, number>
    attack_type_distribution?: Record<string, number>
    risk_level_distribution?: Record<string, number>
    ai_support_count?: number
    ai_support_conservative_count?: number
    latest_window?: WindowItem | null
    latest_alert?: AlertItem | null
  }
}

export interface HistoryExecution {
  execution_id: string
  first_seen_at?: string | null
  last_seen_at?: string | null
  total_windows?: number
  total_anomalies?: number
  ai_support_count?: number
  ai_support_conservative_count?: number
  final_label_distribution?: Record<string, number>
  attack_type_distribution?: Record<string, number>
  risk_level_distribution?: Record<string, number>
  status_distribution?: Record<string, number>
  local_log_path?: string | null
  remote_path?: string | null
}

export interface WindowFilters {
  final_label?: string
  attack_type?: string
  risk_level?: string
  ai_support?: boolean | null
  date_from?: string
  date_to?: string
  src_ip?: string
  dst_ip?: string
  dst_port?: string
  protocol?: string
  action?: string
  only_anomalies?: boolean
}

export interface SystemAudit {
  system: {
    name: string
    version: string
    environment: string
    audited_at: string
  }
  database: {
    enabled: boolean
    available: boolean
  }
  counts: {
    users: number
    live_windows: number
    alerts: number
    executions: number
    analyses: number
    analysis_results: number
  }
  runtime: {
    parser: LiveRuntimeState
    collector: LiveRuntimeState
    last_processing?: string | null
  }
  models: {
    expected_features: string
    preload_error?: string | null
  }
}

export interface AnalysisItem {
  analysis_id: string
  filename: string
  created_at: string
  total_windows: number
  final_status: string
  predominant_attack_type: string
  predominant_risk_level: string
}

export interface AnalysisClassification {
  final_status: string
  predominant_attack_type: string
  predominant_risk_level: string
  confidence_avg?: number | null
}

export interface AnalysisDetails {
  status: string
  analysis_id: string
  filename: string
  created_at: string
  total_windows: number
  summary?: Record<string, number>
  classification?: AnalysisClassification
  counts?: Record<string, Record<string, number>>
  parse_stats?: Record<string, number>
  artifacts?: Record<string, string>
}

export interface AnalysisResultsResponse {
  status: string
  analysis_id: string
  filename: string
  created_at: string
  total_windows: number
  results: Record<string, unknown>[]
  data?: {
    results: Record<string, unknown>[]
  }
  meta?: PaginationMeta
  error?: ApiError | null
}

export interface SystemStatus {
  health: SystemBlock<HealthStatus>
  parser: SystemBlock<LiveStatusResponse>
  collector: SystemBlock<LiveStatusResponse>
}

export interface HealthStatus {
  status: string
  database: {
    enabled: boolean
    available: boolean
  }
}

export interface SystemBlock<TData> {
  ok: boolean
  data?: TData
  error?: string
}

export interface LiveStatusResponse {
  status: string
  state: LiveRuntimeState
}

export interface LiveRuntimeState {
  last_run_status?: string | null
  last_fetch_status?: string | null
  last_processing_mode?: string | null
  last_error?: string | null
  last_run_at?: string | null
  last_fetch_at?: string | null
  last_execution_id?: string | null
  last_lines_new?: number | null
  last_windows_generated?: number | null
  pending_events_count?: number | null
  remote_path?: string | null
  local_path?: string | null
  local_file_exists?: boolean | null
  current_file_size?: number | null
  file_size?: number | null
  [key: string]: unknown
}
