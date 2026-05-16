const ATTACK_TYPE_LABELS: Record<string, string> = {
  normal: 'Normal',
  anomaly: 'Anomalia',
  port_scan: 'Varredura de Portas',
  brute_force: 'Força Bruta',
  syn_flood: 'DDoS',
  ssh_suspicious: 'SSH Suspeito',
  suspicious: 'Suspeito',
  unknown: 'Desconhecido',
}

const RISK_LEVEL_LABELS: Record<string, string> = {
  low: 'Baixo',
  medium: 'Médio',
  high: 'Alto',
  critical: 'Crítico',
  unknown: 'Desconhecido',
}

const FINAL_LABELS: Record<string, string> = {
  normal: 'Normal',
  anomaly: 'Anomalia',
  available: 'Disponível',
  unavailable: 'Indisponível',
  success: 'Sucesso',
  suspicious: 'Suspeito',
  unknown: 'Desconhecido',
}

const DECISION_SOURCE_LABELS: Record<string, string> = {
  decision_engine: 'Motor de Decisão',
  ensemble: 'Ensemble',
  heuristic: 'Heurística',
  heuristic_signature: 'Heurística',
  autoencoder: 'Autoencoder',
  isolation_forest: 'Isolation Forest',
  safe_negative: 'Sistema',
  system: 'Sistema',
  unknown: 'Desconhecida',
}

const TECHNICAL_LABELS: Record<string, string> = {
  final_label: 'Classificação final',
  attack_type: 'Tipo de ataque',
  risk_level: 'Risco',
  decision_source: 'Fonte da decisão',
  decision_reason: 'Motivo da decisão',
  confidence: 'Confiança',
  ai_support: 'Apoio da IA',
  autoencoder_score: 'Score do Autoencoder',
  isolation_score: 'Score do Isolation Forest',
  ensemble_score: 'Score do Ensemble',
  connections: 'Conexões',
  packets: 'Pacotes',
  bytes: 'Bytes',
  ports: 'Portas',
  protocol: 'Protocolo',
  action: 'Ação',
  window_start: 'Início da janela',
  window_end: 'Fim da janela',
}

function normalize(value?: string | number | boolean | null): string {
  return String(value ?? 'unknown').trim().toLowerCase()
}

function fallbackLabel(value?: string | number | boolean | null): string {
  const text = String(value ?? 'unknown')
  return text
    .split('_')
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(' ')
}

export function formatAttackType(value?: string | null): string {
  const key = normalize(value)
  return ATTACK_TYPE_LABELS[key] ?? fallbackLabel(value)
}

export function formatRiskLevel(value?: string | null): string {
  const key = normalize(value)
  return RISK_LEVEL_LABELS[key] ?? fallbackLabel(value)
}

export function formatFinalLabel(value?: string | null): string {
  const key = normalize(value)
  return FINAL_LABELS[key] ?? fallbackLabel(value)
}

export function formatDecisionSource(value?: string | null): string {
  const key = normalize(value)
  return DECISION_SOURCE_LABELS[key] ?? fallbackLabel(value)
}

export function formatBoolean(value?: boolean | null): string {
  if (typeof value !== 'boolean') {
    return 'Desconhecido'
  }
  return value ? 'Sim' : 'Não'
}

export function formatDateTime(value?: string | null): string {
  if (!value) {
    return '-'
  }
  return value.replace('T', ' ').slice(0, 19)
}

export function formatTechnicalLabel(value: string): string {
  return TECHNICAL_LABELS[value] ?? fallbackLabel(value)
}
