<template>
  <section class="space-y-5">
    <div class="flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
      <div>
        <p class="text-xs font-medium text-slate-500">Janelas e análises processadas</p>
        <h1 class="text-xl font-semibold text-white">Histórico de análises</h1>
      </div>
    </div>

    <div class="panel flex flex-wrap gap-2 p-2">
      <button
        v-for="tab in tabs"
        :key="tab.key"
        type="button"
        class="focus-ring rounded-md px-3 py-2 text-sm font-medium transition"
        :class="
          activeTab === tab.key
            ? 'bg-sky-400/10 text-sky-200 ring-1 ring-sky-400/20'
            : 'text-slate-400 hover:bg-surface-800 hover:text-white'
        "
        @click="activeTab = tab.key"
      >
        {{ tab.label }}
      </button>
    </div>

    <div v-if="usesWindowFilters" class="panel p-4">
      <div class="grid gap-3 md:grid-cols-3 xl:grid-cols-6">
        <label class="text-sm">
          <span class="muted-label">Período inicial</span>
          <input
            v-model="filters.date_from"
            type="datetime-local"
            class="mt-2 w-full rounded-md border border-slate-800 bg-surface-850 px-3 py-2 text-slate-200"
          />
        </label>
        <label class="text-sm">
          <span class="muted-label">Período final</span>
          <input
            v-model="filters.date_to"
            type="datetime-local"
            class="mt-2 w-full rounded-md border border-slate-800 bg-surface-850 px-3 py-2 text-slate-200"
          />
        </label>
        <label class="text-sm">
          <span class="muted-label">Classificação</span>
          <select v-model="filters.final_label" class="mt-2 w-full rounded-md border border-slate-800 bg-surface-850 px-3 py-2 text-slate-200">
            <option value="">Todas</option>
            <option value="normal">Normal</option>
            <option value="anomaly">Anomalia</option>
          </select>
        </label>
        <label class="text-sm">
          <span class="muted-label">Tipo de ataque</span>
          <select v-model="filters.attack_type" class="mt-2 w-full rounded-md border border-slate-800 bg-surface-850 px-3 py-2 text-slate-200">
            <option value="">Todos</option>
            <option value="normal">Normal</option>
            <option value="port_scan">Varredura de Portas</option>
            <option value="brute_force">Força Bruta</option>
            <option value="syn_flood">DDoS</option>
            <option value="ssh_suspicious">SSH Suspeito</option>
          </select>
        </label>
        <label class="text-sm">
          <span class="muted-label">Risco</span>
          <select v-model="filters.risk_level" class="mt-2 w-full rounded-md border border-slate-800 bg-surface-850 px-3 py-2 text-slate-200">
            <option value="">Todos</option>
            <option value="low">Baixo</option>
            <option value="medium">Médio</option>
            <option value="high">Alto</option>
            <option value="critical">Crítico</option>
          </select>
        </label>
        <label class="text-sm">
          <span class="muted-label">Apoio da IA</span>
          <select v-model="filters.ai_support" class="mt-2 w-full rounded-md border border-slate-800 bg-surface-850 px-3 py-2 text-slate-200">
            <option value="">Todos</option>
            <option value="true">Sim</option>
            <option value="false">Não</option>
          </select>
        </label>
        <label class="text-sm">
          <span class="muted-label">IP de origem</span>
          <input v-model="filters.src_ip" class="mt-2 w-full rounded-md border border-slate-800 bg-surface-850 px-3 py-2 text-slate-200" />
        </label>
        <label class="text-sm">
          <span class="muted-label">IP de destino</span>
          <input v-model="filters.dst_ip" class="mt-2 w-full rounded-md border border-slate-800 bg-surface-850 px-3 py-2 text-slate-200" />
        </label>
        <label class="text-sm">
          <span class="muted-label">Porta</span>
          <input v-model="filters.dst_port" class="mt-2 w-full rounded-md border border-slate-800 bg-surface-850 px-3 py-2 text-slate-200" />
        </label>
        <label class="text-sm">
          <span class="muted-label">Protocolo</span>
          <input v-model="filters.protocol" class="mt-2 w-full rounded-md border border-slate-800 bg-surface-850 px-3 py-2 text-slate-200" />
        </label>
        <label class="text-sm">
          <span class="muted-label">Ação</span>
          <input v-model="filters.action" class="mt-2 w-full rounded-md border border-slate-800 bg-surface-850 px-3 py-2 text-slate-200" />
        </label>
        <label class="flex items-end gap-2 text-sm text-slate-300">
          <input
            v-model="filters.only_anomalies"
            type="checkbox"
            class="h-4 w-4 rounded border-slate-700 bg-surface-850 text-sky-400"
          />
          Somente anomalias
        </label>
      </div>
      <div class="mt-4 flex flex-wrap gap-2">
        <button
          type="button"
          class="btn btn-primary"
          @click="reloadFiltered"
        >
          Aplicar filtros
        </button>
        <button
          type="button"
          class="btn btn-secondary"
          @click="clearFilters"
        >
          Limpar
        </button>
      </div>
    </div>

    <div class="panel p-4">
      <div class="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
        <div>
          <p class="muted-label">Relatórios</p>
          <p class="mt-1 text-sm text-slate-400">Você pode exportar todos os dados carregados ou apenas os filtrados.</p>
        </div>
        <div class="flex flex-wrap gap-2">
          <button class="btn btn-primary" type="button" @click="exportFilteredHistoryCsv">
            Exportar filtrados
          </button>
          <button class="btn btn-secondary" type="button" @click="exportAllHistoryCsv">
            Exportar tudo
          </button>
          <button class="btn btn-secondary" type="button" @click="exportAlertsCsv">
            Exportar alertas
          </button>
          <button class="btn btn-secondary" type="button" @click="exportExecutionsCsv">
            Exportar execuções
          </button>
          <button class="btn btn-secondary" type="button" @click="exportSummaryJson">
            Exportar JSON
          </button>
        </div>
      </div>
      <p v-if="exportFeedback" class="mt-3 text-sm text-slate-300">{{ exportFeedback }}</p>
    </div>

    <template v-if="activeTab === 'summary'">
      <LoadingState v-if="loading.summary" />
      <ErrorState v-else-if="errors.summary" :message="errors.summary" />
      <template v-else-if="summary">
        <div class="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          <SummaryBox label="Janelas" :value="summary.live?.total_windows" />
          <SummaryBox label="Alertas" :value="summary.live?.total_alerts" />
          <SummaryBox label="Execuções" :value="summary.live?.total_executions" />
          <SummaryBox label="Apoio da IA" :value="summary.live?.ai_support_count" />
        </div>

        <div class="grid gap-4 xl:grid-cols-2">
          <DistributionBox
            title="Distribuição"
            :items="summary.live?.attack_type_distribution"
            kind="attack"
          />
          <DistributionBox
            title="Risco"
            :items="summary.live?.risk_level_distribution"
            kind="risk"
          />
        </div>
      </template>
    </template>

    <template v-else-if="activeTab === 'windows'">
      <LoadingState v-if="activeWindowLoading" />
      <ErrorState v-else-if="activeWindowError" :message="activeWindowError" />
      <div v-else class="panel overflow-hidden">
        <div class="border-b border-slate-800 px-4 py-3">
          <div class="flex items-center justify-between gap-3">
            <div>
              <h2 class="text-sm font-semibold text-white">Janelas</h2>
              <p class="mt-1 text-sm text-slate-500">
                Visão completa de tudo que foi processado, incluindo tráfego normal e anomalias.
              </p>
            </div>
            <p v-if="activeWindowMeta" class="text-sm text-slate-500">
              {{ activeWindowRows.length }} exibidos de {{ activeWindowMeta.total }}
            </p>
          </div>
        </div>
        <p v-if="activeWindowRows.length === 0" class="p-4 text-sm text-slate-400">
          Nenhum resultado encontrado.
        </p>
        <div v-else class="overflow-x-auto">
          <table class="min-w-full divide-y divide-slate-800 text-sm">
            <thead class="bg-surface-850 text-left text-xs uppercase text-slate-500">
              <tr>
                <th class="px-4 py-3 font-medium">Início da janela</th>
                <th class="px-4 py-3 font-medium">Classificação</th>
                <th class="px-4 py-3 font-medium">Tipo de ataque</th>
                <th class="px-4 py-3 font-medium">Risco</th>
                <th class="px-4 py-3 font-medium">Fonte da decisão</th>
                <th class="px-4 py-3 font-medium">Score do Ensemble</th>
                <th class="px-4 py-3 font-medium">Apoio da IA</th>
                <th class="px-4 py-3 font-medium">Detalhe</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-slate-800">
              <tr
                v-for="row in activeWindowRows"
                :key="row.id"
                class="cursor-pointer transition hover:bg-surface-850/70"
                @click="openWindow(row.id)"
              >
                <td class="px-4 py-3 font-medium text-sky-300">{{ formatDateTime(row.window_start) }}</td>
                <td class="px-4 py-3"><StatusBadge :value="row.final_label" /></td>
                <td class="px-4 py-3 text-slate-300">{{ formatAttackType(row.attack_type) }}</td>
                <td class="px-4 py-3"><StatusBadge :value="row.risk_level" /></td>
                <td class="px-4 py-3 text-slate-400">{{ formatDecisionSource(row.decision_source) }}</td>
                <td class="px-4 py-3 text-slate-300">{{ formatScore(row.scores?.ensemble ?? row.ensemble_score) }}</td>
                <td class="px-4 py-3"><StatusBadge :value="row.ai_support" /></td>
                <td class="px-4 py-3">
                  <button class="btn btn-secondary" type="button" @click.stop="openWindow(row.id)">
                    Abrir
                  </button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </template>

    <template v-else-if="activeTab === 'alerts'">
      <LoadingState v-if="activeWindowLoading" />
      <ErrorState v-else-if="activeWindowError" :message="activeWindowError" />
      <div v-else class="space-y-4">
        <div class="panel p-4">
          <div class="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
            <div>
              <h2 class="text-sm font-semibold text-white">Alertas</h2>
              <p class="mt-1 text-sm text-slate-500">
                Triagem focada apenas nas janelas anômalas que precisam de atenção.
              </p>
            </div>
            <p v-if="activeWindowMeta" class="text-sm text-slate-500">
              {{ activeWindowRows.length }} exibidos de {{ activeWindowMeta.total }}
            </p>
          </div>
        </div>

        <p v-if="activeWindowRows.length === 0" class="panel p-4 text-sm text-slate-400">
          Nenhum resultado encontrado.
        </p>

        <div v-else class="grid gap-3 xl:grid-cols-2">
          <article
            v-for="row in activeWindowRows"
            :key="row.id"
            class="panel border-l-4 border-l-rose-400 p-4"
          >
            <div class="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
              <div>
                <p class="text-sm font-semibold text-white">{{ formatAttackType(row.attack_type) }}</p>
                <p class="mt-1 text-sm text-slate-500">{{ formatDateTime(row.window_start) }}</p>
              </div>
              <StatusBadge :value="row.risk_level" />
            </div>

            <div class="mt-4 grid gap-3 text-sm sm:grid-cols-2">
              <div>
                <p class="muted-label">Classificação</p>
                <p class="mt-1 text-slate-200">{{ formatFinalLabel(row.final_label) }}</p>
              </div>
              <div>
                <p class="muted-label">Fonte da decisão</p>
                <p class="mt-1 text-slate-200">{{ formatDecisionSource(row.decision_source) }}</p>
              </div>
              <div>
                <p class="muted-label">Score do Ensemble</p>
                <p class="mt-1 font-mono text-slate-200">{{ formatScore(row.scores?.ensemble ?? row.ensemble_score) }}</p>
              </div>
              <div>
                <p class="muted-label">Apoio da IA</p>
                <div class="mt-1"><StatusBadge :value="row.ai_support" /></div>
              </div>
            </div>

            <div class="mt-4 flex justify-end">
              <button class="btn btn-secondary" type="button" @click="openWindow(row.id)">
                Abrir
              </button>
            </div>
          </article>
        </div>
      </div>
    </template>

    <template v-else-if="activeTab === 'executions'">
      <LoadingState v-if="loading.executions" />
      <ErrorState v-else-if="errors.executions" :message="errors.executions" />
      <div v-else class="panel overflow-hidden">
        <div class="border-b border-slate-800 px-4 py-3">
          <div class="flex items-center justify-between gap-3">
            <h2 class="text-sm font-semibold text-white">Execuções</h2>
            <p v-if="executionsMeta" class="text-sm text-slate-500">
              {{ filteredExecutions.length }} exibidas de {{ executionsMeta.total }}
            </p>
          </div>
        </div>
        <p v-if="filteredExecutions.length === 0" class="p-4 text-sm text-slate-400">
          Nenhum resultado encontrado.
        </p>
        <div v-else class="overflow-x-auto">
          <table class="min-w-full divide-y divide-slate-800 text-sm">
            <thead class="bg-surface-850 text-left text-xs uppercase text-slate-500">
              <tr>
                <th class="px-4 py-3 font-medium">Execução</th>
                <th class="px-4 py-3 font-medium">Primeiro registro</th>
                <th class="px-4 py-3 font-medium">Janelas</th>
                <th class="px-4 py-3 font-medium">Anomalias</th>
                <th class="px-4 py-3 font-medium">Tipo de ataque</th>
                <th class="px-4 py-3 font-medium">Apoio da IA</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-slate-800">
              <tr v-for="execution in filteredExecutions" :key="execution.execution_id">
                <td class="max-w-[260px] truncate px-4 py-3 font-mono text-xs text-sky-300">
                  {{ execution.execution_id }}
                </td>
                <td class="px-4 py-3 text-slate-400">{{ formatDateTime(execution.first_seen_at) }}</td>
                <td class="px-4 py-3 text-slate-300">{{ execution.total_windows ?? 0 }}</td>
                <td class="px-4 py-3 text-slate-300">{{ execution.total_anomalies ?? 0 }}</td>
                <td class="px-4 py-3 text-slate-300">
                  {{ firstDistributionLabel(execution.attack_type_distribution) }}
                </td>
                <td class="px-4 py-3 text-slate-300">{{ execution.ai_support_count ?? 0 }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </template>

    <template v-else>
      <LoadingState v-if="loading.analyses" />
      <ErrorState v-else-if="errors.analyses" :message="errors.analyses" />
      <div v-else class="panel overflow-hidden">
        <div class="border-b border-slate-800 px-4 py-3">
          <div class="flex items-center justify-between gap-3">
            <h2 class="text-sm font-semibold text-white">Análises antigas</h2>
            <p v-if="analysesMeta" class="text-sm text-slate-500">
              {{ filteredAnalyses.length }} exibidas de {{ analysesMeta.total }}
            </p>
          </div>
        </div>
        <p v-if="filteredAnalyses.length === 0" class="p-4 text-sm text-slate-400">
          Nenhum resultado encontrado.
        </p>
        <div v-else class="overflow-x-auto">
          <table class="min-w-full divide-y divide-slate-800 text-sm">
            <thead class="bg-surface-850 text-left text-xs uppercase text-slate-500">
              <tr>
                <th class="px-4 py-3 font-medium">Arquivo</th>
                <th class="px-4 py-3 font-medium">Criado em</th>
                <th class="px-4 py-3 font-medium">Janelas</th>
                <th class="px-4 py-3 font-medium">Status</th>
                <th class="px-4 py-3 font-medium">Tipo de ataque</th>
                <th class="px-4 py-3 font-medium">Risco</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-slate-800">
              <tr v-for="analysis in filteredAnalyses" :key="analysis.analysis_id">
                <td class="px-4 py-3">
                  <RouterLink
                    class="font-medium text-sky-300 hover:text-sky-200"
                    :to="`/analyses/${analysis.analysis_id}`"
                  >
                    {{ analysis.filename }}
                  </RouterLink>
                </td>
                <td class="px-4 py-3 text-slate-400">{{ formatDateTime(analysis.created_at) }}</td>
                <td class="px-4 py-3 text-slate-300">{{ analysis.total_windows }}</td>
                <td class="px-4 py-3"><StatusBadge :value="analysis.final_status" /></td>
                <td class="px-4 py-3 text-slate-300">{{ formatAttackType(analysis.predominant_attack_type) }}</td>
                <td class="px-4 py-3"><StatusBadge :value="analysis.predominant_risk_level" /></td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </template>
  </section>
</template>

<script setup lang="ts">
import { computed, defineComponent, h, onMounted, reactive, ref } from 'vue'
import { RouterLink, useRouter } from 'vue-router'

import ErrorState from '@/components/ui/ErrorState.vue'
import LoadingState from '@/components/ui/LoadingState.vue'
import StatusBadge from '@/components/ui/StatusBadge.vue'
import { useGlobalSearch } from '@/composables/useGlobalSearch'
import {
  getAnalyses,
  getHistoryAlerts,
  getHistoryExecutions,
  getHistorySummary,
  getHistoryWindows,
} from '@/services/api'
import type {
  AnalysisItem,
  HistoryExecution,
  HistorySummary,
  PaginationMeta,
  WindowFilters,
  WindowItem,
} from '@/types/api'
import {
  dateStamp,
  exportCsv,
  exportJson,
  type CsvColumn,
} from '@/utils/exporters'
import {
  analysisSearchText,
  executionSearchText,
  filterBySearch,
  normalizeSearchText,
  windowSearchText,
} from '@/utils/search'
import {
  formatAttackType,
  formatDateTime,
  formatDecisionSource,
  formatFinalLabel,
  formatRiskLevel,
} from '@/utils/formatters'

type TabKey = 'summary' | 'windows' | 'alerts' | 'executions' | 'analyses'
type DistributionKind = 'attack' | 'risk' | 'plain'

const tabs: { key: TabKey; label: string }[] = [
  { key: 'summary', label: 'Resumo' },
  { key: 'windows', label: 'Janelas' },
  { key: 'alerts', label: 'Alertas' },
  { key: 'executions', label: 'Execuções' },
  { key: 'analyses', label: 'Análises antigas' },
]

const activeTab = ref<TabKey>('summary')
const router = useRouter()
const { trimmedSearch } = useGlobalSearch()

const summary = ref<HistorySummary | null>(null)
const windows = ref<WindowItem[]>([])
const alerts = ref<WindowItem[]>([])
const executions = ref<HistoryExecution[]>([])
const analyses = ref<AnalysisItem[]>([])
const exportFeedback = ref('')

const windowsMeta = ref<PaginationMeta | null>(null)
const alertsMeta = ref<PaginationMeta | null>(null)
const executionsMeta = ref<PaginationMeta | null>(null)
const analysesMeta = ref<PaginationMeta | null>(null)

const loading = reactive({
  summary: true,
  windows: true,
  alerts: true,
  executions: true,
  analyses: true,
})

const errors = reactive({
  summary: '',
  windows: '',
  alerts: '',
  executions: '',
  analyses: '',
})

const filters = reactive({
  final_label: '',
  attack_type: '',
  risk_level: '',
  ai_support: '',
  date_from: '',
  date_to: '',
  src_ip: '',
  dst_ip: '',
  dst_port: '',
  protocol: '',
  action: '',
  only_anomalies: false,
})

const usesWindowFilters = computed(
  () => activeTab.value === 'windows' || activeTab.value === 'alerts',
)

const activeWindowRows = computed<WindowItem[]>(() => {
  const rows = activeTab.value === 'alerts' ? alerts.value : windows.value
  return filterBySearch(
    rows.filter(matchesLocalWindowFilters),
    trimmedSearch.value,
    windowSearchText,
  )
})
const activeWindowMeta = computed(() =>
  activeTab.value === 'alerts' ? alertsMeta.value : windowsMeta.value,
)
const activeWindowLoading = computed(() =>
  activeTab.value === 'alerts' ? loading.alerts : loading.windows,
)
const activeWindowError = computed(() =>
  activeTab.value === 'alerts' ? errors.alerts : errors.windows,
)
const filteredExecutions = computed(() =>
  filterBySearch(executions.value, trimmedSearch.value, executionSearchText),
)
const filteredAnalyses = computed(() =>
  filterBySearch(analyses.value, trimmedSearch.value, analysisSearchText),
)

function currentFilters(): WindowFilters {
  const finalLabel =
    filters.only_anomalies && !filters.final_label
      ? 'anomaly'
      : filters.final_label || undefined

  return {
    final_label: finalLabel,
    attack_type: filters.attack_type || undefined,
    risk_level: filters.risk_level || undefined,
    ai_support:
      filters.ai_support === ''
        ? null
        : filters.ai_support === 'true',
    date_from: filters.date_from || undefined,
    date_to: filters.date_to || undefined,
    src_ip: filters.src_ip || undefined,
    dst_ip: filters.dst_ip || undefined,
    dst_port: filters.dst_port || undefined,
    protocol: filters.protocol || undefined,
    action: filters.action || undefined,
    only_anomalies: filters.only_anomalies,
  }
}

function matchesLocalWindowFilters(row: WindowItem): boolean {
  if (filters.only_anomalies && row.final_label !== 'anomaly') {
    return false
  }

  return (
    textIncludes(row.src_ip, filters.src_ip)
    && textIncludes(row.dst_ip, filters.dst_ip)
    && textIncludes(row.dst_port, filters.dst_port)
    && textIncludes(row.protocol, filters.protocol)
    && textIncludes(row.action, filters.action)
    && dateInRange(row.window_start)
  )
}

function textIncludes(value: unknown, query: string): boolean {
  if (!query.trim()) {
    return true
  }
  return normalizeSearchText(value).includes(normalizeSearchText(query))
}

function dateInRange(value?: string | null): boolean {
  if (!filters.date_from && !filters.date_to) {
    return true
  }
  const timestamp = value ? new Date(value).getTime() : Number.NaN
  if (Number.isNaN(timestamp)) {
    return false
  }
  if (filters.date_from && timestamp < new Date(filters.date_from).getTime()) {
    return false
  }
  if (filters.date_to && timestamp > new Date(filters.date_to).getTime()) {
    return false
  }
  return true
}

const windowCsvColumns: CsvColumn<WindowItem>[] = [
  { header: 'ID', value: (item) => item.id },
  { header: 'Janela', value: (item) => item.window_id },
  { header: 'Execução', value: (item) => item.execution_id },
  { header: 'Início da janela', value: (item) => item.window_start },
  { header: 'Fim da janela', value: (item) => item.window_end },
  { header: 'Classificação', value: (item) => formatFinalLabel(item.final_label) },
  { header: 'Tipo de ataque', value: (item) => formatAttackType(item.attack_type) },
  { header: 'Risco', value: (item) => formatRiskLevel(item.risk_level) },
  { header: 'Fonte da decisão', value: (item) => formatDecisionSource(item.decision_source) },
  { header: 'Confiança', value: (item) => item.confidence },
  { header: 'Apoio da IA', value: (item) => (item.ai_support ? 'Sim' : 'Não') },
  { header: 'Score do Ensemble', value: (item) => item.scores?.ensemble ?? item.ensemble_score },
  { header: 'Score do Autoencoder', value: (item) => item.scores?.autoencoder ?? item.autoencoder_score },
  { header: 'Score do Isolation Forest', value: (item) => item.scores?.isolation ?? item.isolation_score },
  { header: 'IP de origem', value: (item) => item.src_ip },
  { header: 'IP de destino', value: (item) => item.dst_ip },
  { header: 'Porta', value: (item) => item.dst_port },
  { header: 'Protocolo', value: (item) => item.protocol },
  { header: 'Ação', value: (item) => item.action },
]

const executionCsvColumns: CsvColumn<HistoryExecution>[] = [
  { header: 'Execução', value: (item) => item.execution_id },
  { header: 'Primeiro registro', value: (item) => item.first_seen_at },
  { header: 'Último registro', value: (item) => item.last_seen_at },
  { header: 'Janelas', value: (item) => item.total_windows },
  { header: 'Anomalias', value: (item) => item.total_anomalies },
  { header: 'Apoio da IA', value: (item) => item.ai_support_count },
]

function formatScore(value?: number | null): string {
  return typeof value === 'number' ? value.toFixed(4) : '-'
}

function distributionLabel(label: string, kind: DistributionKind): string {
  if (kind === 'attack') {
    return formatAttackType(label)
  }
  if (kind === 'risk') {
    return formatRiskLevel(label)
  }
  return label
}

function firstDistributionLabel(distribution?: Record<string, number>): string {
  const [first] = Object.entries(distribution ?? {})
  return first ? `${formatAttackType(first[0])} (${first[1]})` : '-'
}

function openWindow(id: number): void {
  router.push(`/windows/${id}`)
}

async function loadSummary(): Promise<void> {
  loading.summary = true
  errors.summary = ''
  try {
    summary.value = await getHistorySummary()
  } catch {
    errors.summary = 'Não foi possível carregar /history/summary.'
  } finally {
    loading.summary = false
  }
}

async function loadWindows(): Promise<void> {
  loading.windows = true
  errors.windows = ''
  try {
    const response = await getHistoryWindows(500, 0, currentFilters())
    windows.value = response.windows
    windowsMeta.value = response.meta
  } catch {
    errors.windows = 'Não foi possível carregar /history/windows.'
  } finally {
    loading.windows = false
  }
}

async function loadAlerts(): Promise<void> {
  loading.alerts = true
  errors.alerts = ''
  try {
    const response = await getHistoryAlerts(500, 0, currentFilters())
    alerts.value = response.alerts
    alertsMeta.value = response.meta
  } catch {
    errors.alerts = 'Não foi possível carregar /history/alerts.'
  } finally {
    loading.alerts = false
  }
}

async function loadExecutions(): Promise<void> {
  loading.executions = true
  errors.executions = ''
  try {
    const response = await getHistoryExecutions(500, 0)
    executions.value = response.executions
    executionsMeta.value = response.meta
  } catch {
    errors.executions = 'Não foi possível carregar /history/executions.'
  } finally {
    loading.executions = false
  }
}

async function loadAnalyses(): Promise<void> {
  loading.analyses = true
  errors.analyses = ''
  try {
    const response = await getAnalyses(500, 0)
    analyses.value = response.analyses
    analysesMeta.value = response.meta
  } catch {
    errors.analyses = 'Não foi possível carregar /analyses.'
  } finally {
    loading.analyses = false
  }
}

async function reloadFiltered(): Promise<void> {
  await Promise.all([loadSummary(), loadWindows(), loadAlerts(), loadExecutions()])
}

async function clearFilters(): Promise<void> {
  filters.final_label = ''
  filters.attack_type = ''
  filters.risk_level = ''
  filters.ai_support = ''
  filters.date_from = ''
  filters.date_to = ''
  filters.src_ip = ''
  filters.dst_ip = ''
  filters.dst_port = ''
  filters.protocol = ''
  filters.action = ''
  filters.only_anomalies = false
  await reloadFiltered()
}

function showExportFeedback(success: boolean): void {
  exportFeedback.value = success
    ? 'Relatório exportado com sucesso.'
    : 'Não há dados para exportar.'
}

async function exportFilteredHistoryCsv(): Promise<void> {
  const response = await getHistoryWindows(500, 0, currentFilters())
  const rows = filterBySearch(
    response.windows.filter(matchesLocalWindowFilters),
    trimmedSearch.value,
    windowSearchText,
  )
  showExportFeedback(
    exportCsv(
      `sinalyx_relatorio_janelas_filtradas_${dateStamp()}.csv`,
      rows,
      windowCsvColumns,
    ),
  )
}

async function exportAllHistoryCsv(): Promise<void> {
  const response = await getHistoryWindows(500, 0)
  showExportFeedback(
    exportCsv(
      `sinalyx_relatorio_janelas_${dateStamp()}.csv`,
      response.windows,
      windowCsvColumns,
    ),
  )
}

async function exportAlertsCsv(): Promise<void> {
  const response = await getHistoryAlerts(500, 0, currentFilters())
  const rows = filterBySearch(
    response.alerts.filter(matchesLocalWindowFilters),
    trimmedSearch.value,
    windowSearchText,
  )
  showExportFeedback(
    exportCsv(
      `sinalyx_relatorio_alertas_${dateStamp()}.csv`,
      rows,
      windowCsvColumns,
    ),
  )
}

async function exportExecutionsCsv(): Promise<void> {
  const response = await getHistoryExecutions(500, 0)
  const rows = filterBySearch(
    response.executions,
    trimmedSearch.value,
    executionSearchText,
  )
  showExportFeedback(
    exportCsv(
      `sinalyx_relatorio_execucoes_${dateStamp()}.csv`,
      rows,
      executionCsvColumns,
    ),
  )
}

async function exportSummaryJson(): Promise<void> {
  const payload = summary.value ?? (await getHistorySummary())
  showExportFeedback(
    exportJson(`sinalyx_relatorio_resumo_${dateStamp()}.json`, payload),
  )
}

const SummaryBox = defineComponent({
  props: {
    label: {
      type: String,
      required: true,
    },
    value: {
      type: Number,
      default: 0,
    },
  },
  setup(props) {
    return () =>
      h('div', { class: 'panel p-4' }, [
        h('p', { class: 'text-xs font-medium text-slate-500' }, props.label),
        h('p', { class: 'mt-2 text-2xl font-semibold text-white' }, String(props.value ?? 0)),
      ])
  },
})

const DistributionBox = defineComponent({
  props: {
    title: {
      type: String,
      required: true,
    },
    items: {
      type: Object,
      default: () => ({}),
    },
    kind: {
      type: String,
      default: 'plain',
    },
  },
  setup(props) {
    return () =>
      h('div', { class: 'panel p-4' }, [
        h('h2', { class: 'text-sm font-semibold text-white' }, props.title),
        h(
          'div',
          { class: 'mt-4 space-y-2' },
          Object.entries(props.items as Record<string, number>).map(([label, value]) =>
            h('div', { class: 'flex items-center justify-between gap-3 text-sm' }, [
              h('span', { class: 'text-slate-300' }, distributionLabel(label, props.kind as DistributionKind)),
              h('span', { class: 'font-medium text-white' }, String(value)),
            ]),
          ),
        ),
      ])
  },
})

onMounted(async () => {
  await Promise.all([
    loadSummary(),
    loadWindows(),
    loadAlerts(),
    loadExecutions(),
    loadAnalyses(),
  ])
})
</script>
