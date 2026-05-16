<template>
  <section class="space-y-5">
    <div class="flex flex-col gap-2 lg:flex-row lg:items-end lg:justify-between">
      <div>
        <p class="text-xs font-medium text-slate-500">Apresentação</p>
        <h1 class="text-2xl font-semibold text-white">Modo Demo do Sinalyx</h1>
        <p class="mt-1 max-w-3xl text-sm text-slate-400">
          Visão executiva da análise de logs de firewall com IA, usando os dados reais persistidos no PostgreSQL.
        </p>
      </div>
      <StatusBadge :value="systemOk ? 'success' : 'unknown'" />
    </div>

    <LoadingState v-if="loading" />
    <ErrorState v-else-if="mainError" :message="mainError" />

    <template v-else>
      <div class="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <BigMetric label="Janelas analisadas" :value="summary?.live?.total_windows ?? 0" />
        <BigMetric label="Anomalias" :value="summary?.live?.total_alerts ?? 0" tone="danger" />
        <BigMetric label="Execuções" :value="summary?.live?.total_executions ?? 0" tone="info" />
        <BigMetric label="Apoio da IA" :value="summary?.live?.ai_support_count ?? 0" tone="ai" />
      </div>

      <section class="panel p-5">
        <div class="grid gap-4 lg:grid-cols-[1fr_1.4fr]">
          <div>
            <p class="text-xs font-medium text-slate-500">Último ataque detectado</p>
            <h2 class="mt-2 text-2xl font-semibold text-white">
              {{ latestAlertTitle }}
            </h2>
            <p class="mt-2 text-sm text-slate-400">
              {{ latestAlertSubtitle }}
            </p>
          </div>
          <div class="grid gap-3 sm:grid-cols-3">
            <InfoCard label="Risco" :value="formatRiskLevel(latestAlert?.risk_level)" />
            <InfoCard label="Fonte da decisão" :value="formatDecisionSource(latestAlert?.decision_source)" />
            <InfoCard label="Confiança" :value="formatScore(latestAlert?.confidence)" />
          </div>
        </div>
      </section>

      <div class="grid gap-4 xl:grid-cols-3">
        <HorizontalBarChart
          title="Ataques por tipo"
          :items="attackChartItems"
        />
        <HorizontalBarChart
          title="Risco por nível"
          :items="riskChartItems"
        />
        <RecentWindowsChart
          title="Janelas recentes"
          :items="timelineItems"
        />
      </div>

      <div class="grid gap-4 xl:grid-cols-[1.2fr_0.8fr]">
        <section class="panel overflow-hidden">
          <div class="border-b border-slate-800 px-4 py-3">
            <h2 class="text-sm font-semibold text-white">Últimas anomalias</h2>
          </div>
          <div class="overflow-x-auto">
            <table class="min-w-full divide-y divide-slate-800 text-sm">
              <thead class="bg-surface-850 text-left text-xs uppercase text-slate-500">
                <tr>
                  <th class="px-4 py-3 font-medium">Início</th>
                  <th class="px-4 py-3 font-medium">Tipo</th>
                  <th class="px-4 py-3 font-medium">Risco</th>
                  <th class="px-4 py-3 font-medium">Apoio da IA</th>
                </tr>
              </thead>
              <tbody class="divide-y divide-slate-800">
                <tr v-for="alert in alerts" :key="alert.id">
                  <td class="px-4 py-3 text-sky-300">{{ formatDateTime(alert.window_start) }}</td>
                  <td class="px-4 py-3 text-slate-300">{{ formatAttackType(alert.attack_type) }}</td>
                  <td class="px-4 py-3"><StatusBadge :value="alert.risk_level" /></td>
                  <td class="px-4 py-3"><StatusBadge :value="alert.ai_support" /></td>
                </tr>
              </tbody>
            </table>
          </div>
        </section>

        <section class="panel p-4">
          <h2 class="text-sm font-semibold text-white">Status resumido</h2>
          <div class="mt-4 space-y-3 text-sm">
            <InfoLine label="API" :value="systemStatus.health.ok ? 'Disponível' : 'Indisponível'" />
            <InfoLine label="Banco" :value="systemStatus.health.data?.database.available ? 'Disponível' : 'Indisponível'" />
            <InfoLine label="Parser" :value="systemStatus.parser.ok ? 'Disponível' : 'Indisponível'" />
            <InfoLine label="Coletor" :value="systemStatus.collector.ok ? 'Disponível' : 'Indisponível'" />
          </div>
        </section>
      </div>

      <ErrorState v-if="secondaryError" :message="secondaryError" />
    </template>
  </section>
</template>

<script setup lang="ts">
import { computed, defineComponent, h, onMounted, ref } from 'vue'

import HorizontalBarChart from '@/components/charts/HorizontalBarChart.vue'
import RecentWindowsChart from '@/components/charts/RecentWindowsChart.vue'
import ErrorState from '@/components/ui/ErrorState.vue'
import LoadingState from '@/components/ui/LoadingState.vue'
import StatusBadge from '@/components/ui/StatusBadge.vue'
import {
  getHistoryAlerts,
  getHistorySummary,
  getHistoryWindows,
  getSystemStatus,
} from '@/services/api'
import type { AlertItem, HistorySummary, SystemStatus, WindowItem } from '@/types/api'
import {
  formatAttackType,
  formatDateTime,
  formatDecisionSource,
  formatRiskLevel,
} from '@/utils/formatters'

type ChartItem = { label: string; value: number; color: string }
type RecentItem = {
  id: string | number
  label: string
  score: number
  isAnomaly: boolean
  tooltip: string
}

const loading = ref(true)
const mainError = ref('')
const secondaryError = ref('')
const summary = ref<HistorySummary | null>(null)
const windows = ref<WindowItem[]>([])
const alerts = ref<AlertItem[]>([])
const systemStatus = ref<SystemStatus>({
  health: { ok: false },
  parser: { ok: false },
  collector: { ok: false },
})
const colors = ['bg-emerald-400', 'bg-sky-400', 'bg-red-400', 'bg-amber-400', 'bg-cyan-400']

const latestAlert = computed(() => alerts.value[0] ?? summary.value?.live?.latest_alert ?? null)
const latestAlertTitle = computed(() =>
  latestAlert.value
    ? formatAttackType(latestAlert.value.attack_type)
    : 'Nenhuma anomalia recente',
)
const latestAlertSubtitle = computed(() =>
  latestAlert.value
    ? `${formatDateTime(latestAlert.value.window_start)} • ${latestAlert.value.src_ip ?? 'origem não informada'}`
    : 'O ambiente atual não possui alertas recentes para destacar.',
)
const systemOk = computed(() =>
  systemStatus.value.health.ok
  && systemStatus.value.health.data?.database.available === true,
)
const attackChartItems = computed<ChartItem[]>(() =>
  chartItems(summary.value?.live?.attack_type_distribution ?? {}, formatAttackType),
)
const riskChartItems = computed<ChartItem[]>(() =>
  chartItems(summary.value?.live?.risk_level_distribution ?? {}, formatRiskLevel),
)
const timelineItems = computed<RecentItem[]>(() =>
  windows.value.slice().reverse().map((window) => ({
    id: window.id,
    label: formatDateTime(window.window_start).slice(11, 16) || String(window.id),
    score: window.final_label === 'anomaly' ? 0.85 : 0.25,
    isAnomaly: window.final_label === 'anomaly',
    tooltip: `${formatAttackType(window.attack_type)} - ${formatRiskLevel(window.risk_level)}`,
  })),
)

function chartItems(
  distribution: Record<string, number>,
  formatter: (value?: string | null) => string,
): ChartItem[] {
  return Object.entries(distribution).map(([label, value], index) => ({
    label: formatter(label),
    value,
    color: colors[index % colors.length],
  }))
}

function formatScore(value?: number | null): string {
  return typeof value === 'number' ? `${Math.round(value * 100)}%` : '-'
}

const BigMetric = defineComponent({
  props: {
    label: { type: String, required: true },
    value: { type: Number, required: true },
    tone: { type: String, default: 'default' },
  },
  setup(props) {
    const toneClass = computed(() => ({
      danger: 'text-red-200',
      info: 'text-sky-200',
      ai: 'text-cyan-200',
      default: 'text-white',
    }[props.tone] ?? 'text-white'))
    return () => h('article', { class: 'panel p-5' }, [
      h('p', { class: 'text-sm text-slate-500' }, props.label),
      h('p', { class: `mt-3 text-4xl font-semibold ${toneClass.value}` }, String(props.value)),
    ])
  },
})

const InfoCard = defineComponent({
  props: {
    label: { type: String, required: true },
    value: { type: String, required: true },
  },
  setup(props) {
    return () => h('div', { class: 'rounded-md border border-slate-800 bg-surface-850 p-3' }, [
      h('p', { class: 'text-xs font-medium text-slate-500' }, props.label),
      h('p', { class: 'mt-2 text-sm font-semibold text-white' }, props.value),
    ])
  },
})

const InfoLine = defineComponent({
  props: {
    label: { type: String, required: true },
    value: { type: String, required: true },
  },
  setup(props) {
    return () => h('div', { class: 'flex items-center justify-between gap-3' }, [
      h('span', { class: 'text-slate-400' }, props.label),
      h('span', { class: 'font-medium text-white' }, props.value),
    ])
  },
})

onMounted(async () => {
  try {
    const [summaryResponse, windowsResponse, alertsResponse, systemResponse] =
      await Promise.allSettled([
        getHistorySummary(),
        getHistoryWindows(12, 0),
        getHistoryAlerts(8, 0),
        getSystemStatus(),
      ])

    if (summaryResponse.status === 'fulfilled') {
      summary.value = summaryResponse.value
    } else {
      mainError.value = 'Não foi possível carregar o resumo histórico.'
    }
    if (windowsResponse.status === 'fulfilled') {
      windows.value = windowsResponse.value.windows
    }
    if (alertsResponse.status === 'fulfilled') {
      alerts.value = alertsResponse.value.alerts
    }
    if (systemResponse.status === 'fulfilled') {
      systemStatus.value = systemResponse.value
    }
    if ([windowsResponse, alertsResponse, systemResponse].some((item) => item.status === 'rejected')) {
      secondaryError.value = 'Alguns blocos de demonstração não puderam carregar agora.'
    }
  } finally {
    loading.value = false
  }
})
</script>
