<template>
  <section class="space-y-5">
    <div class="flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
      <div>
        <p class="muted-label">Visão geral</p>
        <h1 class="text-xl font-semibold text-white">Resumo</h1>
      </div>
      <p class="text-sm text-slate-500">API: {{ baseUrl }}</p>
    </div>

    <LoadingState v-if="loading" />
    <ErrorState v-else-if="error" :message="error" />

    <template v-else-if="summary">
      <div class="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <StatCard
          label="Janelas"
          :value="summary.total_windows"
          :icon="Activity"
          icon-class="border-sky-400/30 bg-sky-400/10 text-sky-200"
        />
        <StatCard
          label="Normal"
          :value="summary.total_normal"
          :icon="ShieldCheck"
          icon-class="border-emerald-400/30 bg-emerald-400/10 text-emerald-200"
        />
        <StatCard
          label="Anomalias"
          :value="summary.total_anomalies"
          :icon="Bell"
          icon-class="border-red-400/30 bg-red-400/10 text-red-200"
        />
        <StatCard
          label="Apoio da IA"
          :value="summary.ai_support_count"
          :icon="BrainCircuit"
          icon-class="border-cyan-400/30 bg-cyan-400/10 text-cyan-200"
        />
      </div>

      <div class="grid gap-4 xl:grid-cols-3">
        <HorizontalBarChart
          title="Distribuição por tipo de ataque"
          :items="attackChartItems"
        />
        <HorizontalBarChart
          title="Distribuição por risco"
          :items="riskChartItems"
        />
        <RecentWindowsChart
          title="Atividade recente"
          :items="timelineChartItems"
        />
      </div>

      <ErrorState v-if="chartError" :message="chartError" />

      <div class="grid gap-4">
        <div class="panel overflow-hidden">
          <div class="border-b border-slate-800 px-4 py-3">
            <h2 class="text-sm font-semibold text-white">Últimas janelas</h2>
          </div>
          <div class="overflow-x-auto">
            <table class="min-w-full divide-y divide-slate-800 text-sm">
              <thead class="bg-surface-850 text-left text-xs uppercase text-slate-500">
                <tr>
                  <th class="px-4 py-3 font-medium">Início da janela</th>
                  <th class="px-4 py-3 font-medium">Classificação</th>
                  <th class="px-4 py-3 font-medium">Tipo de ataque</th>
                  <th class="px-4 py-3 font-medium">Risco</th>
                  <th class="px-4 py-3 font-medium">Apoio da IA</th>
                </tr>
              </thead>
              <tbody v-if="recentWindows.length > 0" class="divide-y divide-slate-800">
                <tr
                  v-for="window in recentWindows"
                  :key="window.id"
                  class="transition hover:bg-surface-850/70"
                >
                  <td class="px-4 py-3">
                    <RouterLink
                      class="font-medium text-sky-300 hover:text-sky-200"
                      :to="`/windows/${window.id}`"
                    >
                      {{ formatDateTime(window.window_start) }}
                    </RouterLink>
                  </td>
                  <td class="px-4 py-3"><StatusBadge :value="window.final_label" /></td>
                  <td class="px-4 py-3 text-slate-300">{{ formatAttackType(window.attack_type) }}</td>
                  <td class="px-4 py-3"><StatusBadge :value="window.risk_level" /></td>
                  <td class="px-4 py-3"><StatusBadge :value="window.ai_support" /></td>
                </tr>
              </tbody>
              <tbody v-else>
                <tr>
                  <td class="px-4 py-4 text-sm text-slate-400" colspan="5">
                    Nenhum resultado encontrado.
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </template>
  </section>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { RouterLink } from 'vue-router'
import { Activity, Bell, BrainCircuit, ShieldCheck } from 'lucide-vue-next'

import HorizontalBarChart from '@/components/charts/HorizontalBarChart.vue'
import RecentWindowsChart from '@/components/charts/RecentWindowsChart.vue'
import ErrorState from '@/components/ui/ErrorState.vue'
import LoadingState from '@/components/ui/LoadingState.vue'
import StatCard from '@/components/ui/StatCard.vue'
import StatusBadge from '@/components/ui/StatusBadge.vue'
import { useGlobalSearch } from '@/composables/useGlobalSearch'
import {
  apiBaseUrl,
  getDashboardSummary,
  getHistorySummary,
  getHistoryWindows,
} from '@/services/api'
import type { DashboardSummary, HistorySummary, WindowItem } from '@/types/api'
import { filterBySearch, windowSearchText } from '@/utils/search'
import {
  formatAttackType,
  formatDateTime,
  formatRiskLevel,
} from '@/utils/formatters'

const summary = ref<DashboardSummary | null>(null)
const historySummary = ref<HistorySummary | null>(null)
const historyWindows = ref<WindowItem[]>([])
const loading = ref(true)
const error = ref('')
const chartError = ref('')
const baseUrl = apiBaseUrl()
const { trimmedSearch } = useGlobalSearch()

type ChartItem = {
  label: string
  value: number
  color: string
}

type RecentWindowChartItem = {
  id: string | number
  label: string
  score: number
  isAnomaly: boolean
  tooltip: string
}

const chartColors = [
  'bg-emerald-400',
  'bg-sky-400',
  'bg-red-400',
  'bg-amber-400',
  'bg-cyan-400',
  'bg-violet-400',
]

const attackChartItems = computed<ChartItem[]>(() =>
  buildChartItems(
    historySummary.value?.live?.attack_type_distribution
      ?? summary.value?.attack_type_distribution
      ?? {},
    formatAttackType,
  ),
)
const riskChartItems = computed<ChartItem[]>(() =>
  buildChartItems(
    historySummary.value?.live?.risk_level_distribution
      ?? summary.value?.risk_level_distribution
      ?? {},
    formatRiskLevel,
  ),
)
const recentWindows = computed(() =>
  filterBySearch(
    historyWindows.value.length > 0
      ? historyWindows.value
      : summary.value?.recent_windows ?? [],
    trimmedSearch.value,
    windowSearchText,
  ),
)
const timelineChartItems = computed<RecentWindowChartItem[]>(() =>
  (historyWindows.value.length > 0 ? historyWindows.value : recentWindows.value)
    .slice()
    .reverse()
    .map((window) => {
      const score = Number(window.scores?.ensemble ?? window.ensemble_score ?? 0)
      return {
        id: window.id,
        label: formatDateTime(window.window_start).slice(11, 16) || String(window.id),
        score: window.final_label === 'anomaly' ? Math.max(score, 0.75) : Math.max(score, 0.18),
        isAnomaly: window.final_label === 'anomaly',
        tooltip: `${formatAttackType(window.attack_type)} - ${formatRiskLevel(window.risk_level)}`,
      }
    }),
)

function buildChartItems(
  distribution: Record<string, number>,
  formatter: (value?: string | null) => string,
): ChartItem[] {
  return Object.entries(distribution).map(([label, value], index) => ({
    label: formatter(label),
    value: Number(value || 0),
    color: chartColors[index % chartColors.length],
  }))
}

onMounted(async () => {
  try {
    summary.value = await getDashboardSummary()
  } catch {
    error.value = 'Não foi possível carregar /dashboard/summary.'
  } finally {
    loading.value = false
  }

  const [historySummaryResult, historyWindowsResult] = await Promise.allSettled([
    getHistorySummary(),
    getHistoryWindows(12, 0),
  ])
  if (historySummaryResult.status === 'fulfilled') {
    historySummary.value = historySummaryResult.value
  }
  if (historyWindowsResult.status === 'fulfilled') {
    historyWindows.value = historyWindowsResult.value.windows
  }
  if (
    historySummaryResult.status === 'rejected'
    || historyWindowsResult.status === 'rejected'
  ) {
    chartError.value = 'Alguns gráficos não puderam carregar os dados históricos agora.'
  }
})
</script>
