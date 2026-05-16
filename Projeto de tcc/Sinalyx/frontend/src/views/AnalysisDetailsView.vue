<template>
  <section class="space-y-5">
    <div class="flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
      <div>
        <p class="muted-label">Análise</p>
        <h1 class="text-wrap-safe text-xl font-semibold text-white">{{ id }}</h1>
      </div>
      <RouterLink class="btn btn-secondary" to="/history">
        Voltar
      </RouterLink>
    </div>

    <LoadingState v-if="loading" />
    <ErrorState v-else-if="error" :message="error" />

    <template v-else-if="details">
      <div class="grid gap-4 md:grid-cols-3">
        <StatCard
          label="Janelas"
          :value="details.total_windows"
          :icon="TableProperties"
          icon-class="border-sky-400/30 bg-sky-400/10 text-sky-200"
        />
        <StatCard
          label="Tipo predominante"
          :value="formatAttackType(details.classification?.predominant_attack_type)"
          :icon="Crosshair"
          icon-class="border-red-400/30 bg-red-400/10 text-red-200"
        />
        <StatCard
          label="Risco"
          :value="formatRiskLevel(details.classification?.predominant_risk_level)"
          :icon="ShieldAlert"
          icon-class="border-amber-400/30 bg-amber-400/10 text-amber-200"
        />
      </div>

      <div class="panel p-4">
        <div class="grid gap-3 text-sm md:grid-cols-2">
          <div>
            <p class="muted-label">Arquivo</p>
            <p class="mt-1 text-slate-200">{{ details.filename }}</p>
          </div>
          <div>
            <p class="muted-label">Criado em</p>
            <p class="mt-1 text-slate-200">{{ formatDate(details.created_at) }}</p>
          </div>
        </div>
      </div>

      <div class="panel overflow-hidden">
        <div class="border-b border-slate-800 px-4 py-3">
          <h2 class="text-sm font-semibold text-white">Resultados</h2>
        </div>
        <div class="overflow-x-auto">
          <table class="min-w-full divide-y divide-slate-800 text-sm">
            <thead class="bg-surface-850 text-left text-xs uppercase text-slate-500">
              <tr>
                <th class="px-4 py-3 font-medium">Janela</th>
                <th class="px-4 py-3 font-medium">Classificação</th>
                <th class="px-4 py-3 font-medium">Tipo</th>
                <th class="px-4 py-3 font-medium">Risco</th>
                <th class="px-4 py-3 font-medium">Fonte da decisão</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-slate-800">
              <tr v-for="(result, index) in results" :key="`${result.window_id ?? index}`">
                <td class="px-4 py-3 text-slate-300">{{ result.window_id ?? '-' }}</td>
                <td class="px-4 py-3"><StatusBadge :value="String(result.final_label ?? '-')" /></td>
                <td class="px-4 py-3 text-slate-300">{{ formatAttackType(result.attack_type) }}</td>
                <td class="px-4 py-3"><StatusBadge :value="String(result.risk_level ?? '-')" /></td>
                <td class="px-4 py-3 text-slate-400">{{ formatDecisionSource(result.decision_source) }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </template>
  </section>
</template>

<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { RouterLink } from 'vue-router'
import { Crosshair, ShieldAlert, TableProperties } from 'lucide-vue-next'

import ErrorState from '@/components/ui/ErrorState.vue'
import LoadingState from '@/components/ui/LoadingState.vue'
import StatCard from '@/components/ui/StatCard.vue'
import StatusBadge from '@/components/ui/StatusBadge.vue'
import { getAnalysisDetails, getAnalysisResults } from '@/services/api'
import type { AnalysisDetails } from '@/types/api'
import {
  formatAttackType,
  formatDateTime,
  formatDecisionSource,
  formatRiskLevel,
} from '@/utils/formatters'

type AnalysisResultRow = {
  window_id?: string
  final_label?: string
  attack_type?: string
  risk_level?: string
  decision_source?: string
} & Record<string, unknown>

const props = defineProps<{
  id: string
}>()

const details = ref<AnalysisDetails | null>(null)
const results = ref<AnalysisResultRow[]>([])
const loading = ref(true)
const error = ref('')
const id = props.id

function formatDate(value: string): string {
  return formatDateTime(value)
}

onMounted(async () => {
  try {
    const [detailsResponse, resultsResponse] = await Promise.all([
      getAnalysisDetails(id),
      getAnalysisResults(id, 50, 0),
    ])
    details.value = detailsResponse
    results.value = (resultsResponse.data?.results ?? resultsResponse.results ?? []) as AnalysisResultRow[]
  } catch {
    error.value = 'Não foi possível carregar os detalhes da análise.'
  } finally {
    loading.value = false
  }
})
</script>
