<template>
  <section class="space-y-5">
    <div class="flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
      <div>
        <p class="text-xs font-medium text-slate-500">Janelas anômalas</p>
        <h1 class="text-xl font-semibold text-white">Alertas</h1>
      </div>
      <p v-if="meta" class="text-sm text-slate-500">{{ meta.returned }} de {{ meta.total }}</p>
    </div>

    <LoadingState v-if="loading" />
    <ErrorState v-else-if="error" :message="error" />

    <div v-else class="panel overflow-hidden">
      <div class="overflow-x-auto">
        <table class="min-w-full divide-y divide-slate-800 text-sm">
          <thead class="bg-surface-850 text-left text-xs uppercase text-slate-500">
            <tr>
              <th class="px-4 py-3 font-medium">Início da janela</th>
              <th class="px-4 py-3 font-medium">Tipo de ataque</th>
              <th class="px-4 py-3 font-medium">Risco</th>
              <th class="px-4 py-3 font-medium">Fonte da decisão</th>
              <th class="px-4 py-3 font-medium">Score do Ensemble</th>
              <th class="px-4 py-3 font-medium">Apoio da IA</th>
              <th class="px-4 py-3 font-medium">Detalhe</th>
            </tr>
          </thead>
          <tbody v-if="filteredAlerts.length > 0" class="divide-y divide-slate-800">
            <tr
              v-for="alert in filteredAlerts"
              :key="alert.id"
              class="cursor-pointer transition hover:bg-surface-850/70"
              @click="openAlert(alert.id)"
            >
              <td class="px-4 py-3">
                <span class="font-medium text-sky-300">{{ formatDateTime(alert.window_start) }}</span>
              </td>
              <td class="px-4 py-3 text-slate-300">{{ formatAttackType(alert.attack_type) }}</td>
              <td class="px-4 py-3"><StatusBadge :value="alert.risk_level" /></td>
              <td class="px-4 py-3 text-slate-400">{{ formatDecisionSource(alert.decision_source) }}</td>
              <td class="px-4 py-3 text-slate-300">{{ formatScore(alert.scores?.ensemble) }}</td>
              <td class="px-4 py-3"><StatusBadge :value="alert.ai_support" /></td>
              <td class="px-4 py-3">
                <button class="btn btn-secondary" type="button" @click.stop="openAlert(alert.id)">
                  Abrir
                </button>
              </td>
            </tr>
          </tbody>
          <tbody v-else>
            <tr>
              <td class="px-4 py-4 text-sm text-slate-400" colspan="7">
                Nenhum resultado encontrado.
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </section>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'

import ErrorState from '@/components/ui/ErrorState.vue'
import LoadingState from '@/components/ui/LoadingState.vue'
import StatusBadge from '@/components/ui/StatusBadge.vue'
import { useGlobalSearch } from '@/composables/useGlobalSearch'
import { getRecentAlerts } from '@/services/api'
import type { AlertItem, PaginationMeta } from '@/types/api'
import { filterBySearch, windowSearchText } from '@/utils/search'
import {
  formatAttackType,
  formatDateTime,
  formatDecisionSource,
} from '@/utils/formatters'

const alerts = ref<AlertItem[]>([])
const meta = ref<PaginationMeta | null>(null)
const loading = ref(true)
const error = ref('')
const router = useRouter()
const { trimmedSearch } = useGlobalSearch()
const filteredAlerts = computed(() =>
  filterBySearch(alerts.value, trimmedSearch.value, windowSearchText),
)

function formatScore(value?: number | null): string {
  return typeof value === 'number' ? value.toFixed(4) : '-'
}

function openAlert(id: number): void {
  router.push(`/windows/${id}`)
}

onMounted(async () => {
  try {
    const response = await getRecentAlerts(20, 0)
    alerts.value = response.alerts
    meta.value = response.meta
  } catch {
    error.value = 'Não foi possível carregar /alerts/recent.'
  } finally {
    loading.value = false
  }
})
</script>
