<template>
  <section class="space-y-5">
    <div class="flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
      <div>
        <p class="muted-label">Janela</p>
        <h1 class="text-xl font-semibold text-white">Detalhes da janela</h1>
      </div>
      <RouterLink class="btn btn-secondary" to="/alerts">
        Voltar
      </RouterLink>
    </div>

    <LoadingState v-if="loading" />
    <ErrorState v-else-if="error" :message="error" />

    <template v-else-if="windowItem">
      <div class="grid gap-3 md:grid-cols-2 xl:grid-cols-5">
        <div class="panel p-4">
          <p class="text-xs font-medium text-slate-500">Origem</p>
          <p class="mt-2 text-wrap-safe text-sm font-semibold text-white">{{ headerSource }}</p>
        </div>
        <div class="panel p-4">
          <p class="text-xs font-medium text-slate-500">Início da janela</p>
          <p class="mt-2 text-sm font-semibold text-white">{{ formatDateTime(windowItem.window_start) }}</p>
        </div>
        <div class="panel p-4">
          <p class="text-xs font-medium text-slate-500">Duração</p>
          <p class="mt-2 text-sm font-semibold text-white">{{ durationLabel }}</p>
        </div>
        <div class="panel p-4">
          <p class="text-xs font-medium text-slate-500">ID da janela</p>
          <p class="mt-2 text-wrap-safe font-mono text-xs text-slate-300">{{ windowItem.window_id ?? `ID ${props.id}` }}</p>
        </div>
        <div class="panel p-4">
          <p class="text-xs font-medium text-slate-500">Execução</p>
          <p class="mt-2 text-wrap-safe font-mono text-xs text-slate-300">{{ windowItem.execution_id ?? '-' }}</p>
        </div>
      </div>

      <div class="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <div class="panel p-4">
          <p class="text-xs font-medium text-slate-500">Classificação final</p>
          <p class="mt-2 text-lg font-semibold text-white">{{ formatFinalLabel(windowItem.final_label) }}</p>
        </div>
        <div class="panel p-4">
          <p class="text-xs font-medium text-slate-500">Tipo de ataque</p>
          <p class="mt-2 text-lg font-semibold text-white">{{ formatAttackType(windowItem.attack_type) }}</p>
        </div>
        <div class="panel p-4">
          <p class="text-xs font-medium text-slate-500">Risco</p>
          <div class="mt-2">
            <StatusBadge :value="windowItem.risk_level" />
          </div>
        </div>
        <div class="panel p-4">
          <p class="text-xs font-medium text-slate-500">Apoio da IA</p>
          <div class="mt-3 space-y-2 text-sm">
            <div class="flex items-center justify-between gap-3">
              <span class="text-slate-400">Apoio da IA</span>
              <StatusBadge :value="windowItem.ai_support" />
            </div>
            <div class="flex items-center justify-between gap-3">
              <span class="text-slate-400">Apoio da IA conservador</span>
              <StatusBadge :value="windowItem.ai_support_conservative" />
            </div>
          </div>
        </div>
      </div>

      <div class="grid gap-4 xl:grid-cols-[1.1fr_0.9fr]">
        <div class="panel p-4">
          <div class="flex items-start justify-between gap-3">
            <div>
              <p class="text-xs font-medium text-slate-500">Resultado interpretável</p>
              <h2 class="mt-1 text-sm font-semibold text-white">Decisão</h2>
            </div>
            <StatusBadge :value="windowItem.final_label" />
          </div>
          <div class="mt-4 grid gap-3 text-sm md:grid-cols-2">
            <InfoItem label="Fonte da decisão" :value="formatDecisionSource(windowItem.decision_source)" />
            <InfoItem label="Confiança" :value="formatScore(windowItem.confidence)" />
            <InfoItem label="Início da janela" :value="formatDateTime(windowItem.window_start)" />
            <InfoItem label="Fim da janela" :value="formatDateTime(windowItem.window_end)" />
            <InfoItem label="ID de execução" :value="windowItem.execution_id ?? undefined" />
            <InfoItem label="ID da janela" :value="windowItem.window_id ?? undefined" />
            <InfoItem label="Origem" :value="windowItem.src_ip ?? undefined" />
            <InfoItem label="Destino" :value="windowItem.dst_ip ?? undefined" />
            <InfoItem label="Porta" :value="windowItem.dst_port ?? undefined" />
            <InfoItem label="Protocolo" :value="windowItem.protocol ?? undefined" />
            <InfoItem label="Ação" :value="windowItem.action ?? undefined" />
          </div>
          <div class="mt-4">
            <p class="text-xs font-medium text-slate-500">Motivo da decisão</p>
            <p class="mt-2 rounded-md border border-slate-800 bg-surface-850 p-3 text-sm text-slate-300">
              {{ decisionText }}
            </p>
          </div>
        </div>

        <div class="panel p-4">
          <p class="text-xs font-medium text-slate-500">Sinais dos modelos</p>
          <h2 class="mt-1 text-sm font-semibold text-white">Scores</h2>
          <p class="mt-2 text-sm leading-6 text-slate-400">
            Scores são sinais numéricos dos modelos. Valores maiores indicam mais evidência de anomalia; o Ensemble combina os sinais para apoiar a decisão final.
          </p>
          <div class="mt-4 space-y-3">
            <ScoreRow label="Ensemble" :value="windowItem.scores?.ensemble ?? windowItem.ensemble_score ?? undefined" />
            <ScoreRow label="Autoencoder" :value="windowItem.scores?.autoencoder ?? windowItem.autoencoder_score ?? undefined" />
            <ScoreRow label="Isolation Forest" :value="windowItem.scores?.isolation ?? windowItem.isolation_score ?? undefined" />
          </div>
        </div>
      </div>

      <section class="panel p-5">
        <div class="flex flex-col gap-2 lg:flex-row lg:items-start lg:justify-between">
          <div>
            <p class="text-xs font-medium text-slate-500">Explicabilidade</p>
            <h2 class="mt-1 text-base font-semibold text-white">Por que o sistema decidiu isso?</h2>
          </div>
          <StatusBadge :value="windowItem.risk_level" />
        </div>

        <div class="mt-4 grid gap-3 md:grid-cols-2 xl:grid-cols-4">
          <InfoItem label="Tráfego" :value="formatFinalLabel(windowItem.final_label)" />
          <InfoItem label="Risco" :value="formatRiskLevel(windowItem.risk_level)" />
          <InfoItem label="Fonte principal" :value="formatDecisionSource(windowItem.decision_source)" />
          <InfoItem label="Confiança" :value="formatScore(windowItem.confidence)" />
        </div>

        <div class="mt-4 grid gap-3 md:grid-cols-2 xl:grid-cols-5">
          <ModuleCard
            v-for="module in moduleCards"
            :key="module.title"
            :title="module.title"
            :role="module.role"
            :value="module.value"
            :status="module.status"
          />
        </div>

        <div class="mt-4 grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          <InfoItem label="Heurística que disparou" :value="heuristicReason" />
          <InfoItem label="Motivo da decisão" :value="decisionText" />
          <InfoItem label="Apoio da IA" :value="aiSupportReason" />
        </div>

        <div class="mt-4">
          <p class="text-xs font-medium text-slate-500">Features mais relevantes</p>
          <div class="mt-3 grid gap-2 md:grid-cols-2 xl:grid-cols-4">
            <InfoItem
              v-for="[key, value] in relevantFeatures"
              :key="key"
              :label="formatTechnicalLabel(key)"
              :value="displayValue(value)"
            />
          </div>
        </div>
      </section>

      <div class="grid gap-4 xl:grid-cols-2">
        <div class="panel overflow-hidden">
          <div class="border-b border-slate-800 px-4 py-3">
            <h2 class="text-sm font-semibold text-white">Features</h2>
          </div>
          <div class="overflow-x-auto">
            <table class="min-w-full divide-y divide-slate-800 text-sm">
              <tbody class="divide-y divide-slate-800">
                <tr v-for="[key, value] in featureEntries" :key="key">
                  <td class="px-4 py-3 text-slate-500">{{ formatTechnicalLabel(key) }}</td>
                  <td class="px-4 py-3 text-right font-mono text-slate-200">
                    {{ displayValue(value) }}
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

        <div class="panel p-4">
          <h2 class="text-sm font-semibold text-white">Metadados</h2>
          <pre class="mt-4 max-h-[520px] overflow-auto rounded-md border border-slate-800 bg-surface-850 p-3 text-xs leading-relaxed text-slate-300">{{ metadataJson }}</pre>
        </div>
      </div>
    </template>
  </section>
</template>

<script setup lang="ts">
import { computed, defineComponent, h, onMounted, ref } from 'vue'
import { RouterLink } from 'vue-router'

import ErrorState from '@/components/ui/ErrorState.vue'
import LoadingState from '@/components/ui/LoadingState.vue'
import StatusBadge from '@/components/ui/StatusBadge.vue'
import { getWindowById } from '@/services/api'
import type { WindowItem } from '@/types/api'
import {
  formatAttackType,
  formatDateTime,
  formatDecisionSource,
  formatFinalLabel,
  formatRiskLevel,
  formatTechnicalLabel,
} from '@/utils/formatters'

const props = defineProps<{
  id: string
}>()

type ModuleSummary = {
  title: string
  role: string
  value: string
  status: string
}

const windowItem = ref<WindowItem | null>(null)
const loading = ref(true)
const error = ref('')

const headerSource = computed(() =>
  windowItem.value?.src_ip
    ?? (windowItem.value?.metadata?.src_ip as string | undefined)
    ?? 'Origem não informada',
)
const durationLabel = computed(() => {
  const start = parseDate(windowItem.value?.window_start)
  const end = parseDate(windowItem.value?.window_end)
  if (!start || !end) {
    return '60s'
  }
  const seconds = Math.max(1, Math.round((end.getTime() - start.getTime()) / 1000))
  return `${seconds}s`
})

const modelOutputs = computed<Record<string, unknown>>(() => windowItem.value?.model_outputs ?? {})
const heuristicOutput = computed<Record<string, unknown>>(
  () => (modelOutputs.value.heuristic as Record<string, unknown> | undefined) ?? {},
)
const aiSupportPayload = computed<Record<string, unknown>>(
  () =>
    (windowItem.value?.metadata?.ai_support as Record<string, unknown> | undefined)
    ?? (modelOutputs.value.ai_support as Record<string, unknown> | undefined)
    ?? {},
)

const decisionText = computed(() => {
  const aiSupport = aiSupportPayload.value
  return (
    windowItem.value?.decision_reason
    ?? windowItem.value?.explanation
    ?? (typeof aiSupport.reason === 'string' ? aiSupport.reason : null)
    ?? 'Sem explicação detalhada disponível no payload atual.'
  )
})
const heuristicReason = computed(() =>
  String(
    heuristicOutput.value.heuristic_reason
    ?? heuristicOutput.value.reason
    ?? windowItem.value?.decision_reason
    ?? '-',
  ),
)
const aiSupportReason = computed(() =>
  String(aiSupportPayload.value.reason ?? 'Sem apoio adicional da IA nesta janela.'),
)
const moduleCards = computed<ModuleSummary[]>(() => [
  {
    title: 'Autoencoder',
    role: 'Detector principal individual',
    value: formatScore(windowItem.value?.scores?.autoencoder ?? windowItem.value?.autoencoder_score),
    status: moduleLabel(modelOutputs.value.autoencoder),
  },
  {
    title: 'Isolation Forest',
    role: 'Apoio estatístico',
    value: formatScore(windowItem.value?.scores?.isolation ?? windowItem.value?.isolation_score),
    status: moduleLabel(modelOutputs.value.isolation_forest),
  },
  {
    title: 'Heurística',
    role: 'Contexto e interpretação',
    value: formatAttackType(String(heuristicOutput.value.attack_type ?? windowItem.value?.attack_type ?? 'unknown')),
    status:
      heuristicOutput.value.pred === 1 || heuristicOutput.value.heuristic_detected_attack
        ? 'Disparou'
        : 'Neutra',
  },
  {
    title: 'Ensemble',
    role: 'Agregação de sinais',
    value: formatScore(windowItem.value?.scores?.ensemble ?? windowItem.value?.ensemble_score),
    status: moduleLabel(modelOutputs.value.ensemble),
  },
  {
    title: 'Decision Engine',
    role: 'Decisão final',
    value: formatAttackType(windowItem.value?.attack_type),
    status: formatFinalLabel(windowItem.value?.final_label),
  },
])
const relevantFeatures = computed(() => {
  const features = windowItem.value?.features ?? {}
  const keys = [
    'connections',
    'packets',
    'bytes',
    'ports',
    'bytes_per_packet',
    'packets_per_connection',
    'bytes_per_connection',
    'log1p_connections',
  ]
  return keys
    .filter((key) => key in features)
    .map((key) => [key, features[key]] as const)
})

const featureEntries = computed(() =>
  Object.entries(windowItem.value?.features ?? {}),
)
const metadataJson = computed(() =>
  JSON.stringify(windowItem.value?.metadata ?? {}, null, 2),
)

function parseDate(value?: string | null): Date | null {
  if (!value) {
    return null
  }
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? null : date
}

function formatScore(value?: number | null): string {
  return typeof value === 'number' ? value.toFixed(4) : '-'
}

function displayValue(value: unknown): string {
  if (typeof value === 'number') {
    return Number.isInteger(value) ? String(value) : value.toFixed(4)
  }
  if (typeof value === 'boolean') {
    return value ? 'Sim' : 'Não'
  }
  if (value === null || typeof value === 'undefined') {
    return '-'
  }
  if (typeof value === 'object') {
    return JSON.stringify(value)
  }
  return String(value)
}

function moduleLabel(payload: unknown): string {
  const record = payload as Record<string, unknown> | undefined
  if (!record) {
    return 'Sem sinal'
  }
  if (record.pred === 1 || record.label === 'anomaly') {
    return 'Detectou'
  }
  if (record.pred === 0 || record.label === 'normal') {
    return 'Normal'
  }
  return 'Neutro'
}

const InfoItem = defineComponent({
  props: {
    label: {
      type: String,
      required: true,
    },
    value: {
      type: [String, Number, Boolean],
      default: '-',
    },
  },
  setup(itemProps) {
    return () =>
      h('div', [
        h('p', { class: 'text-xs font-medium text-slate-500' }, itemProps.label),
        h(
          'p',
          { class: 'mt-1 text-wrap-safe text-slate-200' },
          displayValue(itemProps.value),
        ),
      ])
  },
})

const ScoreRow = defineComponent({
  props: {
    label: {
      type: String,
      required: true,
    },
    value: {
      type: Number,
      default: null,
    },
  },
  setup(scoreProps) {
    return () =>
      h(
        'div',
        {
          class:
            'flex items-center justify-between gap-3 rounded-md border border-slate-800 bg-surface-850 px-3 py-2 text-sm',
        },
        [
          h('span', { class: 'text-slate-400' }, scoreProps.label),
          h('span', { class: 'font-mono text-slate-100' }, formatScore(scoreProps.value)),
        ],
      )
  },
})

const ModuleCard = defineComponent({
  props: {
    title: {
      type: String,
      required: true,
    },
    role: {
      type: String,
      required: true,
    },
    value: {
      type: String,
      required: true,
    },
    status: {
      type: String,
      required: true,
    },
  },
  setup(cardProps) {
    return () =>
      h('article', { class: 'rounded-md border border-slate-800 bg-surface-850 p-3' }, [
        h('p', { class: 'text-sm font-semibold text-white' }, cardProps.title),
        h('p', { class: 'mt-1 min-h-10 text-xs leading-5 text-slate-500' }, cardProps.role),
        h('p', { class: 'mt-3 font-mono text-sm text-sky-200' }, cardProps.value),
        h('p', { class: 'mt-1 text-xs text-slate-300' }, cardProps.status),
      ])
  },
})

onMounted(async () => {
  try {
    const response = await getWindowById(props.id)
    if (!response) {
      error.value = 'Janela não encontrada em /history/windows/{id} nem no fallback /history/windows.'
      return
    }
    windowItem.value = response
  } catch {
    error.value = 'Não foi possível carregar o detalhe da janela.'
  } finally {
    loading.value = false
  }
})
</script>
