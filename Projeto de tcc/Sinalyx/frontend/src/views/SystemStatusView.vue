<template>
  <section class="space-y-5">
    <div>
      <p class="muted-label">Infraestrutura</p>
      <h1 class="text-xl font-semibold text-white">Sistema</h1>
    </div>

    <LoadingState v-if="loading" />

    <template v-else-if="status">
      <div class="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <StatCard
          label="API"
          :value="healthLabel"
          :icon="ServerCog"
          icon-class="border-sky-400/30 bg-sky-400/10 text-sky-200"
        />
        <StatCard
          label="Banco de dados"
          :value="databaseLabel"
          :icon="Database"
          icon-class="border-emerald-400/30 bg-emerald-400/10 text-emerald-200"
        />
        <StatCard
          label="Parser"
          :value="parserLabel"
          :icon="FileSearch"
          icon-class="border-cyan-400/30 bg-cyan-400/10 text-cyan-200"
        />
        <StatCard
          label="Coletor"
          :value="collectorLabel"
          :icon="RadioReceiver"
          icon-class="border-amber-400/30 bg-amber-400/10 text-amber-200"
        />
      </div>

      <div class="grid gap-4 xl:grid-cols-2">
        <section class="panel p-4">
          <div class="flex items-start justify-between gap-3">
            <div>
              <p class="muted-label">Parser incremental</p>
              <h2 class="mt-1 text-base font-semibold text-white">Runtime pfSense</h2>
            </div>
            <StatusBadge :value="parserLabel" />
          </div>

          <ErrorState
            v-if="!status.parser.ok"
            class="mt-4"
            title="Parser indisponível"
            :message="status.parser.error"
          />
          <dl v-else class="mt-4 grid gap-3 sm:grid-cols-2">
            <InfoItem label="Último processamento" :value="parserState.last_processing_mode ?? undefined" />
            <InfoItem label="Última execução" :value="parserState.last_execution_id ?? undefined" />
            <InfoItem label="Linhas novas" :value="parserState.last_lines_new ?? undefined" />
            <InfoItem label="Janelas geradas" :value="parserState.last_windows_generated ?? undefined" />
            <InfoItem label="Eventos pendentes" :value="parserState.pending_events_count ?? undefined" />
            <InfoItem label="Arquivo local" :value="fileExistsLabel" />
            <InfoItem label="Tamanho atual" :value="formatBytes(parserState.current_file_size)" />
            <InfoItem label="Último erro" :value="parserState.last_error ?? undefined" />
          </dl>
        </section>

        <section class="panel p-4">
          <div class="flex items-start justify-between gap-3">
            <div>
              <p class="muted-label">Coletor SSH/SFTP</p>
              <h2 class="mt-1 text-base font-semibold text-white">filter.log pfSense</h2>
            </div>
            <StatusBadge :value="collectorLabel" />
          </div>

          <ErrorState
            v-if="!status.collector.ok"
            class="mt-4"
            title="Coletor indisponível"
            :message="status.collector.error"
          />
          <dl v-else class="mt-4 grid gap-3 sm:grid-cols-2">
            <InfoItem label="Última coleta" :value="collectorState.last_fetch_at ?? undefined" />
            <InfoItem label="Status da coleta" :value="formatRuntimeStatus(collectorState.last_fetch_status)" />
            <InfoItem label="Remoto" :value="collectorState.remote_path ?? undefined" />
            <InfoItem label="Local" :value="collectorState.local_path ?? undefined" />
            <InfoItem label="Tamanho coletado" :value="formatBytes(collectorState.file_size)" />
            <InfoItem label="Último erro" :value="collectorState.last_error ?? undefined" />
          </dl>
        </section>
      </div>
    </template>
  </section>
</template>

<script setup lang="ts">
import { computed, defineComponent, h, onMounted, ref } from 'vue'
import { Database, FileSearch, RadioReceiver, ServerCog } from 'lucide-vue-next'

import ErrorState from '@/components/ui/ErrorState.vue'
import LoadingState from '@/components/ui/LoadingState.vue'
import StatCard from '@/components/ui/StatCard.vue'
import StatusBadge from '@/components/ui/StatusBadge.vue'
import { getSystemStatus } from '@/services/api'
import type { LiveRuntimeState, SystemStatus } from '@/types/api'

const status = ref<SystemStatus | null>(null)
const loading = ref(true)

const parserState = computed<LiveRuntimeState>(() => status.value?.parser.data?.state ?? {})
const collectorState = computed<LiveRuntimeState>(() => status.value?.collector.data?.state ?? {})

const healthLabel = computed(() => {
  if (!status.value?.health.ok) {
    return 'Indisponível'
  }
  return status.value.health.data?.status === 'ok' ? 'Sucesso' : 'Desconhecido'
})

const databaseLabel = computed(() => {
  if (!status.value?.health.ok) {
    return 'Indisponível'
  }
  return status.value.health.data?.database.available ? 'Disponível' : 'Indisponível'
})

const parserLabel = computed(() => {
  if (!status.value?.parser.ok) {
    return 'erro'
  }
  return parserState.value.last_run_status === 'success' ? 'Sucesso' : 'Desconhecido'
})

const collectorLabel = computed(() => {
  if (!status.value?.collector.ok) {
    return 'erro'
  }
  return collectorState.value.last_fetch_status === 'success' ? 'Sucesso' : 'Desconhecido'
})

const fileExistsLabel = computed(() => {
  if (parserState.value.local_file_exists === undefined || parserState.value.local_file_exists === null) {
    return '-'
  }
  return parserState.value.local_file_exists ? 'Sim' : 'Não'
})

function formatBytes(value: unknown): string {
  if (typeof value !== 'number' || Number.isNaN(value)) {
    return '-'
  }
  if (value < 1024) {
    return `${value} B`
  }
  if (value < 1024 * 1024) {
    return `${(value / 1024).toFixed(1)} KB`
  }
  return `${(value / 1024 / 1024).toFixed(2)} MB`
}

function formatRuntimeStatus(value?: string | null): string {
  if (value === 'success') {
    return 'Sucesso'
  }
  if (value === 'available') {
    return 'Disponível'
  }
  if (!value || value === 'unknown') {
    return 'Desconhecido'
  }
  return value
}

const InfoItem = defineComponent({
  props: {
    label: {
      type: String,
      required: true,
    },
    value: {
      type: [String, Number, Boolean],
      default: null,
    },
  },
  setup(props) {
    return () =>
      h('div', { class: 'min-w-0 rounded-md border border-slate-800 bg-surface-850 p-3' }, [
        h('dt', { class: 'text-xs font-medium text-slate-500' }, props.label),
        h(
          'dd',
          { class: 'mt-1 break-words text-sm text-slate-200' },
          props.value === null || props.value === undefined || props.value === ''
            ? '-'
            : String(props.value),
        ),
      ])
  },
})

onMounted(async () => {
  status.value = await getSystemStatus()
  loading.value = false
})
</script>
