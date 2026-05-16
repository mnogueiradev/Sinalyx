<template>
  <section class="space-y-5">
    <div class="flex flex-col gap-2 lg:flex-row lg:items-end lg:justify-between">
      <div>
        <p class="text-xs font-medium text-slate-500">Relatórios</p>
        <h1 class="text-xl font-semibold text-white">Relatório do Sinalyx</h1>
        <p class="mt-1 text-sm text-slate-400">Análise de logs de firewall com IA.</p>
      </div>
      <div class="flex flex-wrap gap-2">
        <button class="focus-ring rounded-md bg-sky-400 px-3 py-2 text-sm font-semibold text-surface-950 transition hover:bg-sky-300" type="button" @click="downloadHtml">
          Exportar HTML
        </button>
        <button class="focus-ring rounded-md border border-slate-700 px-3 py-2 text-sm font-medium text-slate-300 transition hover:bg-surface-800" type="button" @click="printReport">
          Imprimir / salvar em PDF
        </button>
      </div>
    </div>

    <LoadingState v-if="loading" />
    <ErrorState v-else-if="error" :message="error" />

    <article v-else class="printable-report space-y-5">
      <section class="panel p-5">
        <div class="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
          <div>
            <h2 class="text-2xl font-semibold text-white">Relatório do Sinalyx</h2>
            <p class="mt-1 text-sm text-slate-400">Sistema de coleta de logs</p>
          </div>
          <p class="text-sm text-slate-500">Gerado em {{ generatedAt }}</p>
        </div>
      </section>

      <div class="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <Metric label="Janelas" :value="summary?.live?.total_windows ?? 0" />
        <Metric label="Anomalias" :value="summary?.live?.total_alerts ?? 0" />
        <Metric label="Execuções" :value="summary?.live?.total_executions ?? 0" />
        <Metric label="Apoio da IA" :value="summary?.live?.ai_support_count ?? 0" />
      </div>

      <div class="grid gap-4 xl:grid-cols-2">
        <SummaryTable title="Distribuição por tipo de ataque" :items="attackDistribution" />
        <SummaryTable title="Distribuição por risco" :items="riskDistribution" />
      </div>

      <section class="panel overflow-hidden">
        <div class="border-b border-slate-800 px-4 py-3">
          <h2 class="text-sm font-semibold text-white">Alertas recentes</h2>
        </div>
        <ReportTable :rows="alerts" />
      </section>

      <section class="panel overflow-hidden">
        <div class="border-b border-slate-800 px-4 py-3">
          <h2 class="text-sm font-semibold text-white">Últimas janelas analisadas</h2>
        </div>
        <ReportTable :rows="windows" />
      </section>

      <section class="panel p-4">
        <h2 class="text-sm font-semibold text-white">Status do sistema</h2>
        <div class="mt-4 grid gap-3 md:grid-cols-4">
          <Info label="API" :value="systemStatus.health.ok ? 'Disponível' : 'Indisponível'" />
          <Info label="Banco" :value="systemStatus.health.data?.database.available ? 'Disponível' : 'Indisponível'" />
          <Info label="Parser" :value="systemStatus.parser.ok ? 'Disponível' : 'Indisponível'" />
          <Info label="Coletor" :value="systemStatus.collector.ok ? 'Disponível' : 'Indisponível'" />
        </div>
      </section>

      <p v-if="feedback" class="text-sm text-slate-300">{{ feedback }}</p>
    </article>
  </section>
</template>

<script setup lang="ts">
import { computed, defineComponent, h, onMounted, ref } from 'vue'

import ErrorState from '@/components/ui/ErrorState.vue'
import LoadingState from '@/components/ui/LoadingState.vue'
import {
  getHistoryAlerts,
  getHistorySummary,
  getHistoryWindows,
  getSystemStatus,
} from '@/services/api'
import type { AlertItem, HistorySummary, SystemStatus, WindowItem } from '@/types/api'
import { dateStamp, exportHtml } from '@/utils/exporters'
import {
  formatAttackType,
  formatDateTime,
  formatDecisionSource,
  formatRiskLevel,
} from '@/utils/formatters'

const loading = ref(true)
const error = ref('')
const feedback = ref('')
const generatedAt = formatDateTime(new Date().toISOString())
const summary = ref<HistorySummary | null>(null)
const windows = ref<WindowItem[]>([])
const alerts = ref<AlertItem[]>([])
const systemStatus = ref<SystemStatus>({
  health: { ok: false },
  parser: { ok: false },
  collector: { ok: false },
})

const attackDistribution = computed(() =>
  Object.entries(summary.value?.live?.attack_type_distribution ?? {})
    .map(([label, value]) => [formatAttackType(label), value] as const),
)
const riskDistribution = computed(() =>
  Object.entries(summary.value?.live?.risk_level_distribution ?? {})
    .map(([label, value]) => [formatRiskLevel(label), value] as const),
)

function reportHtml(): string {
  const alertRows = alerts.value.map((row) => tableRow(row)).join('')
  const windowRows = windows.value.map((row) => tableRow(row)).join('')
  const attackRows = attackDistribution.value.map(([label, value]) => `<tr><td>${label}</td><td>${value}</td></tr>`).join('')
  const riskRows = riskDistribution.value.map(([label, value]) => `<tr><td>${label}</td><td>${value}</td></tr>`).join('')

  return `<!doctype html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8" />
  <title>Relatório do Sinalyx</title>
  <style>
    body { font-family: Arial, sans-serif; color: #111827; margin: 32px; }
    h1, h2 { color: #0f172a; }
    .grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin: 20px 0; }
    .card { border: 1px solid #cbd5e1; border-radius: 8px; padding: 14px; }
    .value { font-size: 28px; font-weight: 700; }
    table { width: 100%; border-collapse: collapse; margin: 12px 0 24px; }
    th, td { border: 1px solid #cbd5e1; padding: 8px; text-align: left; font-size: 13px; }
    th { background: #e2e8f0; }
  </style>
</head>
<body>
  <h1>Relatório do Sinalyx</h1>
  <p>Sistema de coleta de logs</p>
  <p>Gerado em ${generatedAt}</p>
  <p><strong>Escopo:</strong> Análise de logs de firewall com IA.</p>
  <div class="grid">
    <div class="card"><p>Janelas</p><div class="value">${summary.value?.live?.total_windows ?? 0}</div></div>
    <div class="card"><p>Anomalias</p><div class="value">${summary.value?.live?.total_alerts ?? 0}</div></div>
    <div class="card"><p>Execuções</p><div class="value">${summary.value?.live?.total_executions ?? 0}</div></div>
    <div class="card"><p>Apoio da IA</p><div class="value">${summary.value?.live?.ai_support_count ?? 0}</div></div>
  </div>
  <h2>Distribuição por tipo de ataque</h2>
  <table><tbody>${attackRows}</tbody></table>
  <h2>Distribuição por risco</h2>
  <table><tbody>${riskRows}</tbody></table>
  <h2>Alertas recentes</h2>
  <table><thead><tr><th>Início</th><th>Tipo</th><th>Risco</th><th>Fonte</th></tr></thead><tbody>${alertRows}</tbody></table>
  <h2>Últimas janelas analisadas</h2>
  <table><thead><tr><th>Início</th><th>Tipo</th><th>Risco</th><th>Fonte</th></tr></thead><tbody>${windowRows}</tbody></table>
</body>
</html>`
}

function tableRow(row: WindowItem): string {
  return `<tr><td>${formatDateTime(row.window_start)}</td><td>${formatAttackType(row.attack_type)}</td><td>${formatRiskLevel(row.risk_level)}</td><td>${formatDecisionSource(row.decision_source)}</td></tr>`
}

function downloadHtml(): void {
  feedback.value = exportHtml(`sinalyx_relatorio_${dateStamp()}.html`, reportHtml())
    ? 'Relatório HTML exportado com sucesso.'
    : 'Não há dados para exportar.'
}

function printReport(): void {
  window.print()
}

const Metric = defineComponent({
  props: {
    label: { type: String, required: true },
    value: { type: Number, required: true },
  },
  setup(props) {
    return () => h('div', { class: 'panel p-4' }, [
      h('p', { class: 'text-sm text-slate-500' }, props.label),
      h('p', { class: 'mt-2 text-3xl font-semibold text-white' }, String(props.value)),
    ])
  },
})

const Info = defineComponent({
  props: {
    label: { type: String, required: true },
    value: { type: String, required: true },
  },
  setup(props) {
    return () => h('div', { class: 'rounded-md border border-slate-800 bg-surface-850 p-3' }, [
      h('p', { class: 'text-xs text-slate-500' }, props.label),
      h('p', { class: 'mt-1 text-sm font-semibold text-white' }, props.value),
    ])
  },
})

const SummaryTable = defineComponent({
  props: {
    title: { type: String, required: true },
    items: { type: Array as () => readonly (readonly [string, number])[], required: true },
  },
  setup(props) {
    return () => h('section', { class: 'panel overflow-hidden' }, [
      h('div', { class: 'border-b border-slate-800 px-4 py-3' }, [
        h('h2', { class: 'text-sm font-semibold text-white' }, props.title),
      ]),
      h('div', { class: 'p-4 space-y-2' }, props.items.map(([label, value]) =>
        h('div', { class: 'flex items-center justify-between gap-3 text-sm' }, [
          h('span', { class: 'text-slate-300' }, label),
          h('span', { class: 'font-medium text-white' }, String(value)),
        ]),
      )),
    ])
  },
})

const ReportTable = defineComponent({
  props: {
    rows: { type: Array as () => WindowItem[], required: true },
  },
  setup(props) {
    return () => h('div', { class: 'overflow-x-auto' }, [
      h('table', { class: 'min-w-full divide-y divide-slate-800 text-sm' }, [
        h('thead', { class: 'bg-surface-850 text-left text-xs uppercase text-slate-500' }, [
          h('tr', [
            h('th', { class: 'px-4 py-3 font-medium' }, 'Início'),
            h('th', { class: 'px-4 py-3 font-medium' }, 'Tipo'),
            h('th', { class: 'px-4 py-3 font-medium' }, 'Risco'),
            h('th', { class: 'px-4 py-3 font-medium' }, 'Fonte da decisão'),
          ]),
        ]),
        h('tbody', { class: 'divide-y divide-slate-800' }, props.rows.map((row) =>
          h('tr', [
            h('td', { class: 'px-4 py-3 text-sky-300' }, formatDateTime(row.window_start)),
            h('td', { class: 'px-4 py-3 text-slate-300' }, formatAttackType(row.attack_type)),
            h('td', { class: 'px-4 py-3 text-slate-300' }, formatRiskLevel(row.risk_level)),
            h('td', { class: 'px-4 py-3 text-slate-400' }, formatDecisionSource(row.decision_source)),
          ]),
        )),
      ]),
    ])
  },
})

onMounted(async () => {
  try {
    const [summaryResponse, windowsResponse, alertsResponse, systemResponse] =
      await Promise.all([
        getHistorySummary(),
        getHistoryWindows(20, 0),
        getHistoryAlerts(20, 0),
        getSystemStatus(),
      ])
    summary.value = summaryResponse
    windows.value = windowsResponse.windows
    alerts.value = alertsResponse.alerts
    systemStatus.value = systemResponse
  } catch {
    error.value = 'Não foi possível carregar os dados do relatório.'
  } finally {
    loading.value = false
  }
})
</script>
