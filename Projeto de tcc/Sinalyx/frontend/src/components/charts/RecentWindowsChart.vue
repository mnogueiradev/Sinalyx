<template>
  <section class="panel p-4">
    <div class="flex items-center justify-between gap-3">
      <h2 class="text-sm font-semibold text-white">{{ title }}</h2>
      <p class="text-xs text-slate-500">Janelas recentes</p>
    </div>

    <p v-if="items.length === 0" class="mt-4 text-sm text-slate-400">
      Nenhuma janela recente para exibir.
    </p>

    <div v-else class="mt-5">
      <div class="flex h-40 items-end gap-2 border-b border-slate-800 pb-2">
        <div
          v-for="item in items"
          :key="item.id"
          class="flex min-w-0 flex-1 flex-col items-center gap-2"
        >
          <div class="flex h-28 w-full items-end justify-center rounded-t-md bg-surface-850 px-1">
            <div
              class="w-full max-w-8 rounded-t-md transition"
              :class="item.isAnomaly ? 'bg-red-400' : 'bg-emerald-400'"
              :style="{ height: `${barHeight(item.score)}%` }"
              :title="item.tooltip"
            />
          </div>
          <span class="max-w-full truncate text-[11px] text-slate-500">
            {{ item.label }}
          </span>
        </div>
      </div>
      <div class="mt-3 flex flex-wrap gap-3 text-xs text-slate-400">
        <span class="inline-flex items-center gap-2">
          <span class="h-2 w-2 rounded-full bg-emerald-400" /> Normal
        </span>
        <span class="inline-flex items-center gap-2">
          <span class="h-2 w-2 rounded-full bg-red-400" /> Anomalia
        </span>
      </div>
    </div>
  </section>
</template>

<script setup lang="ts">
export type RecentWindowChartItem = {
  id: string | number
  label: string
  score: number
  isAnomaly: boolean
  tooltip: string
}

defineProps<{
  title: string
  items: RecentWindowChartItem[]
}>()

function barHeight(score: number): number {
  const normalized = Math.max(0, Math.min(1, Number(score || 0)))
  return Math.max(18, Math.round(normalized * 100))
}
</script>

