<template>
  <section class="panel p-4">
    <div class="flex items-center justify-between gap-3">
      <h2 class="text-sm font-semibold text-white">{{ title }}</h2>
      <p class="text-xs text-slate-500">{{ total }} registros</p>
    </div>

    <p v-if="items.length === 0" class="mt-4 text-sm text-slate-400">
      Nenhum dado disponível para o gráfico.
    </p>

    <div v-else class="mt-4 space-y-3">
      <div v-for="item in items" :key="item.label" class="space-y-1">
        <div class="flex items-center justify-between gap-3 text-sm">
          <span class="text-slate-300">{{ item.label }}</span>
          <span class="font-medium text-white">{{ item.value }}</span>
        </div>
        <div class="h-2 overflow-hidden rounded-full bg-surface-850">
          <div
            class="h-full rounded-full"
            :class="item.color"
            :style="{ width: `${barWidth(item.value)}%` }"
          />
        </div>
      </div>
    </div>
  </section>
</template>

<script setup lang="ts">
import { computed } from 'vue'

export type ChartItem = {
  label: string
  value: number
  color: string
}

const props = defineProps<{
  title: string
  items: ChartItem[]
}>()

const total = computed(() =>
  props.items.reduce((sum, item) => sum + Number(item.value || 0), 0),
)
const maxValue = computed(() =>
  Math.max(1, ...props.items.map((item) => Number(item.value || 0))),
)

function barWidth(value: number): number {
  return Math.max(4, Math.round((Number(value || 0) / maxValue.value) * 100))
}
</script>

