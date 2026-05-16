<template>
  <span
    class="inline-flex items-center rounded-md px-2 py-1 text-xs font-medium ring-1"
    :class="classes"
  >
    {{ label }}
  </span>
</template>

<script setup lang="ts">
import { computed } from 'vue'

import {
  formatBoolean,
  formatFinalLabel,
  formatRiskLevel,
} from '@/utils/formatters'

const props = defineProps<{
  value?: string | boolean | null
}>()

const normalized = computed(() => String(props.value ?? 'unknown').toLowerCase())

const label = computed(() => {
  if (typeof props.value === 'boolean') {
    return formatBoolean(props.value)
  }
  const value = String(props.value ?? 'unknown')
  if (['low', 'medium', 'high', 'critical'].includes(normalized.value)) {
    return formatRiskLevel(value)
  }
  return formatFinalLabel(value)
})

const classes = computed(() => {
  if (['normal', 'low', 'success', 'sucesso', 'available', 'disponível', 'ok', 'false'].includes(normalized.value)) {
    return 'bg-emerald-400/10 text-emerald-200 ring-emerald-400/20'
  }
  if (['anomaly', 'high', 'critical', 'error', 'erro', 'unavailable', 'indisponível', 'true'].includes(normalized.value)) {
    return 'bg-red-400/10 text-red-200 ring-red-400/20'
  }
  if (['medium', 'médio', 'warning'].includes(normalized.value)) {
    return 'bg-amber-400/10 text-amber-200 ring-amber-400/20'
  }
  return 'bg-slate-700/40 text-slate-300 ring-slate-600/50'
})
</script>
