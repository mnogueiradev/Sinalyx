<template>
  <div class="panel p-4">
    <div class="flex items-center gap-3 text-slate-400">
      <LoaderCircle class="h-5 w-5 animate-spin text-sky-300" />
      <span class="text-sm">{{ label }}</span>
    </div>
  </div>
</template>

<script setup lang="ts">
import { LoaderCircle } from 'lucide-vue-next'

withDefaults(
  defineProps<{
    label?: string
  }>(),
  {
    label: 'Carregando dados',
  },
)
</script>
