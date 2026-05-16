<template>
  <div class="panel border-red-400/20 bg-red-950/20 p-4 text-red-100">
    <div class="flex items-start gap-3">
      <AlertTriangle class="mt-0.5 h-5 w-5 shrink-0 text-red-300" />
      <div>
        <p class="font-medium">{{ title }}</p>
        <p class="mt-1 text-sm text-red-200/80">{{ message }}</p>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { AlertTriangle } from 'lucide-vue-next'

withDefaults(
  defineProps<{
    title?: string
    message?: string
  }>(),
  {
    title: 'Nao foi possivel carregar os dados',
    message: 'Verifique se a API do Sinalyx esta acessivel.',
  },
)
</script>
