<template>
  <article class="panel p-4">
    <div class="flex items-start justify-between gap-4">
      <div>
        <p class="text-xs font-medium text-slate-500">{{ label }}</p>
        <p class="mt-2 text-2xl font-semibold text-white">{{ value }}</p>
      </div>
      <div class="grid h-10 w-10 place-items-center rounded-md border" :class="iconClass">
        <component :is="icon" class="h-5 w-5" />
      </div>
    </div>
    <p v-if="hint" class="mt-3 text-sm text-slate-500">{{ hint }}</p>
  </article>
</template>

<script setup lang="ts">
import type { Component } from 'vue'

defineProps<{
  label: string
  value: string | number
  hint?: string
  icon: Component
  iconClass?: string
}>()
</script>
