<template>
  <section class="space-y-5">
    <div>
      <p class="text-xs font-medium text-slate-500">Configuração local</p>
      <h1 class="text-xl font-semibold text-white">Configurações</h1>
    </div>

    <div class="panel p-4">
      <div class="grid gap-4 md:grid-cols-2">
        <div>
          <p class="muted-label">API base</p>
          <p class="mt-2 break-all text-sm text-slate-200">{{ baseUrl }}</p>
        </div>
        <div>
          <p class="muted-label">Variável</p>
          <p class="mt-2 text-sm text-slate-200">VITE_API_BASE_URL</p>
        </div>
      </div>
    </div>
  </section>
</template>

<script setup lang="ts">
import { apiBaseUrl } from '@/services/api'

const baseUrl = apiBaseUrl()
</script>
