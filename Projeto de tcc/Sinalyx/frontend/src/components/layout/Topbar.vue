<template>
  <header class="sticky top-0 z-30 border-b border-slate-800 bg-surface-950/90 backdrop-blur">
    <div class="flex h-16 items-center gap-4 px-4 sm:px-6 lg:px-8">
      <div class="min-w-0 flex-1">
        <label class="relative block max-w-xl">
          <Search class="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
          <input
            v-model="globalSearch"
            class="focus-ring h-10 w-full rounded-md border border-slate-800 bg-surface-900 pl-10 pr-3 text-sm text-slate-100 placeholder:text-slate-600"
            type="search"
            placeholder="Buscar janela, alerta ou análise"
          />
        </label>
      </div>

      <div class="hidden items-center gap-3 sm:flex">
        <div class="text-right">
          <p class="text-sm font-medium text-white">{{ currentUser?.name ?? 'Usuário' }}</p>
          <p class="text-xs text-slate-500">{{ roleLabel }}</p>
        </div>
        <div class="grid h-10 w-10 place-items-center rounded-md border border-emerald-400/30 bg-emerald-400/10 text-sm font-semibold text-emerald-200">
          {{ initials }}
        </div>
        <button
          class="focus-ring rounded-md border border-slate-700 px-3 py-2 text-sm font-medium text-slate-300 transition hover:bg-surface-800"
          type="button"
          @click="handleLogout"
        >
          Sair
        </button>
      </div>
    </div>
  </header>
</template>

<script setup lang="ts">
import { Search } from 'lucide-vue-next'
import { computed } from 'vue'
import { useRouter } from 'vue-router'

import { useAuth } from '@/composables/useAuth'
import { useGlobalSearch } from '@/composables/useGlobalSearch'

const { globalSearch } = useGlobalSearch()
const { currentUser, logout } = useAuth()
const router = useRouter()

const roleLabel = computed(() =>
  currentUser.value?.role === 'admin' ? 'Administrador' : 'Usuário',
)
const initials = computed(() => {
  const source = currentUser.value?.name || currentUser.value?.email || 'US'
  return source
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part.charAt(0).toUpperCase())
    .join('')
})

function handleLogout(): void {
  logout()
  router.push('/login')
}
</script>
