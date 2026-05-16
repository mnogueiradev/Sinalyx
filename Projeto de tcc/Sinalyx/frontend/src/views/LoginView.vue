<template>
  <main class="grid min-h-screen place-items-center bg-surface-950 px-4 py-8 text-slate-100">
    <section class="w-full max-w-md">
      <div class="mb-6 flex items-center gap-3">
        <img
          src="@/assets/sinalyx-logo.png"
          alt="Logo Sinalyx"
          class="h-12 w-12 rounded-md object-contain"
        />
        <div>
          <h1 class="text-2xl font-semibold text-white">Sinalyx</h1>
          <p class="text-sm text-slate-500">Sistema de coleta de logs</p>
        </div>
      </div>

      <form class="panel space-y-4 p-5" @submit.prevent="handleLogin">
        <div>
          <p class="text-xs font-medium text-slate-500">Acesso restrito</p>
          <h2 class="mt-1 text-lg font-semibold text-white">Entrar no painel</h2>
        </div>

        <label class="block text-sm">
          <span class="text-slate-300">Email</span>
          <input
            v-model="email"
            class="focus-ring mt-2 h-11 w-full rounded-md border border-slate-800 bg-surface-900 px-3 text-sm text-slate-100 placeholder:text-slate-600"
            type="email"
            autocomplete="username"
            placeholder="admin@sinalyx.local"
            required
          />
        </label>

        <label class="block text-sm">
          <span class="text-slate-300">Senha</span>
          <input
            v-model="password"
            class="focus-ring mt-2 h-11 w-full rounded-md border border-slate-800 bg-surface-900 px-3 text-sm text-slate-100 placeholder:text-slate-600"
            type="password"
            autocomplete="current-password"
            placeholder="Digite sua senha"
            required
          />
        </label>

        <p v-if="error" class="rounded-md border border-red-400/20 bg-red-400/10 px-3 py-2 text-sm text-red-200">
          {{ error }}
        </p>

        <button
          class="focus-ring h-11 w-full rounded-md bg-sky-400 text-sm font-semibold text-surface-950 transition hover:bg-sky-300 disabled:cursor-not-allowed disabled:opacity-60"
          type="submit"
          :disabled="loading"
        >
          {{ loading ? 'Entrando...' : 'Entrar' }}
        </button>
      </form>
    </section>
  </main>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'

import { useAuth } from '@/composables/useAuth'

const email = ref('')
const password = ref('')
const loading = ref(false)
const error = ref('')
const auth = useAuth()
const router = useRouter()
const route = useRoute()

async function handleLogin(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    await auth.login(email.value, password.value)
    const redirect = typeof route.query.redirect === 'string'
      ? route.query.redirect
      : '/'
    await router.push(redirect)
  } catch {
    error.value = 'Não foi possível entrar. Verifique email, senha e disponibilidade da API.'
  } finally {
    loading.value = false
  }
}
</script>

