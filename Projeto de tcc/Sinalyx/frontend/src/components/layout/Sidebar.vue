<template>
  <aside
    class="fixed inset-x-0 bottom-0 z-40 border-t border-slate-800 bg-surface-900/95 backdrop-blur lg:inset-y-0 lg:left-0 lg:w-64 lg:border-r lg:border-t-0"
  >
    <div class="hidden h-16 items-center gap-3 border-b border-slate-800 px-5 lg:flex">
      <img
        src="@/assets/sinalyx-logo.png"
        alt="Logo Sinalyx"
        class="h-10 w-10 rounded-md object-contain"
      />
      <div>
        <p class="text-base font-semibold text-white">Sinalyx</p>
        <p class="text-xs text-slate-500">Sistema de coleta de logs</p>
      </div>
    </div>

    <nav class="grid grid-cols-6 gap-1 p-2 lg:block lg:space-y-1 lg:p-4">
      <RouterLink
        v-for="item in visibleNavigation"
        :key="item.to"
        :to="item.to"
        class="focus-ring flex min-h-12 items-center justify-center rounded-md px-3 text-slate-400 transition hover:bg-surface-800 hover:text-white lg:justify-start lg:gap-3"
        :class="{ 'bg-sky-400/10 text-sky-200 ring-1 ring-sky-400/20': route.path === item.to }"
        :title="item.label"
      >
        <component :is="item.icon" class="h-5 w-5 shrink-0" />
        <span class="hidden text-sm font-medium lg:inline">{{ item.label }}</span>
      </RouterLink>
    </nav>
  </aside>
</template>

<script setup lang="ts">
import {
  Bell,
  FileText,
  History,
  Info,
  LayoutDashboard,
  Presentation,
  Settings,
  ServerCog,
  Users,
} from 'lucide-vue-next'
import { computed } from 'vue'
import { RouterLink, useRoute } from 'vue-router'

import { useAuth } from '@/composables/useAuth'

const route = useRoute()
const { isAdmin } = useAuth()

const navigation = [
  { label: 'Dashboard', to: '/', icon: LayoutDashboard },
  { label: 'Apresentação', to: '/demo', icon: Presentation },
  { label: 'Alertas', to: '/alerts', icon: Bell },
  { label: 'Histórico', to: '/history', icon: History },
  { label: 'Relatórios', to: '/reports', icon: FileText },
  { label: 'Sobre', to: '/about', icon: Info },
  { label: 'Sistema', to: '/system', icon: ServerCog },
  { label: 'Administração', to: '/admin/users', icon: Users, adminOnly: true },
  { label: 'Configurações', to: '/settings', icon: Settings },
]

const visibleNavigation = computed(() =>
  navigation.filter((item) => !item.adminOnly || isAdmin.value),
)
</script>
