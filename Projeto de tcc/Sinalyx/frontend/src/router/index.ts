import { createRouter, createWebHistory } from 'vue-router'

import AlertsView from '@/views/AlertsView.vue'
import AdminUsersView from '@/views/AdminUsersView.vue'
import AnalysisDetailsView from '@/views/AnalysisDetailsView.vue'
import AboutView from '@/views/AboutView.vue'
import DashboardView from '@/views/DashboardView.vue'
import DemoView from '@/views/DemoView.vue'
import HistoryView from '@/views/HistoryView.vue'
import LoginView from '@/views/LoginView.vue'
import ReportsView from '@/views/ReportsView.vue'
import SettingsView from '@/views/SettingsView.vue'
import SystemStatusView from '@/views/SystemStatusView.vue'
import WindowDetailsView from '@/views/WindowDetailsView.vue'
import { useAuth } from '@/composables/useAuth'

export const router = createRouter({
  history: createWebHistory(),
  routes: [
    {
      path: '/login',
      name: 'login',
      component: LoginView,
      meta: { public: true },
    },
    {
      path: '/',
      name: 'dashboard',
      component: DashboardView,
    },
    {
      path: '/demo',
      name: 'demo',
      component: DemoView,
    },
    {
      path: '/alerts',
      name: 'alerts',
      component: AlertsView,
    },
    {
      path: '/history',
      name: 'history',
      component: HistoryView,
    },
    {
      path: '/reports',
      name: 'reports',
      component: ReportsView,
    },
    {
      path: '/about',
      name: 'about',
      component: AboutView,
    },
    {
      path: '/analyses/:id',
      name: 'analysis-details',
      component: AnalysisDetailsView,
      props: true,
    },
    {
      path: '/windows/:id',
      name: 'window-details',
      component: WindowDetailsView,
      props: true,
    },
    {
      path: '/system',
      name: 'system',
      component: SystemStatusView,
    },
    {
      path: '/admin/users',
      name: 'admin-users',
      component: AdminUsersView,
      meta: { requiresAdmin: true },
    },
    {
      path: '/settings',
      name: 'settings',
      component: SettingsView,
    },
  ],
})

router.beforeEach(async (to) => {
  const auth = useAuth()

  if (to.meta.public === true) {
    if (to.name === 'login' && auth.token.value) {
      if (!auth.currentUser.value) {
        await auth.loadMe()
      }
      if (auth.isAuthenticated.value) {
        return { path: '/' }
      }
    }
    return true
  }

  if (!auth.token.value) {
    return {
      path: '/login',
      query: { redirect: to.fullPath },
    }
  }

  if (!auth.currentUser.value) {
    await auth.loadMe()
  }

  if (!auth.isAuthenticated.value) {
    return {
      path: '/login',
      query: { redirect: to.fullPath },
    }
  }

  if (to.meta.requiresAdmin === true && !auth.isAdmin.value) {
    return { path: '/' }
  }

  return true
})
