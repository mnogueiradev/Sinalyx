<template>
  <div class="min-h-screen bg-surface-950 text-slate-100">
    <template v-if="isPublicRoute">
      <RouterView />
    </template>

    <div v-else class="min-h-screen lg:pl-64">
      <Sidebar />
      <Topbar />
      <main class="px-4 py-5 sm:px-6 lg:px-8">
        <RouterView />
      </main>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { RouterView, useRoute } from 'vue-router'

import Sidebar from './Sidebar.vue'
import Topbar from './Topbar.vue'

const route = useRoute()
const isPublicRoute = computed(() => route.meta.public === true)
</script>
