<template>
  <section class="space-y-5">
    <div class="flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
      <div>
        <p class="text-xs font-medium text-slate-500">Painel administrativo</p>
        <h1 class="text-xl font-semibold text-white">Usuários</h1>
      </div>
      <p v-if="meta" class="text-sm text-slate-500">{{ meta.returned }} de {{ meta.total }}</p>
    </div>

    <div class="grid gap-4 xl:grid-cols-[0.9fr_1.3fr]">
      <form class="panel space-y-3 p-4" @submit.prevent="saveUser">
        <div>
          <p class="text-xs font-medium text-slate-500">{{ editingUser ? 'Editar usuário' : 'Novo usuário' }}</p>
          <h2 class="mt-1 text-sm font-semibold text-white">Cadastro</h2>
        </div>

        <label class="block text-sm">
          <span class="text-slate-300">Nome</span>
          <input v-model="form.name" class="field" required />
        </label>
        <label class="block text-sm">
          <span class="text-slate-300">Email</span>
          <input v-model="form.email" class="field" type="email" required :disabled="editingProtectedUser" />
        </label>
        <label class="block text-sm">
          <span class="text-slate-300">Senha</span>
          <input
            v-model="form.password"
            class="field"
            type="password"
            :required="!editingUser"
            placeholder="Obrigatória para novo usuário"
          />
        </label>
        <div class="grid gap-3 sm:grid-cols-2">
          <label class="block text-sm">
            <span class="text-slate-300">Papel</span>
            <select v-model="form.role" class="field" :disabled="editingProtectedUser">
              <option value="user">Usuário</option>
              <option value="admin">Administrador</option>
            </select>
          </label>
          <label class="flex items-center gap-2 pt-7 text-sm text-slate-300">
            <input v-model="form.is_active" type="checkbox" :disabled="editingProtectedUser" />
            Ativo
          </label>
        </div>

        <p v-if="editingProtectedUser" class="rounded-md border border-sky-400/20 bg-sky-400/10 px-3 py-2 text-sm text-sky-100">
          Administrador protegido: esta conta não pode ser desativada, removida, rebaixada ou ter o email alterado.
        </p>

        <p v-if="feedback" class="rounded-md border border-slate-800 bg-surface-850 px-3 py-2 text-sm text-slate-300">
          {{ feedback }}
        </p>

        <div class="flex flex-wrap gap-2">
          <button class="btn btn-primary" type="submit">
            {{ editingUser ? 'Salvar alterações' : 'Criar usuário' }}
          </button>
          <button class="btn btn-secondary" type="button" @click="resetForm">
            Limpar
          </button>
        </div>
      </form>

      <div>
        <LoadingState v-if="loading" />
        <ErrorState v-else-if="error" :message="error" />
        <div v-else class="panel overflow-hidden">
          <div class="overflow-x-auto">
            <table class="min-w-full divide-y divide-slate-800 text-sm">
              <thead class="bg-surface-850 text-left text-xs uppercase text-slate-500">
                <tr>
                  <th class="px-4 py-3 font-medium">Nome</th>
                  <th class="px-4 py-3 font-medium">Email</th>
                  <th class="px-4 py-3 font-medium">Papel</th>
                  <th class="px-4 py-3 font-medium">Status</th>
                  <th class="px-4 py-3 font-medium">Ações</th>
                </tr>
              </thead>
              <tbody class="divide-y divide-slate-800">
                <tr v-for="user in users" :key="user.id">
                  <td class="px-4 py-3 font-medium text-white text-wrap-safe">
                    {{ user.name }}
                  </td>
                  <td class="whitespace-nowrap px-4 py-3 text-slate-300">{{ user.email }}</td>
                  <td class="px-4 py-3 text-slate-300">{{ user.role === 'admin' ? 'Administrador' : 'Usuário' }}</td>
                  <td class="px-4 py-3">
                    <StatusBadge :value="user.is_active" />
                  </td>
                  <td class="px-4 py-3">
                    <div v-if="isProtectedAdmin(user)" class="flex flex-wrap gap-2">
                      <span class="rounded-md border border-slate-700 bg-surface-850 px-3 py-2 text-sm font-medium text-slate-300">
                        Protegido
                      </span>
                    </div>
                    <div v-else class="flex flex-wrap gap-2">
                      <button class="btn btn-secondary" type="button" @click="editUser(user)">
                        Editar
                      </button>
                      <button
                        class="btn"
                        :class="user.is_active ? 'btn-secondary' : 'btn-success'"
                        type="button"
                        title="Alterar status"
                        @click="toggleStatus(user)"
                      >
                        {{ user.is_active ? 'Desativar' : 'Ativar' }}
                      </button>
                      <button
                        class="btn btn-danger"
                        type="button"
                        :disabled="user.id === currentUser?.id"
                        :title="removeTitle(user)"
                        @click="removeUser(user)"
                      >
                        Remover
                      </button>
                    </div>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  </section>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'

import ErrorState from '@/components/ui/ErrorState.vue'
import LoadingState from '@/components/ui/LoadingState.vue'
import StatusBadge from '@/components/ui/StatusBadge.vue'
import {
  createAdminUser,
  deleteAdminUser,
  getAdminUsers,
  updateAdminUser,
  updateAdminUserStatus,
} from '@/services/api'
import type { AuthUser, PaginationMeta, UserPayload, UserRole } from '@/types/api'
import { useAuth } from '@/composables/useAuth'

const users = ref<AuthUser[]>([])
const meta = ref<PaginationMeta | null>(null)
const loading = ref(true)
const error = ref('')
const feedback = ref('')
const editingUser = ref<AuthUser | null>(null)
const { currentUser } = useAuth()
const editingProtectedUser = computed(() => isProtectedAdmin(editingUser.value))
const form = reactive<{
  name: string
  email: string
  password: string
  role: UserRole
  is_active: boolean
}>({
  name: '',
  email: '',
  password: '',
  role: 'user',
  is_active: true,
})

function isProtectedAdmin(user: AuthUser | null | undefined): boolean {
  return user?.is_protected === true
}

function removeTitle(user: AuthUser): string {
  if (isProtectedAdmin(user)) {
    return 'O administrador supremo nao pode ser removido.'
  }
  if (user.id === currentUser.value?.id) {
    return 'Nao e possivel remover o proprio usuario.'
  }
  return 'Remover usuario'
}

async function loadUsers(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    const response = await getAdminUsers(100, 0)
    users.value = response.users
    meta.value = response.meta
  } catch {
    error.value = 'Não foi possível carregar os usuários.'
  } finally {
    loading.value = false
  }
}

function resetForm(): void {
  editingUser.value = null
  form.name = ''
  form.email = ''
  form.password = ''
  form.role = 'user'
  form.is_active = true
  feedback.value = ''
}

function editUser(user: AuthUser): void {
  editingUser.value = user
  form.name = user.name
  form.email = user.email
  form.password = ''
  form.role = user.role
  form.is_active = isProtectedAdmin(user) ? true : user.is_active
  feedback.value = ''
}

async function saveUser(): Promise<void> {
  feedback.value = ''
  const payload: UserPayload = {
    name: form.name,
    email: form.email,
    role: editingProtectedUser.value ? 'admin' : form.role,
    is_active: editingProtectedUser.value ? true : form.is_active,
  }
  if (form.password) {
    payload.password = form.password
  }

  try {
    if (editingUser.value) {
      await updateAdminUser(editingUser.value.id, payload)
      feedback.value = 'Usuário atualizado com sucesso.'
    } else {
      await createAdminUser({
        ...payload,
        password: form.password,
      })
      feedback.value = 'Usuário criado com sucesso.'
    }
    resetForm()
    await loadUsers()
  } catch {
    feedback.value = 'Não foi possível salvar o usuário.'
  }
}

async function toggleStatus(user: AuthUser): Promise<void> {
  if (isProtectedAdmin(user)) {
    feedback.value = 'O administrador supremo nao pode ser desativado.'
    return
  }
  try {
    await updateAdminUserStatus(user.id, !user.is_active)
    await loadUsers()
  } catch {
    feedback.value = 'Não foi possível alterar o status do usuário.'
  }
}

async function removeUser(user: AuthUser): Promise<void> {
  if (isProtectedAdmin(user)) {
    feedback.value = 'O administrador supremo nao pode ser removido.'
    return
  }
  if (user.id === currentUser.value?.id) {
    feedback.value = 'Não é possível remover o próprio usuário autenticado.'
    return
  }
  const confirmed = window.confirm(`Remover definitivamente o usuário ${user.email}?`)
  if (!confirmed) {
    return
  }
  try {
    await deleteAdminUser(user.id)
    feedback.value = 'Usuário removido com sucesso.'
    if (editingUser.value?.id === user.id) {
      resetForm()
    }
    await loadUsers()
  } catch {
    feedback.value = 'Não foi possível remover o usuário.'
  }
}

onMounted(loadUsers)
</script>

<style scoped>
.field {
  @apply mt-2 h-10 w-full rounded-md border border-slate-800 bg-surface-900 px-3 text-sm text-slate-100 placeholder:text-slate-600 disabled:cursor-not-allowed disabled:opacity-60;
}
</style>
