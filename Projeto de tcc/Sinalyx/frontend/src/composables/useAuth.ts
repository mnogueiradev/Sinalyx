import { computed, ref } from 'vue'

import {
  getCurrentUser,
  loginUser,
} from '@/services/api'
import type { AuthUser } from '@/types/api'

const TOKEN_KEY = 'sinalyx_access_token'
const USER_KEY = 'sinalyx_user'

function readStoredUser(): AuthUser | null {
  const raw = window.localStorage.getItem(USER_KEY)
  if (!raw) {
    return null
  }
  try {
    return JSON.parse(raw) as AuthUser
  } catch {
    window.localStorage.removeItem(USER_KEY)
    return null
  }
}

const token = ref(window.localStorage.getItem(TOKEN_KEY) ?? '')
const currentUser = ref<AuthUser | null>(readStoredUser())
const loadingUser = ref(false)

function persistSession(accessToken: string, user: AuthUser): void {
  token.value = accessToken
  currentUser.value = user
  window.localStorage.setItem(TOKEN_KEY, accessToken)
  window.localStorage.setItem(USER_KEY, JSON.stringify(user))
}

function clearSession(): void {
  token.value = ''
  currentUser.value = null
  window.localStorage.removeItem(TOKEN_KEY)
  window.localStorage.removeItem(USER_KEY)
}

export function useAuth() {
  const isAuthenticated = computed(() => Boolean(token.value && currentUser.value))
  const isAdmin = computed(() => currentUser.value?.role === 'admin')

  async function login(email: string, password: string): Promise<void> {
    const response = await loginUser(email, password)
    persistSession(response.access_token, response.user)
  }

  async function loadMe(): Promise<AuthUser | null> {
    if (!token.value) {
      clearSession()
      return null
    }
    loadingUser.value = true
    try {
      const user = await getCurrentUser()
      persistSession(token.value, user)
      return user
    } catch {
      clearSession()
      return null
    } finally {
      loadingUser.value = false
    }
  }

  function logout(): void {
    clearSession()
  }

  return {
    token,
    currentUser,
    loadingUser,
    isAuthenticated,
    isAdmin,
    login,
    logout,
    loadMe,
  }
}

