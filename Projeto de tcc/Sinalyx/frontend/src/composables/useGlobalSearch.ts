import { computed, ref } from 'vue'

const globalSearch = ref('')

export function useGlobalSearch() {
  const trimmedSearch = computed(() => globalSearch.value.trim())

  return {
    globalSearch,
    trimmedSearch,
  }
}
