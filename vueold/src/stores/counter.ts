import { ref, computed, readonly } from 'vue'
import { createGlobalState } from '@vueuse/core'

export const useCounterStore = createGlobalState(() => {
  const count = ref(0)
  const doubleCount = computed(() => count.value * 2)
  function increment() {
    count.value++
  }

  return {
    count: readonly(count),
    doubleCount,
    increment
  }
})
