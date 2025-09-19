/**
 * 加载状态组合式函数
 */

import { computed } from 'vue'
import { useLoadingStore } from '@/stores/loading'

export function useLoading(key?: string) {
  const loadingStore = useLoadingStore()

  // 如果没有提供 key，使用全局加载
  if (!key) {
    return {
      loading: computed(() => loadingStore.globalLoading),
      text: computed(() => loadingStore.globalLoadingText),
      setLoading: (loading: boolean, text = '加载中...') => {
        loadingStore.setGlobalLoading(loading, text)
      }
    }
  }

  // 局部加载
  return {
    loading: computed(() => loadingStore.getLocalLoading(key)),
    text: computed(() => loadingStore.getLocalLoadingText(key)),
    setLoading: (loading: boolean, text = '加载中...') => {
      loadingStore.setLocalLoading(key, loading, text)
    }
  }
}

export function usePageLoading() {
  const loadingStore = useLoadingStore()

  return {
    loading: computed(() => loadingStore.pageLoading),
    text: computed(() => loadingStore.pageLoadingText),
    setLoading: (loading: boolean, text = '页面加载中...') => {
      loadingStore.setPageLoading(loading, text)
    }
  }
}

export function useGlobalLoading() {
  const loadingStore = useLoadingStore()

  return {
    loading: computed(() => loadingStore.globalLoading),
    text: computed(() => loadingStore.globalLoadingText),
    setLoading: (loading: boolean, text = '加载中...') => {
      loadingStore.setGlobalLoading(loading, text)
    }
  }
}
