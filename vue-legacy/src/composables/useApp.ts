// 应用状态管理组合式函数
import { ref, computed, readonly } from 'vue'
import type { AppStage } from '@/types'

// 应用阶段状态
const currentStage = ref<AppStage>('initial-loading')
const loadingText = ref('正在初始化系统...')

// 全局加载状态
const globalLoading = ref(false)
const globalLoadingText = ref('')

export const useApp = () => {
  // 阶段管理
  const setStage = (stage: AppStage) => {
    currentStage.value = stage
  }

  const setLoadingText = (text: string) => {
    loadingText.value = text
  }

  // 全局加载管理
  const showGlobalLoading = (text: string = '加载中...') => {
    globalLoading.value = true
    globalLoadingText.value = text
  }

  const hideGlobalLoading = () => {
    globalLoading.value = false
    globalLoadingText.value = ''
  }

  // 计算属性
  const isInitialLoading = computed(() => currentStage.value === 'initial-loading')
  const isAuthCheck = computed(() => currentStage.value === 'auth-check')
  const isLogin = computed(() => currentStage.value === 'login')
  const isMainPreload = computed(() => currentStage.value === 'main-preload')
  const isMain = computed(() => currentStage.value === 'main')

  return {
    // 状态
    currentStage: readonly(currentStage),
    loadingText: readonly(loadingText),
    globalLoading: readonly(globalLoading),
    globalLoadingText: readonly(globalLoadingText),

    // 方法
    setStage,
    setLoadingText,
    showGlobalLoading,
    hideGlobalLoading,

    // 计算属性
    isInitialLoading,
    isAuthCheck,
    isLogin,
    isMainPreload,
    isMain
  }
}
