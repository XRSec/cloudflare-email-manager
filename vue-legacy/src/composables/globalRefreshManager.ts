/**
 * 全局刷新管理器
 * 统一管理所有页面的刷新逻辑，根据当前路由自动调用对应的API
 */

import { ref, computed } from 'vue'
import { useRoute } from 'vue-router'
import { useRouteApiCacheMapper, useGlobalRefreshManager } from './routeApiCacheMapper'
import { useAuthStore } from './stores'

// 刷新状态管理
const refreshing = ref(false)
const lastRefreshTime = ref<Date | null>(null)
const refreshHistory = ref<Array<{
  routeName: string
  timestamp: Date
  success: boolean
  error?: string
}>>([])

// 全局刷新管理器
export function useUnifiedGlobalRefreshManager() {
  const route = useRoute()
  const authStore = useAuthStore()
  const { isSupportedRoute, hasPermission, getRouteInfo } = useRouteApiCacheMapper()
  const { refreshCurrentPage } = useGlobalRefreshManager()

  // 当前刷新状态
  const isRefreshing = computed(() => refreshing.value)

  // 上次刷新时间
  const lastRefresh = computed(() => lastRefreshTime.value)

  // 刷新历史
  const refreshHistoryList = computed(() => refreshHistory.value)

  // 执行全局刷新
  const executeGlobalRefresh = async (customParams?: any) => {
    if (refreshing.value) {
      console.log('🔄 刷新正在进行中，跳过重复请求')
      return null
    }

    refreshing.value = true
    const startTime = new Date()

    try {
      console.log('🌍 开始全局刷新')

      // 先触发全局刷新事件
      window.dispatchEvent(new CustomEvent('global:refresh', {
        detail: {
          routeName: route.name,
          timestamp: startTime,
          customParams
        }
      }))

      let result = null

      // 检查是否支持统一管理
      if (isSupportedRoute.value && hasPermission.value) {
        console.log('📋 使用统一刷新管理器')
        result = await refreshCurrentPage(customParams)
      } else {
        console.log('🔧 使用页面级刷新方法')
        // 调用页面级刷新方法（如果存在）
        if (window.refreshCurrentPage && typeof window.refreshCurrentPage === 'function') {
          // 避免递归调用，检查是否是同一个函数
          if (window.refreshCurrentPage !== executeGlobalRefresh) {
            result = await window.refreshCurrentPage()
          }
        }
      }

      // 记录刷新历史
      const endTime = new Date()
      refreshHistory.value.unshift({
        routeName: route.name as string,
        timestamp: endTime,
        success: true
      })

      // 保持历史记录不超过50条
      if (refreshHistory.value.length > 50) {
        refreshHistory.value = refreshHistory.value.slice(0, 50)
      }

      lastRefreshTime.value = endTime

      console.log(`✅ 全局刷新完成，耗时: ${endTime.getTime() - startTime.getTime()}ms`)
      return result

    } catch (error) {
      console.error('❌ 全局刷新失败:', error)

      // 记录失败历史
      refreshHistory.value.unshift({
        routeName: route.name as string,
        timestamp: new Date(),
        success: false,
        error: error instanceof Error ? error.message : String(error)
      })

      throw error
    } finally {
      refreshing.value = false
    }
  }

  // 获取当前页面刷新信息
  const getCurrentPageRefreshInfo = () => {
    const routeInfo = getRouteInfo()
    return {
      routeName: route.name as string,
      isSupported: isSupportedRoute.value,
      hasPermission: hasPermission.value,
      routeInfo,
      lastRefresh: lastRefreshTime.value,
      isRefreshing: refreshing.value
    }
  }

  // 清除刷新历史
  const clearRefreshHistory = () => {
    refreshHistory.value = []
    console.log('🗑️ 刷新历史已清除')
  }

  // 获取刷新统计
  const getRefreshStats = () => {
    const total = refreshHistory.value.length
    const successful = refreshHistory.value.filter(item => item.success).length
    const failed = total - successful

    return {
      total,
      successful,
      failed,
      successRate: total > 0 ? (successful / total * 100).toFixed(1) + '%' : '0%'
    }
  }

  return {
    // 状态
    isRefreshing,
    lastRefresh,
    refreshHistoryList,

    // 方法
    executeGlobalRefresh,
    getCurrentPageRefreshInfo,
    clearRefreshHistory,
    getRefreshStats
  }
}

// 页面级刷新注册器
export function usePageRefreshRegistry() {
  // 注册页面级刷新方法
  const registerPageRefresh = (refreshFunction: () => Promise<any> | void) => {
    window.refreshCurrentPage = refreshFunction
    console.log('📝 页面级刷新方法已注册')
  }

  // 注销页面级刷新方法
  const unregisterPageRefresh = () => {
    if (window.refreshCurrentPage) {
      delete window.refreshCurrentPage
      console.log('🗑️ 页面级刷新方法已注销')
    }
  }

  // 检查是否有页面级刷新方法
  const hasPageRefreshMethod = () => {
    return window.refreshCurrentPage && typeof window.refreshCurrentPage === 'function'
  }

  return {
    registerPageRefresh,
    unregisterPageRefresh,
    hasPageRefreshMethod
  }
}

// 全局刷新事件监听器
export function useGlobalRefreshEventListener() {
  // 监听全局刷新事件
  const addGlobalRefreshListener = (callback: (event: CustomEvent) => void) => {
    window.addEventListener('global:refresh', callback as EventListener)
    console.log('👂 全局刷新事件监听器已添加')
  }

  // 移除全局刷新事件监听器
  const removeGlobalRefreshListener = (callback: (event: CustomEvent) => void) => {
    window.removeEventListener('global:refresh', callback as EventListener)
    console.log('🗑️ 全局刷新事件监听器已移除')
  }

  return {
    addGlobalRefreshListener,
    removeGlobalRefreshListener
  }
}

// 导出全局状态供其他组件使用
export { refreshing, lastRefreshTime, refreshHistory }
