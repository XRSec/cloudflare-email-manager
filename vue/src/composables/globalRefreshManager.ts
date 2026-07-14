/**
 * 全局刷新管理器
 * 统一管理所有页面的刷新逻辑，根据当前路由自动调用对应的API
 */

import { ref, computed } from 'vue'
import { useRoute } from 'vue-router'
import { useRouteApiManager, useRouteGlobalRefreshManager } from './routeApiManager'

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
  const { isSupportedRoute, hasPermission, getRouteInfo } = useRouteApiManager()
  const { executeGlobalRefresh: executeUnifiedRefresh } = useRouteGlobalRefreshManager()

  // 当前刷新状态
  const isRefreshing = computed(() => refreshing.value)

  // 上次刷新时间
  const lastRefresh = computed(() => lastRefreshTime.value)

  // 刷新历史
  const refreshHistoryList = computed(() => refreshHistory.value)

  // 执行全局刷新
  const executeGlobalRefresh = async (customParams?: any) => {
    if (refreshing.value) {
      return null
    }

    refreshing.value = true
    const startTime = new Date()

    try {
      let result = null
      let handledByPageRefresh = false

      const pageRefresh = window.refreshCurrentPage
      if (pageRefresh && typeof pageRefresh === 'function' && pageRefresh !== executeGlobalRefresh) {
        handledByPageRefresh = true
        result = pageRefresh()
      } else if (isSupportedRoute.value && hasPermission.value) {
        // 检查是否支持统一管理
        // 支持统一管理的路由，直接调用刷新，更新缓存
        result = await executeUnifiedRefresh()
      } else {
        // 不支持统一管理的路由，先触发事件，然后调用页面级刷新方法
        window.dispatchEvent(new CustomEvent('global:refresh', {
          detail: {
            routeName: route.name,
            timestamp: startTime,
            customParams
          }
        }))

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

      // 🔥 重要：触发刷新完成事件，通知所有页面组件重新加载数据
      // 对于支持统一管理的路由，缓存已更新，页面需要重新加载数据以更新显示
      if (!handledByPageRefresh) {
        window.dispatchEvent(new CustomEvent('global:refresh:complete', {
          detail: {
            routeName: route.name,
            timestamp: endTime,
            duration: endTime.getTime() - startTime.getTime(),
            result
          }
        }))
      }

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
  }

  // 注销页面级刷新方法
  const unregisterPageRefresh = () => {
    if (window.refreshCurrentPage) {
      delete window.refreshCurrentPage
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
  }

  // 移除全局刷新事件监听器
  const removeGlobalRefreshListener = (callback: (event: CustomEvent) => void) => {
    window.removeEventListener('global:refresh', callback as EventListener)
  }

  // 监听全局刷新完成事件
  const addGlobalRefreshCompleteListener = (callback: (event: CustomEvent) => void) => {
    window.addEventListener('global:refresh:complete', callback as EventListener)
  }

  // 移除全局刷新完成事件监听器
  const removeGlobalRefreshCompleteListener = (callback: (event: CustomEvent) => void) => {
    window.removeEventListener('global:refresh:complete', callback as EventListener)
  }

  return {
    addGlobalRefreshListener,
    removeGlobalRefreshListener,
    addGlobalRefreshCompleteListener,
    removeGlobalRefreshCompleteListener
  }
}

// 导出全局状态供其他组件使用
export { refreshing, lastRefreshTime, refreshHistory }
