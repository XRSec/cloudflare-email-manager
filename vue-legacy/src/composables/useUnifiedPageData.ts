/**
 * 统一页面数据管理 Hook
 * 基于路由API缓存映射器的页面数据管理
 */

import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useRoute } from 'vue-router'
import { useRouteApiCacheMapper } from './routeApiCacheMapper'
import { usePageRefreshRegistry, useGlobalRefreshEventListener } from './globalRefreshManager'

// 页面数据状态
interface PageDataState {
  data: any
  loading: boolean
  error: string | null
  lastUpdated: Date | null
}

// 统一页面数据管理 Hook
export function useUnifiedPageData(customParams?: any) {
  const route = useRoute()
  const { callApiMethod, isSupportedRoute, hasPermission, getRouteInfo } = useRouteApiCacheMapper()
  const { registerPageRefresh, unregisterPageRefresh } = usePageRefreshRegistry()
  const { addGlobalRefreshListener, removeGlobalRefreshListener } = useGlobalRefreshEventListener()

  // 页面数据状态
  const pageData = ref<PageDataState>({
    data: null,
    loading: false,
    error: null,
    lastUpdated: null
  })

  // 当前路由信息
  const routeInfo = computed(() => getRouteInfo())

  // 是否支持统一管理
  const isSupported = computed(() => isSupportedRoute.value)

  // 是否有权限
  const hasAccess = computed(() => hasPermission.value)

  // 加载数据
  const loadData = async (forceRefresh = false, params?: any) => {
    if (pageData.value.loading) return

    pageData.value.loading = true
    pageData.value.error = null

    try {
      const finalParams = { ...customParams, ...params }

      if (isSupported.value && hasAccess.value) {
        console.log('📋 使用统一管理器加载数据')
        const response = await callApiMethod(finalParams, forceRefresh)
        pageData.value.data = response
      } else {
        console.warn('当前路由不支持统一管理或权限不足')
        pageData.value.error = '当前路由不支持统一管理或权限不足'
      }

      pageData.value.lastUpdated = new Date()
    } catch (error) {
      console.error('加载数据失败:', error)
      pageData.value.error = error instanceof Error ? error.message : String(error)
    } finally {
      pageData.value.loading = false
    }
  }

  // 刷新数据
  const refreshData = async (params?: any) => {
    await loadData(true, params)
  }

  // 页面级刷新方法
  const pageRefresh = async () => {
    console.log('🔄 页面级刷新触发')
    await refreshData()
  }

  // 全局刷新事件处理
  const handleGlobalRefresh = (event: CustomEvent) => {
    console.log('🌍 收到全局刷新事件', event.detail)
    refreshData()
  }

  // 页面初始化
  onMounted(() => {
    // 注册页面级刷新方法
    registerPageRefresh(pageRefresh)

    // 监听全局刷新事件
    addGlobalRefreshListener(handleGlobalRefresh)

    // 初始加载数据
    loadData()
  })

  // 页面卸载
  onUnmounted(() => {
    // 注销页面级刷新方法
    unregisterPageRefresh()

    // 移除全局刷新事件监听
    removeGlobalRefreshListener(handleGlobalRefresh)
  })

  return {
    // 状态
    pageData: computed(() => pageData.value),
    routeInfo,
    isSupported,
    hasAccess,

    // 方法
    loadData,
    refreshData,
    pageRefresh
  }
}

// 简化的页面数据管理 Hook（适用于简单页面）
export function useSimplePageData() {
  const { pageData, routeInfo, isSupported, hasAccess, loadData, refreshData } = useUnifiedPageData()

  return {
    // 状态
    data: computed(() => pageData.value.data),
    loading: computed(() => pageData.value.loading),
    error: computed(() => pageData.value.error),
    lastUpdated: computed(() => pageData.value.lastUpdated),
    routeInfo,
    isSupported,
    hasAccess,

    // 方法
    loadData,
    refreshData
  }
}

// 分页数据管理 Hook
export function usePaginatedPageData(initialPage = 1, initialLimit = 20) {
  const currentPage = ref(initialPage)
  const pageSize = ref(initialLimit)

  const { pageData, routeInfo, isSupported, hasAccess, loadData, refreshData } = useUnifiedPageData({
    page: currentPage.value,
    limit: pageSize.value
  })

  // 分页信息
  const pagination = computed(() => {
    const data = pageData.value.data
    if (!data || !data.data) return null

    return {
      total: data.data.total || 0,
      page: currentPage.value,
      limit: pageSize.value,
      totalPages: Math.ceil((data.data.total || 0) / pageSize.value)
    }
  })

  // 切换页面
  const changePage = async (page: number) => {
    currentPage.value = page
    await loadData(false, { page, limit: pageSize.value })
  }

  // 改变页面大小
  const changePageSize = async (limit: number) => {
    pageSize.value = limit
    currentPage.value = 1 // 重置到第一页
    await loadData(false, { page: 1, limit })
  }

  return {
    // 状态
    data: computed(() => pageData.value.data),
    loading: computed(() => pageData.value.loading),
    error: computed(() => pageData.value.error),
    lastUpdated: computed(() => pageData.value.lastUpdated),
    routeInfo,
    isSupported,
    hasAccess,
    pagination,
    currentPage: computed(() => currentPage.value),
    pageSize: computed(() => pageSize.value),

    // 方法
    loadData,
    refreshData,
    changePage,
    changePageSize
  }
}
