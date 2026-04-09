/**
 * 统一页面数据管理 Hook
 * 基于路由API缓存映射器的页面数据管理
 */

import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useRouteApiManager } from './routeApiManager'
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
  const { callApiMethod, isSupportedRoute, hasPermission, getRouteInfo } = useRouteApiManager()
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

  // 全局刷新完成事件处理
  // 当全局刷新完成后，页面组件需要重新加载数据以更新显示
  const handleGlobalRefreshComplete = async (event: CustomEvent) => {
    console.log('🎉 收到全局刷新完成事件', event.detail)

    if (!isSupported.value || !hasAccess.value) {
      console.log('⚠️ 当前路由不支持或无权限，跳过数据加载')
      return
    }

    console.log('📊 重新加载数据以更新页面显示')
    // 从缓存中重新加载数据（全局刷新已经更新了缓存）
    await loadData(false) // 不强制刷新，使用缓存中的最新数据
    console.log('✅ 页面数据已更新')
  }

  // 旧的全局刷新事件处理（保留用于不支持统一管理的路由）
  const handleGlobalRefresh = async (event: CustomEvent) => {
    console.log('🌍 收到全局刷新事件', event.detail)

    // 只有不支持统一管理的路由才需要响应此事件
    if (isSupported.value && hasAccess.value) {
      console.log('📋 路由支持统一管理，等待 global:refresh:complete 事件')
      return
    }

    console.log('🔧 路由不支持统一管理，通过强制刷新获取数据')
    await refreshData() // 强制刷新
  }

  // 页面初始化
  onMounted(() => {
    // 注册页面级刷新方法
    registerPageRefresh(pageRefresh)

    // 监听全局刷新事件（旧事件，用于不支持统一管理的路由）
    addGlobalRefreshListener(handleGlobalRefresh)

    // 监听全局刷新完成事件（新事件，用于支持统一管理的路由）
    window.addEventListener('global:refresh:complete', handleGlobalRefreshComplete as unknown as EventListener)
    console.log('👂 已添加 global:refresh:complete 事件监听器')

    // 初始加载数据
    loadData()
  })

  // 页面卸载
  onUnmounted(() => {
    // 注销页面级刷新方法
    unregisterPageRefresh()

    // 移除全局刷新事件监听
    removeGlobalRefreshListener(handleGlobalRefresh)

    // 移除全局刷新完成事件监听
    window.removeEventListener('global:refresh:complete', handleGlobalRefreshComplete as unknown as EventListener)
    console.log('🗑️ 已移除 global:refresh:complete 事件监听器')
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

const sanitizeQueryParams = (params: Record<string, any> = {}) => {
  return Object.fromEntries(
    Object.entries(params).filter(([_, value]) => value !== undefined && value !== null && value !== '')
  )
}

// 分页数据管理 Hook
export function usePaginatedPageData(initialPage = 1, initialLimit = 20, initialQueryParams: Record<string, any> = {}) {
  const currentPage = ref(initialPage)
  const pageSize = ref(initialLimit)
  const queryParams = ref<Record<string, any>>(sanitizeQueryParams(initialQueryParams))

  const { pageData, routeInfo, isSupported, hasAccess, loadData, refreshData } = useUnifiedPageData({
    page: currentPage.value,
    limit: pageSize.value,
    ...queryParams.value
  })

  const buildRequestParams = (overrides: Record<string, any> = {}) => {
    const { page, limit, ...restOverrides } = overrides

    return {
      ...queryParams.value,
      ...sanitizeQueryParams(restOverrides),
      page: page ?? currentPage.value,
      limit: limit ?? pageSize.value
    }
  }

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

  const loadPaginatedData = async (forceRefresh = false, overrides: Record<string, any> = {}) => {
    if (typeof overrides.page === 'number') {
      currentPage.value = overrides.page
    }

    if (typeof overrides.limit === 'number') {
      pageSize.value = overrides.limit
    }

    await loadData(forceRefresh, buildRequestParams(overrides))
  }

  const refreshPaginatedData = async (params: Record<string, any> = {}) => {
    await refreshData(buildRequestParams(params))
  }

  // 切换页面
  const changePage = async (page: number) => {
    currentPage.value = page
    await loadPaginatedData(false, { page })
  }

  // 改变页面大小
  const changePageSize = async (limit: number) => {
    pageSize.value = limit
    currentPage.value = 1 // 重置到第一页
    await loadPaginatedData(false, { page: 1, limit })
  }

  const setQueryParams = async (params: Record<string, any> = {}, options: { forceRefresh?: boolean; resetPage?: boolean } = {}) => {
    const { forceRefresh = false, resetPage = true } = options
    queryParams.value = sanitizeQueryParams(params)

    if (resetPage) {
      currentPage.value = 1
    }

    await loadPaginatedData(forceRefresh, {
      page: currentPage.value,
      limit: pageSize.value
    })
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
    queryParams: computed(() => queryParams.value),

    // 方法
    loadData: loadPaginatedData,
    refreshData: refreshPaginatedData,
    changePage,
    changePageSize,
    setQueryParams
  }
}
