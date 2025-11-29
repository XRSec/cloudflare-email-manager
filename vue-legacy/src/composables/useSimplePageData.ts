// 简化的页面数据管理 Composable
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { cacheService, pageRefreshManager } from './cache'
import { getPageConfig, generateCacheKey } from './pageConfig'
import { apiService, adminApiService } from './api'

// 页面数据状态接口
export interface PageDataState {
  data: any  // 原始API响应数据
  loading: boolean
  error: string | null
  pagination: {
    page: number
    pageSize: number
    total: number  // 总数量
  }
  search: {
    query: string
    filters: Record<string, any>
  }
}

// API 响应格式接口
export interface ApiResponse<T = any> {
  data?: T[]
  items?: T[]
  total?: number
  page?: number
  pageSize?: number
}

// 简化的页面数据管理 Hook
export function useSimplePageData(routeName: string) {
  // 获取页面配置
  const config = getPageConfig(routeName)
  if (!config) {
    throw new Error(`No configuration found for route: ${routeName}`)
  }

  // 响应式状态
  const state = ref<PageDataState>({
    data: null,
    loading: false,
    error: null,
    pagination: {
      page: 1,
      pageSize: 20,
      total: 0
    },
    search: {
      query: '',
      filters: {}
    }
  })

  // 计算属性
  const pageTitle = computed(() => config.ui.title)
  const pageIcon = computed(() => config.ui.icon)
  const showSearch = computed(() => config.ui.showSearch || false)
  const showActions = computed(() => config.ui.showActions || false)
  const hasData = computed(() => {
    const data = state.value.data
    return data && ((data.items && data.items.length > 0) || (data.data && data.data.length > 0) || (Array.isArray(data) && data.length > 0))
  })
  const isEmpty = computed(() => !state.value.loading && !hasData.value)

  // 获取 API 服务实例
  const getApiService = () => {
    return routeName.startsWith('admin-') ? adminApiService : apiService
  }

  // 生成缓存键
  const getCacheKey = () => {
    const params = {
      page: state.value.pagination.page,
      pageSize: state.value.pagination.pageSize,
      query: state.value.search.query,
      ...state.value.search.filters
    }
    return generateCacheKey(routeName, JSON.stringify(params))
  }

  // 加载数据
  const loadData = async (forceRefresh = false) => {
    if (state.value.loading) return

    state.value.loading = true
    state.value.error = null

    try {
      const cacheKey = getCacheKey()

      // 如果强制刷新，清除缓存
      if (forceRefresh) {
        cacheService.delete(cacheKey)
      }

      // 尝试从缓存获取
      const cached = cacheService.get(cacheKey)
      if (cached && !forceRefresh) {
        console.log(`Cache hit for ${routeName}`)
        state.value.data = cached
        state.value.loading = false
        return
      }

      // 缓存未命中，调用 API
      console.log(`Cache miss for ${routeName}, calling API`)
      const api = getApiService()
      const method = config.api.method as keyof typeof api

      if (typeof api[method] !== 'function') {
        throw new Error(`API method ${method} not found`)
      }

      const params = {
        page: state.value.pagination.page,
        pageSize: state.value.pagination.pageSize,
        query: state.value.search.query,
        ...state.value.search.filters,
        ...config.api.params
      }

      const response = await (api[method] as any)(params)

      // 直接保存原始响应数据，让前端组件自己处理
      state.value.data = response

      // 简化缓存，直接存储响应数据
      cacheService.set(cacheKey, state.value.data, config.cache.ttl || 300000)

    } catch (error: any) {
      console.error(`Error loading data for ${routeName}:`, error)
      state.value.error = error.message || '加载数据失败'
    } finally {
      state.value.loading = false
    }
  }

  // 刷新数据
  const refreshData = () => loadData(true)

  // 搜索处理
  const handleSearch = (query: string) => {
    state.value.search.query = query
    state.value.pagination.page = 1 // 重置到第一页
    loadData(true)
  }

  // 分页处理
  const handlePageChange = (page: number) => {
    state.value.pagination.page = page
    loadData()
  }

  // 筛选处理
  const handleFilter = (filters: Record<string, any>) => {
    state.value.search.filters = { ...filters }
    state.value.pagination.page = 1 // 重置到第一页
    loadData(true)
  }

  // 清除搜索和筛选
  const clearSearch = () => {
    state.value.search.query = ''
    state.value.search.filters = {}
    state.value.pagination.page = 1
    loadData(true)
  }

  // 页面刷新处理函数
  const pageRefreshHandler = async () => {
    await refreshData()
  }

  // 生命周期管理
  onMounted(() => {
    // 注册页面刷新处理函数
    pageRefreshManager.registerPageRefresh(routeName, pageRefreshHandler)

    // 初始加载数据
    loadData()
  })

  onUnmounted(() => {
    // 注销页面刷新处理函数
    pageRefreshManager.unregisterPageRefresh(routeName)
  })

  return {
    // 状态
    state: readonly(state),
    data: computed(() => state.value.data),
    loading: computed(() => state.value.loading),
    error: computed(() => state.value.error),
    pagination: computed(() => state.value.pagination),
    search: computed(() => state.value.search),

    // 分页相关计算属性
    total: computed(() => state.value.pagination.total),
    currentPage: computed(() => state.value.pagination.page),
    pageSize: computed(() => state.value.pagination.pageSize),
    searchKeyword: computed(() => state.value.search.query),

    // 计算属性
    pageTitle,
    pageIcon,
    showSearch,
    showActions,
    hasData,
    isEmpty,

    // 方法
    loadData,
    refreshData,
    handleSearch,
    handlePageChange,
    handleFilter,
    clearSearch,

    // 兼容性方法
    setSearchKeyword: (keyword: string) => {
      state.value.search.query = keyword
    }
  }
}

// 只读包装器
function readonly<T extends object>(obj: T): T {
  return new Proxy(obj, {
    set() {
      console.warn('Attempted to modify readonly state')
      return false
    }
  })
}
