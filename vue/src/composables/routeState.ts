// 路由状态管理 - 基于路由的现代化状态管理
import { ref, computed, watch, readonly } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { smartCache, CacheStatus } from './smartCache'

// 页面状态枚举
export enum PageState {
  INITIAL = 'initial',       // 初始状态
  LOADING = 'loading',       // 加载中
  LOADED = 'loaded',         // 已加载
  ERROR = 'error',           // 错误状态
  REFRESHING = 'refreshing'  // 刷新中
}

// 页面配置接口
interface PageConfig {
  title: string
  showRefreshButton?: boolean
  showBackButton?: boolean
  autoRefresh?: boolean
  refreshInterval?: number
  keepAlive?: boolean
  preload?: boolean
  meta?: Record<string, any>
}

// 页面状态接口
interface PageStateData {
  state: PageState
  error: Error | null
  lastUpdated: number
  refreshCount: number
  data?: any
}

// 路由配置映射
const ROUTE_CONFIGS: Record<string, PageConfig> = {
  'dashboard': {
    title: '仪表板',
    showRefreshButton: true,
    autoRefresh: true,
    refreshInterval: 30000,
    keepAlive: true,
    preload: true
  },
  'my-emails': {
    title: '我的邮件',
    showRefreshButton: true,
    autoRefresh: true,
    refreshInterval: 15000,
    keepAlive: true
  },
  'my-mailboxes': {
    title: '我的邮箱',
    showRefreshButton: true,
    keepAlive: true
  },
  'forward-rules': {
    title: '转发规则',
    showRefreshButton: true,
    keepAlive: true
  },
  'personal-settings': {
    title: '个人设置',
    showRefreshButton: false,
    keepAlive: true
  },
  'admin-users': {
    title: '用户管理',
    showRefreshButton: true,
    autoRefresh: false,
    keepAlive: true
  },
  'all-emails': {
    title: '全部邮件',
    showRefreshButton: true,
    autoRefresh: true,
    refreshInterval: 20000,
    keepAlive: true
  },
  'mailbox-management': {
    title: '邮箱管理',
    showRefreshButton: true,
    keepAlive: true
  },
  'admin-applications': {
    title: '申请审核',
    showRefreshButton: true,
    autoRefresh: true,
    refreshInterval: 30000,
    keepAlive: true
  },
  'admin-security-overview': {
    title: '安全概览',
    showRefreshButton: true,
    autoRefresh: true,
    refreshInterval: 60000,
    keepAlive: true
  },
  'system-settings': {
    title: '系统设置',
    showRefreshButton: false,
    keepAlive: true
  },
  'debug': {
    title: '调试模式',
    showRefreshButton: true,
    keepAlive: false
  }
}

class RouteStateManager {
  private pageStates = new Map<string, PageStateData>()
  private refreshTimers = new Map<string, NodeJS.Timeout>()
  private pageLoadPromises = new Map<string, Promise<any>>()
  private preloadQueue = new Set<string>()

  // 当前路由状态

  constructor() {
    // 监听路由变化
    this.setupRouteWatcher()

    // 监听页面可见性变化
    document.addEventListener('visibilitychange', () => {
      if (document.visibilityState === 'visible') {
        this.handlePageVisible()
      } else {
        this.handlePageHidden()
      }
    })

    // 清理定时器
    window.addEventListener('beforeunload', () => {
      this.cleanup()
    })
  }

  // 获取页面配置
  getPageConfig(routeName: string): PageConfig {
    return ROUTE_CONFIGS[routeName] || {
      title: routeName,
      showRefreshButton: true,
      keepAlive: false
    }
  }

  // 获取页面状态
  getPageState(routeName: string): PageStateData {
    if (!this.pageStates.has(routeName)) {
      this.pageStates.set(routeName, {
        state: PageState.INITIAL,
        error: null,
        lastUpdated: 0,
        refreshCount: 0
      })
    }
    return this.pageStates.get(routeName)!
  }

  // 设置页面状态
  setPageState(routeName: string, updates: Partial<PageStateData>): void {
    const current = this.getPageState(routeName)
    const newState = { ...current, ...updates }
    this.pageStates.set(routeName, newState)

    console.log(`📄 页面状态更新: ${routeName}`, newState)
  }

  // 设置页面加载中
  setPageLoading(routeName: string): void {
    this.setPageState(routeName, {
      state: PageState.LOADING,
      error: null
    })
  }

  // 设置页面已加载
  setPageLoaded(routeName: string, data?: any): void {
    this.setPageState(routeName, {
      state: PageState.LOADED,
      error: null,
      lastUpdated: Date.now(),
      data
    })
  }

  // 设置页面错误
  setPageError(routeName: string, error: Error): void {
    this.setPageState(routeName, {
      state: PageState.ERROR,
      error
    })
  }

  // 设置页面刷新中
  setPageRefreshing(routeName: string): void {
    const current = this.getPageState(routeName)
    this.setPageState(routeName, {
      state: PageState.REFRESHING,
      refreshCount: current.refreshCount + 1
    })
  }

  // 加载页面数据
  async loadPageData(
    routeName: string,
    loader: () => Promise<any>,
    forceRefresh = false
  ): Promise<any> {
    // 如果已经在加载中，返回现有的 Promise
    if (!forceRefresh && this.pageLoadPromises.has(routeName)) {
      return this.pageLoadPromises.get(routeName)
    }

    // 检查缓存
    if (!forceRefresh) {
      const cacheKey = smartCache.generateCacheKey(routeName)
      const cached = smartCache.get(cacheKey)

      if (cached.status === CacheStatus.FRESH) {
        this.setPageLoaded(routeName, cached.data)
        return cached.data
      }

      // 使用过期数据，但在后台刷新
      if (cached.status === CacheStatus.STALE && cached.data) {
        this.setPageLoaded(routeName, cached.data)
        // 后台刷新
        this.loadPageData(routeName, loader, true).catch(console.error)
        return cached.data
      }
    }

    // 设置加载状态
    if (forceRefresh) {
      this.setPageRefreshing(routeName)
    } else {
      this.setPageLoading(routeName)
    }

    // 创建加载 Promise
    const loadPromise = loader()
      .then(data => {
        this.setPageLoaded(routeName, data)

        // 更新缓存
        const cacheKey = smartCache.generateCacheKey(routeName)
        smartCache.set(cacheKey, data, routeName)

        return data
      })
      .catch(error => {
        this.setPageError(routeName, error)
        throw error
      })
      .finally(() => {
        this.pageLoadPromises.delete(routeName)
      })

    this.pageLoadPromises.set(routeName, loadPromise)
    return loadPromise
  }

  // 刷新页面数据
  async refreshPageData(routeName: string, loader: () => Promise<any>): Promise<any> {
    return this.loadPageData(routeName, loader, true)
  }

  // 预加载页面数据
  async preloadPageData(routeName: string, loader: () => Promise<any>): Promise<void> {
    if (this.preloadQueue.has(routeName)) return

    this.preloadQueue.add(routeName)

    try {
      // 使用 requestIdleCallback 在空闲时预加载
      if ('requestIdleCallback' in window) {
        await new Promise(resolve => {
          window.requestIdleCallback(() => {
            this.loadPageData(routeName, loader, false)
              .then(resolve)
              .catch(resolve)
          })
        })
      } else {
        // 延迟预加载
        await new Promise(resolve => setTimeout(resolve, 100))
        await this.loadPageData(routeName, loader, false)
      }
    } catch (error) {
      console.warn(`预加载失败: ${routeName}`, error)
    } finally {
      this.preloadQueue.delete(routeName)
    }
  }

  // 设置自动刷新
  setupAutoRefresh(routeName: string, loader: () => Promise<any>): void {
    const config = this.getPageConfig(routeName)

    if (!config.autoRefresh || !config.refreshInterval) return

    // 清除现有定时器
    this.clearAutoRefresh(routeName)

    // 设置新定时器
    const timer = setInterval(() => {
      // 只在页面可见时自动刷新
      if (document.visibilityState === 'visible') {
        this.refreshPageData(routeName, loader).catch(console.error)
      }
    }, config.refreshInterval)

    this.refreshTimers.set(routeName, timer)
    console.log(`⏰ 自动刷新已设置: ${routeName} (${config.refreshInterval}ms)`)
  }

  // 清除自动刷新
  clearAutoRefresh(routeName: string): void {
    const timer = this.refreshTimers.get(routeName)
    if (timer) {
      clearInterval(timer)
      this.refreshTimers.delete(routeName)
      console.log(`⏰ 自动刷新已清除: ${routeName}`)
    }
  }

  // 页面可见时处理
  private handlePageVisible(): void {
    // 恢复所有自动刷新定时器
    this.refreshTimers.forEach((_, routeName) => {
      console.log(`👁️ 页面可见，恢复刷新: ${routeName}`)
    })
  }

  // 页面隐藏时处理
  private handlePageHidden(): void {
    console.log('👁️ 页面隐藏，暂停自动刷新')
  }

  // 设置路由监听
  private setupRouteWatcher(): void {
    // 这个会在具体的 composable 中设置
  }

  // 清理资源
  private cleanup(): void {
    this.refreshTimers.forEach(timer => clearInterval(timer))
    this.refreshTimers.clear()
    this.pageLoadPromises.clear()
    this.preloadQueue.clear()
  }

  // 获取所有页面状态统计
  getStats() {
    const stats = {
      totalPages: this.pageStates.size,
      loadingPages: 0,
      loadedPages: 0,
      errorPages: 0,
      refreshingPages: 0,
      autoRefreshPages: this.refreshTimers.size
    }

    this.pageStates.forEach(state => {
      switch (state.state) {
        case PageState.LOADING:
          stats.loadingPages++
          break
        case PageState.LOADED:
          stats.loadedPages++
          break
        case PageState.ERROR:
          stats.errorPages++
          break
        case PageState.REFRESHING:
          stats.refreshingPages++
          break
      }
    })

    return stats
  }
}

// 全局路由状态管理器
export const routeStateManager = new RouteStateManager()

// 页面状态管理 Hook
export function usePageState(routeName?: string) {
  const route = useRoute()

  const currentRouteName = computed(() => routeName || route.name as string)
  const pageConfig = computed(() => routeStateManager.getPageConfig(currentRouteName.value))
  const pageState = computed(() => routeStateManager.getPageState(currentRouteName.value))

  // 页面状态
  const isLoading = computed(() => pageState.value.state === PageState.LOADING)
  const isLoaded = computed(() => pageState.value.state === PageState.LOADED)
  const isError = computed(() => pageState.value.state === PageState.ERROR)
  const isRefreshing = computed(() => pageState.value.state === PageState.REFRESHING)
  const error = computed(() => pageState.value.error)
  const data = computed(() => pageState.value.data)

  // 加载数据
  const loadData = (loader: () => Promise<any>, forceRefresh = false) => {
    return routeStateManager.loadPageData(currentRouteName.value, loader, forceRefresh)
  }

  // 刷新数据
  const refreshData = (loader: () => Promise<any>) => {
    return routeStateManager.refreshPageData(currentRouteName.value, loader)
  }

  // 设置自动刷新
  const setupAutoRefresh = (loader: () => Promise<any>) => {
    routeStateManager.setupAutoRefresh(currentRouteName.value, loader)
  }

  // 清除自动刷新
  const clearAutoRefresh = () => {
    routeStateManager.clearAutoRefresh(currentRouteName.value)
  }

  // 预加载
  const preload = (loader: () => Promise<any>) => {
    return routeStateManager.preloadPageData(currentRouteName.value, loader)
  }

  // 页面切换时清理
  watch(() => route.name, (newRoute, oldRoute) => {
    if (oldRoute && oldRoute !== newRoute) {
      const oldConfig = routeStateManager.getPageConfig(oldRoute as string)
      if (!oldConfig.keepAlive) {
        // 清理不需要保持活跃的页面状态
        routeStateManager.clearAutoRefresh(oldRoute as string)
      }
    }
  })

  return {
    // 状态
    pageConfig: readonly(pageConfig),
    pageState: readonly(pageState),
    isLoading: readonly(isLoading),
    isLoaded: readonly(isLoaded),
    isError: readonly(isError),
    isRefreshing: readonly(isRefreshing),
    error: readonly(error),
    data: readonly(data),

    // 方法
    loadData,
    refreshData,
    setupAutoRefresh,
    clearAutoRefresh,
    preload
  }
}

// 路由导航 Hook
export function useRouteNavigation() {
  const route = useRoute()

  const isTransitioning = ref(false)
  const transitionProgress = ref(0)

  // 刷新当前页面
  const refreshCurrentPage = () => {
    const routeName = route.name as string
    window.dispatchEvent(new CustomEvent('page:refresh', {
      detail: { routeName }
    }))
  }

  return {
    isTransitioning: readonly(isTransitioning),
    transitionProgress: readonly(transitionProgress),
    refreshCurrentPage
  }
}

export default routeStateManager
