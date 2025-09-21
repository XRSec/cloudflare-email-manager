// 全局状态管理 - 基于路径和缓存的统一管理
import { computed } from 'vue'
import { useRoute } from 'vue-router'
import { simpleCache } from './simpleCache'
import { useSystemStore } from './system'

// 全局状态接口
interface GlobalState {
  searchQuery: string
  currentPage: number
  pageSize: number
  sortField: string
  sortOrder: 'asc' | 'desc'
  isDebugMode: boolean
  selectedItems: any[]
}

// 页面配置
interface PageConfig {
  title: string
  icon: string
  hasSearch: boolean
  hasRefresh: boolean
  hasBatchActions: boolean
  defaultPageSize: number
}

// 路由页面配置
const PAGE_CONFIGS: Record<string, PageConfig> = {
  'dashboard': {
    title: '仪表板',
    icon: '🏠',
    hasSearch: false,
    hasRefresh: true,
    hasBatchActions: false,
    defaultPageSize: 20
  },
  'emails': {
    title: '我的邮件',
    icon: '📧',
    hasSearch: true,
    hasRefresh: true,
    hasBatchActions: true,
    defaultPageSize: 20
  },
  'mailboxes': {
    title: '我的邮箱',
    icon: '📮',
    hasSearch: true,
    hasRefresh: true,
    hasBatchActions: false,
    defaultPageSize: 20
  },
  'forward-rules': {
    title: '转发规则',
    icon: '🔄',
    hasSearch: true,
    hasRefresh: true,
    hasBatchActions: true,
    defaultPageSize: 20
  },
  'settings': {
    title: '设置',
    icon: '⚙️',
    hasSearch: false,
    hasRefresh: false,
    hasBatchActions: false,
    defaultPageSize: 20
  },
  'admin-users': {
    title: '用户管理',
    icon: '👥',
    hasSearch: true,
    hasRefresh: true,
    hasBatchActions: true,
    defaultPageSize: 20
  },
  'admin-emails': {
    title: '全部邮件',
    icon: '📨',
    hasSearch: true,
    hasRefresh: true,
    hasBatchActions: true,
    defaultPageSize: 20
  },
  'admin-mailboxes': {
    title: '邮箱管理',
    icon: '📮',
    hasSearch: true,
    hasRefresh: true,
    hasBatchActions: true,
    defaultPageSize: 20
  },
  'admin-applications': {
    title: '申请审核',
    icon: '📋',
    hasSearch: true,
    hasRefresh: true,
    hasBatchActions: true,
    defaultPageSize: 20
  },
  'admin-security-overview': {
    title: '安全概览',
    icon: '🛡️',
    hasSearch: false,
    hasRefresh: true,
    hasBatchActions: false,
    defaultPageSize: 20
  },
  'admin-settings': {
    title: '系统设置',
    icon: '🛠️',
    hasSearch: false,
    hasRefresh: false,
    hasBatchActions: false,
    defaultPageSize: 20
  },
  'debug': {
    title: '调试模式',
    icon: '🐛',
    hasSearch: true,
    hasRefresh: true,
    hasBatchActions: false,
    defaultPageSize: 50
  }
}

class GlobalStateManager {
  private states = new Map<string, GlobalState>()

  // 获取页面状态的缓存键
  private getStateKey(path: string): string {
    return `pageState:${path}`
  }

  // 获取页面状态
  getPageState(path: string): GlobalState {
    const cacheKey = this.getStateKey(path)

    // 尝试从缓存恢复
    const cached = simpleCache.get<GlobalState>(cacheKey)
    if (cached.data) {
      this.states.set(path, cached.data)
      return cached.data
    }

    // 创建默认状态
    const defaultState: GlobalState = {
      searchQuery: '',
      currentPage: 1,
      pageSize: this.getPageConfig(path).defaultPageSize,
      sortField: '',
      sortOrder: 'desc',
      isDebugMode: false, // 将在初始化时从 systemStore 获取
      selectedItems: []
    }

    this.states.set(path, defaultState)
    return defaultState
  }

  // 更新页面状态
  updatePageState(path: string, updates: Partial<GlobalState>): void {
    const current = this.getPageState(path)
    const newState = { ...current, ...updates }

    this.states.set(path, newState)

    // 持久化到缓存
    const cacheKey = this.getStateKey(path)
    simpleCache.set(cacheKey, newState)
  }

  // 获取页面配置
  getPageConfig(routeName: string): PageConfig {
    return PAGE_CONFIGS[routeName] || {
      title: routeName,
      icon: '📄',
      hasSearch: true,
      hasRefresh: true,
      hasBatchActions: false,
      defaultPageSize: 20
    }
  }

  // 清除页面状态
  clearPageState(path: string): void {
    this.states.delete(path)
    const cacheKey = this.getStateKey(path)
    simpleCache.delete(cacheKey)
  }

  // 重置搜索状态
  resetSearch(path: string): void {
    this.updatePageState(path, {
      searchQuery: '',
      currentPage: 1,
      selectedItems: []
    })
  }

  // 获取全局统计
  getStats() {
    return {
      activePages: this.states.size,
      debugMode: Array.from(this.states.values()).some(s => s.isDebugMode)
    }
  }
}

export const globalStateManager = new GlobalStateManager()

// 页面状态 Hook
export function usePageState(routeName?: string) {
  const route = useRoute()
  const currentRouteName = computed(() => routeName || route.name as string)
  const currentPath = computed(() => route.path)

  // 获取页面配置
  const pageConfig = computed(() =>
    globalStateManager.getPageConfig(currentRouteName.value)
  )

  // 获取页面状态
  const pageState = computed(() =>
    globalStateManager.getPageState(currentPath.value)
  )

  // 搜索查询
  const searchQuery = computed({
    get: () => pageState.value.searchQuery,
    set: (value: string) => {
      globalStateManager.updatePageState(currentPath.value, {
        searchQuery: value,
        currentPage: 1 // 搜索时重置页码
      })
    }
  })

  // 当前页码
  const currentPage = computed({
    get: () => pageState.value.currentPage,
    set: (value: number) => {
      globalStateManager.updatePageState(currentPath.value, { currentPage: value })
    }
  })

  // 页面大小
  const pageSize = computed({
    get: () => pageState.value.pageSize,
    set: (value: number) => {
      globalStateManager.updatePageState(currentPath.value, {
        pageSize: value,
        currentPage: 1
      })
    }
  })

  // 选中项目
  const selectedItems = computed({
    get: () => pageState.value.selectedItems,
    set: (value: any[]) => {
      globalStateManager.updatePageState(currentPath.value, { selectedItems: value })
    }
  })

  // 调试模式 - 从 systemStore 获取
  const systemStore = useSystemStore()
  const isDebugMode = computed(() => systemStore.systemConfig?.debug_mode === 1)

  // 更新状态
  const updateState = (updates: Partial<GlobalState>) => {
    globalStateManager.updatePageState(currentPath.value, updates)
  }

  // 重置搜索
  const resetSearch = () => {
    globalStateManager.resetSearch(currentPath.value)
  }

  // 清除状态
  const clearState = () => {
    globalStateManager.clearPageState(currentPath.value)
  }

  return {
    // 配置
    pageConfig,

    // 状态
    searchQuery,
    currentPage,
    pageSize,
    selectedItems,
    isDebugMode,

    // 方法
    updateState,
    resetSearch,
    clearState
  }
}

export default globalStateManager
