<template>
  <div class="admin-page">
    <div class="page-header">
      <h1>{{ pageIcon }} {{ pageTitle }}</h1>

      <!-- 控制栏 -->
      <div class="page-controls">
        <!-- 搜索框 -->
        <div class="search-box">
          <input v-model="searchQuery" type="text" class="search-input" placeholder="搜索邮件标题、发件人..."
            @input="handleSearch" @keyup.enter="performSearch">
          <button class="search-btn" @click="performSearch" :disabled="loading">
            🔍
          </button>
          <button v-if="searchQuery" class="clear-btn" @click="clearSearch">
            ✕
          </button>
        </div>

        <!-- 操作按钮 -->
        <div class="action-controls">
          <button v-if="isAdminPage && !showAllEmails" class="btn btn-secondary btn-sm" @click="toggleScope">
            📋 查看全部邮件
          </button>
          <button v-if="isAdminPage && showAllEmails" class="btn btn-primary btn-sm" @click="toggleScope">
            👤 查看我的邮件
          </button>

          <button class="btn btn-secondary btn-sm" @click="toggleCollapse" :title="isCollapsed ? '展开邮件列表' : '收起邮件列表'">
            {{ isCollapsed ? '📄 展开' : '📋 收起' }}
          </button>
        </div>
      </div>
    </div>

    <div class="page-content" :class="{ collapsed: isCollapsed }">
      <!-- 搜索状态提示 -->
      <div v-if="isSearching && searchQuery" class="search-status">
        🔍 搜索 "{{ searchQuery }}" 找到 {{ searchResults.length }} 条结果
        <button @click="clearSearch"
          style="margin-left: 10px; background: none; border: none; color: #0066cc; cursor: pointer;">
          清除搜索
        </button>
      </div>

      <!-- 临时调试信息 -->
      <div v-if="isDebugMode"
        style="background: #f0f0f0; padding: 10px; margin: 10px 0; font-family: monospace; font-size: 12px;">
        <div>调试信息：</div>
        <div>loading: {{ loading }}</div>
        <div>isSearching: {{ isSearching }}</div>
        <div>searchQuery: {{ searchQuery }}</div>
        <div>emails数组长度: {{ emails.length }}</div>
        <div>emails类型: {{ typeof emails }}</div>
        <div>total: {{ total }}</div>
        <div>原始emails: {{ emails }}</div>
      </div>

      <LoadingOverlay v-if="loading" :text="isSearching ? '搜索中...' : '加载邮件列表...'" />
      <div v-if="!loading && emails.length === 0" class="empty-state">
        <div class="empty-icon">{{ pageIcon }}</div>
        <p>暂无邮件</p>
      </div>
      <div v-if="emails.length > 0" class="list-container">
        <div v-for="email in emails" :key="email.id" class="list-item clickable" @click="viewEmail(email.id)">
          <div class="list-item-info">
            <div class="list-item-title">{{ email.subject }}</div>
            <div class="list-item-meta">
              <span class="list-item-meta-left">
                {{ isAdminPage ? `${email.sender_email} → ${email.recipient_email}` : email.sender_email }}
              </span>
              <span class="list-item-meta-right">{{ formatTime(email.received_at) }}</span>
            </div>
          </div>
        </div>
      </div>

      <!-- 分页 -->
      <div v-if="total > pageSize" class="pagination-container">
        <div class="pagination-info">
          显示 {{ (currentPage - 1) * pageSize + 1 }} - {{ Math.min(currentPage * pageSize, total) }} 条，共 {{ total }} 条
        </div>
        <div class="pagination">
          <button class="btn btn-sm" :disabled="currentPage <= 1" @click="handlePageChange(currentPage - 1)">
            上一页
          </button>
          <span class="pagination-current">{{ currentPage }} / {{ Math.ceil(total / pageSize) }}</span>
          <button class="btn btn-sm" :disabled="currentPage >= Math.ceil(total / pageSize)"
            @click="handlePageChange(currentPage + 1)">
            下一页
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { adminApiService } from '@/composables/api'
import { cacheService } from '@/composables/cache'
import LoadingOverlay from '@/layouts/AppLoadingSpinner.vue'
import { useSystemStore } from '@/composables/system'
const systemStore = useSystemStore()

const router = useRouter()
const route = useRoute()

// 根据路由名称判断页面类型
const routeName = computed(() => route.name as string)
const isAdminPage = computed(() => routeName.value === 'admin-emails')

// 响应式数据
const emailsResponse = ref<any>(null)
const loading = ref(false)
const searchQuery = ref('')
const searchResults = ref<any[]>([])
const isSearching = ref(false)
// 使用 localStorage 持久化 showAllEmails 状态
// 在管理员页面默认显示全部邮件
const showAllEmails = ref(
  isAdminPage.value ?
    (localStorage.getItem('cem_show_all_emails') !== 'false') :
    (localStorage.getItem('cem_show_all_emails') === 'true')
)
const isCollapsed = ref(false)

// 调试信息
console.log('🔍 EmailsView 初始化状态:', {
  routeName: routeName.value,
  isAdminPage: routeName.value === 'admin-emails',
  showAllEmails: showAllEmails.value,
  localStorageValue: localStorage.getItem('cem_show_all_emails'),
  scope: (routeName.value === 'admin-emails' && showAllEmails.value) ? 'all' : 'user'
})

// 分页数据
const currentPage = ref(1)
const pageSize = ref(20)

// 页面信息
const pageTitle = computed(() => {
  const base = isAdminPage.value ? '全部邮件' : '我的邮件'
  if (showAllEmails.value && isAdminPage.value) return '🌍 ' + base
  return base
})
const pageIcon = computed(() => isAdminPage.value ? '📨' : '📧')

// 从响应数据中提取邮件数组和分页信息
const emails = computed(() => {
  if (isSearching.value && searchResults.value.length > 0) {
    return searchResults.value
  }
  return emailsResponse.value?.data?.items || []
})
const total = computed(() => emailsResponse.value?.data?.total || 0)
const isDebugMode = computed(() => systemStore.systemConfig?.debug_mode === 1)

// 搜索防抖定时器
let searchTimeout: ReturnType<typeof setTimeout> | undefined

// 改进的加载数据函数 - 包含缓存策略
const loadData = async (forceRefresh = false) => {
  if (loading.value) return

  loading.value = true
  try {
    const params = {
      page: currentPage.value,
      limit: pageSize.value,
      scope: (isAdminPage.value && showAllEmails.value) ? 'all' as const : undefined
    }

    // 生成缓存键
    const cacheKey = `emails_${routeName.value}_${params.page}_${params.limit}_${params.scope || 'user'}`

    // 检查缓存（只有在非强制刷新时）
    if (!forceRefresh) {
      const cached = cacheService.get<any>(cacheKey)
      if (cached) {
        console.log(`📧 从缓存加载邮件 - ${cacheKey}`)
        emailsResponse.value = cached
        loading.value = false
        return
      }
    }

    console.log(`📧 从API加载邮件 - scope: ${params.scope}, 页面类型: ${isAdminPage.value ? '管理员' : '用户'}, showAllEmails: ${showAllEmails.value}`)
    console.log('📧 详细参数信息:', {
      isAdminPage: isAdminPage.value,
      showAllEmails: showAllEmails.value,
      routeName: routeName.value,
      params: params,
      localStorageValue: localStorage.getItem('cem_show_all_emails')
    })

    const response = await adminApiService.getEmails(params)
    emailsResponse.value = response

    if (response.success) {
      // 将数据存入缓存（30分钟，比其他页面更长）
      cacheService.set(cacheKey, response, 30 * 60 * 1000)
      console.log(`📧 邮件数据已缓存 - ${cacheKey}`)
    } else {
      console.error('加载邮件失败:', response)
    }
  } catch (error) {
    console.error('加载邮件失败:', error)
  } finally {
    loading.value = false
  }
}

// 搜索功能
const handleSearch = () => {
  if (searchTimeout) {
    clearTimeout(searchTimeout)
  }

  searchTimeout = setTimeout(() => {
    performSearch()
  }, 300) // 300ms 防抖
}

const performSearch = async () => {
  const query = searchQuery.value.trim()

  if (!query) {
    clearSearch()
    return
  }

  isSearching.value = true
  loading.value = true

  try {
    // 优先本地搜索
    const localResults = performLocalSearch(query)

    if (localResults.length > 0) {
      searchResults.value = localResults
      console.log(`📧 本地搜索找到 ${localResults.length} 条结果`)
    } else {
      // 本地没有结果，执行远程搜索
      console.log(`📧 执行远程搜索: ${query}`)
      const response = await adminApiService.getEmails({
        page: 1,
        limit: 100, // 搜索时获取更多结果
        search: query,
        scope: (isAdminPage.value && showAllEmails.value) ? 'all' as const : undefined
      })

      if (response.success) {
        searchResults.value = response.data?.items || []
        console.log(`📧 远程搜索找到 ${searchResults.value.length} 条结果`)
      }
    }
  } catch (error) {
    console.error('搜索邮件失败:', error)
    searchResults.value = []
  } finally {
    loading.value = false
  }
}

// 本地搜索函数
const performLocalSearch = (query: string) => {
  const allEmails = emailsResponse.value?.data?.items || []
  const lowercaseQuery = query.toLowerCase()

  return allEmails.filter((email: any) => {
    return (
      email.subject?.toLowerCase().includes(lowercaseQuery) ||
      email.sender_email?.toLowerCase().includes(lowercaseQuery) ||
      email.recipient_email?.toLowerCase().includes(lowercaseQuery)
    )
  })
}

// 清除搜索
const clearSearch = () => {
  searchQuery.value = ''
  searchResults.value = []
  isSearching.value = false
  if (searchTimeout) {
    clearTimeout(searchTimeout)
  }
}

// 切换作用域（管理员功能）
const toggleScope = () => {
  const oldValue = showAllEmails.value
  showAllEmails.value = !showAllEmails.value
  // 保存状态到 localStorage
  localStorage.setItem('cem_show_all_emails', showAllEmails.value.toString())

  console.log('🔄 toggleScope 切换状态:', {
    oldValue,
    newValue: showAllEmails.value,
    localStorageValue: localStorage.getItem('cem_show_all_emails'),
    scope: (isAdminPage.value && showAllEmails.value) ? 'all' : 'user'
  })

  currentPage.value = 1 // 重置到第一页
  loadData(true) // 强制刷新
}

// 收起/展开功能
const toggleCollapse = () => {
  isCollapsed.value = !isCollapsed.value
}

// 暴露刷新方法给全局刷新按钮使用
const refreshData = () => {
  console.log('📧 EmailsView 页面级刷新触发，当前状态:', {
    showAllEmails: showAllEmails.value,
    isAdminPage: isAdminPage.value,
    scope: (isAdminPage.value && showAllEmails.value) ? 'all' : 'user'
  })
  clearSearch() // 清除搜索状态
  loadData(true) // 强制刷新
}

// 注册到全局，让MainLayoutView的刷新按钮能调用
const refreshEmailsPage = () => {
  refreshData()
}

// 分页处理
const handlePageChange = (page: number) => {
  if (isSearching.value) {
    // 搜索模式下不支持分页，需要清除搜索
    clearSearch()
  }
  currentPage.value = page
  loadData()
}

// 页面初始化
onMounted(() => {
  // 确保管理员页面的状态正确设置
  if (isAdminPage.value && !showAllEmails.value) {
    showAllEmails.value = true
    localStorage.setItem('cem_show_all_emails', 'true')
    console.log('🔧 自动设置管理员页面显示全部邮件')
  }

  loadData()
  // 注册全局刷新函数
  window.refreshCurrentPage = refreshEmailsPage
})

// 页面卸载时清理
onUnmounted(() => {
  // 清理防抖定时器
  if (searchTimeout) {
    clearTimeout(searchTimeout)
  }

  // 清理全局刷新函数
  if (window.refreshCurrentPage === refreshEmailsPage) {
    window.refreshCurrentPage = undefined
  }
})

const formatTime = (dateString: string) => {
  const date = new Date(dateString)
  const now = new Date()
  const diff = now.getTime() - date.getTime()

  if (diff < 60000) {
    return '刚刚'
  } else if (diff < 3600000) {
    return `${Math.floor(diff / 60000)}分钟前`
  } else if (diff < 86400000) {
    return `${Math.floor(diff / 3600000)}小时前`
  } else {
    return date.toLocaleDateString('zh-CN')
  }
}

const viewEmail = (emailId: string) => {
  router.push({ name: 'email-detail', params: { id: emailId } })
}

// 页面刷新逻辑已由 usePageData 处理
</script>

<style scoped>
/* 页面控制栏样式 */
.page-controls {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 20px;
  margin-top: 15px;
  padding: 15px;
  background: #f8f9fa;
  border-radius: 8px;
  flex-wrap: wrap;
}

/* 搜索框样式 */
.search-box {
  display: flex;
  align-items: center;
  gap: 8px;
  flex: 1;
  min-width: 300px;
  max-width: 500px;
}

.search-input {
  flex: 1;
  padding: 8px 12px;
  border: 1px solid #ddd;
  border-radius: 6px;
  font-size: 14px;
  transition: border-color 0.3s ease;
}

.search-input:focus {
  outline: none;
  border-color: #007bff;
  box-shadow: 0 0 0 2px rgba(0, 123, 255, 0.25);
}

.search-btn,
.clear-btn {
  padding: 8px 12px;
  border: 1px solid #ddd;
  background: white;
  border-radius: 6px;
  cursor: pointer;
  transition: all 0.3s ease;
  font-size: 14px;
}

.search-btn:hover,
.clear-btn:hover {
  background: #f8f9fa;
  border-color: #007bff;
}

.search-btn:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.clear-btn {
  border-color: #dc3545;
  color: #dc3545;
}

.clear-btn:hover {
  background: #dc3545;
  color: white;
}

/* 操作控制栏样式 */
.action-controls {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-shrink: 0;
}

/* 收起状态样式 */
.page-content.collapsed {
  max-height: 100px;
  overflow: hidden;
  transition: max-height 0.3s ease;
}

.page-content.collapsed .list-container {
  display: none;
}

.page-content.collapsed .pagination-container {
  display: none;
}

/* 搜索结果提示 */
.search-status {
  padding: 10px;
  background: #e7f3ff;
  border: 1px solid #b3d7ff;
  border-radius: 6px;
  margin-bottom: 15px;
  font-size: 14px;
  color: #0066cc;
}

/* 响应式布局 */
@media (max-width: 768px) {
  .page-controls {
    flex-direction: column;
    align-items: stretch;
    gap: 15px;
  }

  .search-box {
    min-width: auto;
    max-width: none;
  }

  .action-controls {
    justify-content: center;
    flex-wrap: wrap;
  }
}

@media (max-width: 480px) {
  .search-box {
    flex-direction: column;
    gap: 10px;
  }

  .search-input {
    width: 100%;
  }

  .search-btn,
  .clear-btn {
    width: 100%;
  }
}
</style>