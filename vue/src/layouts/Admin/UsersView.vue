<template>
  <div class="page-content">
    <!-- 统一页面头部 -->
    <PageHeader :title="`${pageIcon} ${pageTitle}`" :show-search="true" search-placeholder="搜索用户名或邮箱..."
      :search-loading="loading" :search-results="searchResults" :show-refresh="false"
      v-model:search-query="searchKeyword" @search="handleSearch" @clear-search="handleClearSearch" />

    <div class="users-content">
      <!-- 加载状态 -->
      <LoadingOverlay v-if="loading" :show="true" text="加载用户列表..." type="local" />

      <!-- 错误状态 -->
      <div v-else-if="error" class="error-state">
        <div class="error-icon">❌</div>
        <p>{{ error }}</p>
        <button class="btn btn-primary" @click="loadData(true)">重试</button>
      </div>

      <!-- 空状态 -->
      <div v-else-if="!hasUsers" class="empty-state">
        <div class="empty-icon">👥</div>
        <p>{{ searchKeyword ? '没有找到匹配的用户' : '暂无用户' }}</p>
        <button v-if="searchKeyword" class="btn btn-secondary" @click="handleClearSearch">
          清除搜索
        </button>
      </div>

      <!-- 用户列表 -->
      <div v-else class="users-list">
        <div v-for="user in users" :key="user.id" class="user-item">
          <div class="user-info">
            <div class="user-avatar">{{ user.username.charAt(0).toUpperCase() }}</div>
            <div class="user-details">
              <div class="user-name">{{ user.username }}</div>
              <div class="user-email">{{ user.email }}</div>
              <div class="user-type">
                <span :class="['badge', user.user_type === 'admin' ? 'badge-danger' : 'badge-primary']">
                  {{ user.user_type === 'admin' ? '管理员' : '普通用户' }}
                </span>
              </div>
            </div>
          </div>
          <div class="user-actions">
            <button class="btn btn-primary btn-sm" @click="editUser(user.id)">
              ✏️ 编辑
            </button>
            <button class="btn btn-danger btn-sm" @click="deleteUser(user.id)">
              🗑️ 删除
            </button>
          </div>
        </div>
      </div>

      <!-- 分页信息 -->
      <div v-if="!loading && !error && hasUsers" class="pagination-info">
        <p>共 {{ total }} 个用户，当前第 {{ currentPage }} 页</p>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import LoadingOverlay from '@/layouts/AppLoadingSpinner.vue'
import PageHeader from '@/layouts/components/PageHeader.vue'
import { adminApiService } from '@/composables/api'
import { cacheService } from '@/composables/cache'

// 调试工具函数
const debugLog = (...args: any[]) => {
  const isDebugMode = import.meta.env.DEV || import.meta.env.VITE_DEBUG === 'true'
  if (isDebugMode) {
    console.log(...args)
  }
}

// 响应式数据
const users = ref<any[]>([])
const total = ref(0)
const loading = ref(false)
const error = ref<string | null>(null)
const currentPage = ref(1)
const pageSize = ref(20)
const searchKeyword = ref('')
const searchResults = ref<any>(null)

// 页面配置
const pageTitle = computed(() => '用户管理')
const pageIcon = computed(() => '👥')

// 计算属性
const hasUsers = computed(() => users.value && users.value.length > 0)

// 加载用户数据
const loadData = async (forceRefresh = false) => {
  debugLog(`📊 用户管理：开始加载数据 (forceRefresh: ${forceRefresh})`)
  loading.value = true
  error.value = null

  try {
    const cacheKey = `admin-users_${currentPage.value}_${pageSize.value}_${searchKeyword.value}`
    debugLog(`🔑 缓存键: ${cacheKey}`)

    // 检查缓存
    if (!forceRefresh) {
      const cached = cacheService.get<{ items: any[], total: number }>(cacheKey)
      if (cached) {
        debugLog('✅ 从缓存加载用户数据', cached)
        users.value = cached.items || []
        total.value = cached.total || 0
        loading.value = false
        return
      } else {
        debugLog('❌ 缓存中没有数据')
      }
    } else {
      debugLog('🚫 强制刷新，跳过缓存检查')
    }

    // 从API获取
    debugLog('📡 准备调用 API: /admin/users', {
      page: currentPage.value,
      limit: pageSize.value,
      search: searchKeyword.value
    })

    const response = await adminApiService.getAllUsers({
      page: currentPage.value,
      limit: pageSize.value,
      search: searchKeyword.value
    })

    debugLog('📡 API 响应:', response)

    if (response.success && response.data) {
      users.value = response.data.items || []
      total.value = response.data.total || 0

      // 存入缓存（5分钟）
      cacheService.set(cacheKey, {
        items: users.value,
        total: total.value
      }, 5 * 60 * 1000)
    } else {
      throw new Error(response.message || '加载用户数据失败')
    }
  } catch (err) {
    debugLog('加载用户数据失败:', err)
    error.value = err instanceof Error ? err.message : '加载数据失败'
  } finally {
    loading.value = false
  }
}


// 编辑用户
const editUser = (userId: string) => {
  debugLog('编辑用户:', userId)
  // TODO: 实现编辑用户功能
}

// 删除用户
const deleteUser = async (userId: string) => {
  if (!confirm('确定要删除这个用户吗？此操作不可撤销。')) {
    return
  }

  try {
    loading.value = true
    const response = await adminApiService.deleteUser(parseInt(userId))
    if (response.success) {
      // 删除成功后刷新列表
      await loadData(true)
      debugLog('用户删除成功')
    } else {
      debugLog('删除用户失败:', response.message)
    }
  } catch (error) {
    debugLog('删除用户失败:', error)
  } finally {
    loading.value = false
  }
}

// 搜索用户
const handleSearch = async () => {
  const startTime = Date.now()
  currentPage.value = 1
  await loadData(true) // 强制刷新
  searchResults.value = {
    total: total.value,
    time: Date.now() - startTime
  }
}

const handleClearSearch = () => {
  searchKeyword.value = ''
  searchResults.value = null
  currentPage.value = 1
  loadData(true)
}

const refreshData = () => {
  debugLog('🔄 用户管理页面：手动刷新数据')
  // 清空当前数据，强制重新加载
  users.value = []
  total.value = 0
  // 清空缓存
  const cacheKey = `admin-users_${currentPage.value}_${pageSize.value}_${searchKeyword.value}`
  cacheService.delete(cacheKey)
  // 重新加载
  loadData(true)
}

// 页面初始化
onMounted(() => {
  loadData()
  // 注册全局刷新函数
  window.refreshCurrentPage = refreshData
})

// 页面卸载时清理
onUnmounted(() => {
  // 清理全局刷新函数
  if (window.refreshCurrentPage === refreshData) {
    window.refreshCurrentPage = undefined
  }
})
</script>

<style scoped>
.users-page {
  padding: 20px;
  background: #f8f9fa;
  min-height: 100%;
}

.page-header {
  margin-bottom: 20px;
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.page-header h1 {
  margin: 0;
  color: #2c3e50;
  font-size: 24px;
  font-weight: 600;
}

.page-actions {
  display: flex;
  gap: 10px;
}

.search-section {
  margin-bottom: 20px;
}

.search-box {
  display: flex;
  gap: 10px;
  max-width: 400px;
}

.search-box .form-control {
  flex: 1;
}

.users-content {
  position: relative;
  min-height: 200px;
}

.empty-state,
.error-state {
  text-align: center;
  padding: 40px;
  color: #6c757d;
}

.empty-icon,
.error-icon {
  font-size: 48px;
  margin-bottom: 15px;
}

.error-state {
  color: #dc3545;
}

.users-list {
  display: flex;
  flex-direction: column;
  gap: 15px;
}

.user-item {
  background: white;
  border-radius: 10px;
  padding: 20px;
  box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.user-info {
  display: flex;
  align-items: center;
  gap: 15px;
}

.user-avatar {
  width: 40px;
  height: 40px;
  border-radius: 50%;
  background: #3498db;
  color: white;
  display: flex;
  align-items: center;
  justify-content: center;
  font-weight: bold;
  font-size: 16px;
}

.user-details {
  display: flex;
  flex-direction: column;
  gap: 5px;
}

.user-name {
  font-weight: 500;
  color: #2c3e50;
  font-size: 16px;
}

.user-email {
  color: #6c757d;
  font-size: 14px;
}

.user-type {
  color: #3498db;
  font-size: 12px;
  font-weight: 500;
}

.user-actions {
  display: flex;
  gap: 10px;
}

.btn {
  padding: 6px 12px;
  border: none;
  border-radius: 5px;
  font-size: 12px;
  cursor: pointer;
  transition: all 0.3s;
  font-weight: 500;
}

.btn-primary {
  background: #3498db;
  color: white;
}

.btn-primary:hover {
  background: #2980b9;
}

.btn-danger {
  background: #e74c3c;
  color: white;
}

.btn-danger:hover {
  background: #c0392b;
}

.btn-sm {
  padding: 4px 8px;
  font-size: 11px;
}

.pagination-info {
  text-align: center;
  padding: 20px;
  color: #6c757d;
  font-size: 14px;
}

.badge {
  display: inline-block;
  padding: 4px 8px;
  font-size: 12px;
  font-weight: 500;
  border-radius: 4px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.badge-primary {
  background: #007bff;
  color: white;
}

.badge-danger {
  background: #dc3545;
  color: white;
}
</style>