<template>
  <div class="admin-users-page">
    <!-- 页面头部 -->
    <div class="page-header">
      <div class="header-content">
        <h2 class="page-title">👥 用户管理</h2>
        <p class="page-description">
          管理系统中的所有用户，包括普通用户和管理员
        </p>
      </div>
      <div class="header-actions">
        <button
          class="btn btn-primary"
          @click="refreshUsers"
          :disabled="adminStore.loading"
        >
          <span v-if="adminStore.loading">刷新中...</span>
          <span v-else">🔄 刷新</span>
        </button>
      </div>
    </div>

    <!-- 用户统计 -->
    <div class="stats-section">
      <div class="stat-card">
        <div class="stat-number">{{ adminStore.totalUsers }}</div>
        <div class="stat-label">总用户数</div>
      </div>
      <div class="stat-card">
        <div class="stat-number">{{ adminStore.adminUsers.length }}</div>
        <div class="stat-label">管理员</div>
      </div>
      <div class="stat-card">
        <div class="stat-number">{{ adminStore.regularUsers.length }}</div>
        <div class="stat-label">普通用户</div>
      </div>
      <div class="stat-card">
        <div class="stat-number">{{ usersWithWebhook }}</div>
        <div class="stat-label">已配置 Webhook</div>
      </div>
    </div>

    <!-- 用户列表 -->
    <div class="users-section card">
      <div class="card-header">
        <h3 class="card-title">用户列表</h3>
        <div class="header-actions">
          <div class="search-box">
            <input
              v-model="searchQuery"
              type="text"
              class="form-control"
              placeholder="搜索用户..."
              @input="handleSearch"
            >
          </div>
          <div class="filter-select">
            <select v-model="userTypeFilter" class="form-control" @change="handleFilterChange">
              <option value="">所有用户</option>
              <option value="admin">管理员</option>
              <option value="user">普通用户</option>
            </select>
          </div>
        </div>
      </div>

      <!-- 加载状态 -->
      <div v-if="adminStore.loading" class="loading">
        正在加载用户列表...
      </div>

      <!-- 错误状态 -->
      <div v-else-if="adminStore.error" class="error-message">
        <p>{{ adminStore.error }}</p>
        <button class="btn btn-primary" @click="refreshUsers">
          重试
        </button>
      </div>

      <!-- 空状态 -->
      <div v-else-if="filteredUsers.length === 0" class="empty-state">
        <div class="empty-icon">👤</div>
        <h3>暂无用户</h3>
        <p>当前筛选条件下没有找到匹配的用户。</p>
      </div>

      <!-- 用户表格 -->
      <div v-else class="table-responsive">
        <table class="table">
          <thead>
            <tr>
              <th>用户前缀</th>
              <th>完整邮箱</th>
              <th>用户类型</th>
              <th>Webhook</th>
              <th>注册时间</th>
              <th>操作</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="user in filteredUsers" :key="user.id">
              <td>
                <code class="user-prefix">{{ user.email_prefix }}</code>
              </td>
              <td>
                <span class="user-email">{{ getFullEmail(user.email_prefix) }}</span>
                <button
                  class="btn btn-sm btn-light ml-2"
                  @click="copyToClipboard(getFullEmail(user.email_prefix))"
                  title="复制邮箱"
                >
                  📋
                </button>
              </td>
              <td>
                <span :class="['badge', user.user_type === 'admin' ? 'badge-primary' : 'badge-success']">
                  {{ user.user_type === 'admin' ? '管理员' : '普通用户' }}
                </span>
              </td>
              <td>
                <span :class="['webhook-status', user.webhook_url ? 'has-webhook' : 'no-webhook']">
                  {{ user.webhook_url ? '✅ 已配置' : '❌ 未配置' }}
                </span>
              </td>
              <td>
                <span class="create-time">{{ formatDate(user.created_at) }}</span>
              </td>
              <td>
                <div class="action-buttons">
                  <button
                    class="btn btn-sm btn-info"
                    @click="sendUserInfo(user)"
                    :disabled="sendingInfo === user.id"
                    title="发送用户信息到邮箱"
                  >
                    <span v-if="sendingInfo === user.id">发送中...</span>
                    <span v-else>📧 发送信息</span>
                  </button>
                  <button
                    v-if="user.user_type !== 'admin'"
                    class="btn btn-sm btn-danger"
                    @click="deleteUser(user)"
                    :disabled="deletingUser === user.id"
                    title="删除用户"
                  >
                    <span v-if="deletingUser === user.id">删除中...</span>
                    <span v-else">🗑️ 删除</span>
                  </button>
                  <span v-else class="text-muted">
                    <small>管理员不可删除</small>
                  </span>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- 用户详情模态框 -->
    <UserDetailModal
      v-if="selectedUser"
      :user="selectedUser"
      @close="selectedUser = null"
      @updated="handleUserUpdated"
    />
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useAdminStore } from '@/stores/admin'
import { useSystemStore } from '@/stores/system'
import type { User } from '@/types'
import UserDetailModal from '@/components/admin/UserDetailModal.vue'

// Composables
const adminStore = useAdminStore()
const systemStore = useSystemStore()

// State
const searchQuery = ref('')
const userTypeFilter = ref('')
const selectedUser = ref<User | null>(null)
const sendingInfo = ref<number | null>(null)
const deletingUser = ref<number | null>(null)
let searchTimeout: NodeJS.Timeout | null = null

// Computed
const usersWithWebhook = computed(() => {
  return adminStore.users.filter(user => user.webhook_url).length
})

const filteredUsers = computed(() => {
  let users = adminStore.users

  // 按用户类型过滤
  if (userTypeFilter.value) {
    users = users.filter(user => user.user_type === userTypeFilter.value)
  }

  // 按搜索关键词过滤
  if (searchQuery.value.trim()) {
    const query = searchQuery.value.toLowerCase()
    users = users.filter(user =>
      user.email_prefix.toLowerCase().includes(query) ||
      getFullEmail(user.email_prefix).toLowerCase().includes(query)
    )
  }

  return users
})

// Methods
const refreshUsers = async () => {
  await adminStore.loadUsers()
}

const handleSearch = () => {
  if (searchTimeout) {
    clearTimeout(searchTimeout)
  }
  
  searchTimeout = setTimeout(() => {
    // 搜索逻辑已在 computed 中处理
  }, 300)
}

const handleFilterChange = () => {
  // 过滤逻辑已在 computed 中处理
}

const getFullEmail = (prefix: string): string => {
  return systemStore.getFullEmailAddress(prefix)
}

const formatDate = (dateString?: string): string => {
  if (!dateString) return '-'
  return systemStore.formatDate(dateString)
}

const copyToClipboard = async (text: string) => {
  try {
    await navigator.clipboard.writeText(text)
    showMessage('已复制到剪贴板', 'success')
  } catch (error) {
    // 降级方案
    const textArea = document.createElement('textarea')
    textArea.value = text
    document.body.appendChild(textArea)
    textArea.select()
    document.execCommand('copy')
    document.body.removeChild(textArea)
    showMessage('已复制到剪贴板', 'success')
  }
}

const sendUserInfo = async (user: User) => {
  if (!confirm(`确定要发送用户信息到 ${getFullEmail(user.email_prefix)} 吗？`)) {
    return
  }

  sendingInfo.value = user.id
  try {
    const success = await adminStore.sendUserInfo(user.id)
    if (success) {
      showMessage('用户信息发送成功', 'success')
    }
  } catch (error) {
    console.error('发送用户信息失败:', error)
  } finally {
    sendingInfo.value = null
  }
}

const deleteUser = async (user: User) => {
  const confirmText = `确定要删除用户 ${user.email_prefix} 吗？\n\n此操作将：\n- 删除用户账户\n- 删除所有相关邮件\n- 删除所有附件\n\n此操作不可恢复！`
  
  if (!confirm(confirmText)) {
    return
  }

  deletingUser.value = user.id
  try {
    const success = await adminStore.deleteUser(user.id)
    if (success) {
      showMessage(`用户 ${user.email_prefix} 删除成功`, 'success')
    }
  } catch (error) {
    console.error('删除用户失败:', error)
  } finally {
    deletingUser.value = null
  }
}

const handleUserUpdated = () => {
  // 用户信息更新后刷新列表
  refreshUsers()
}

const showMessage = (message: string, type: 'success' | 'error' | 'info' = 'info') => {
  // 这里应该使用全局消息组件
  console.log(`[${type.toUpperCase()}] ${message}`)
}

// Lifecycle
onMounted(async () => {
  await refreshUsers()
})

onUnmounted(() => {
  if (searchTimeout) {
    clearTimeout(searchTimeout)
  }
  adminStore.reset()
})
</script>

<style scoped>
.admin-users-page {
  max-width: 1200px;
  margin: 0 auto;
}

.page-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: var(--spacing-6);
  gap: var(--spacing-4);
}

.header-content {
  flex: 1;
}

.page-title {
  font-size: var(--font-size-2xl);
  font-weight: 600;
  color: var(--gray-800);
  margin-bottom: var(--spacing-2);
}

.page-description {
  color: var(--gray-600);
  font-size: var(--font-size-base);
  margin: 0;
}

.header-actions {
  display: flex;
  gap: var(--spacing-3);
}

.stats-section {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: var(--spacing-4);
  margin-bottom: var(--spacing-6);
}

.stat-card {
  background: var(--white);
  padding: var(--spacing-5);
  border-radius: var(--border-radius-lg);
  text-align: center;
  box-shadow: var(--shadow);
}

.stat-number {
  font-size: var(--font-size-2xl);
  font-weight: 700;
  color: var(--primary-color);
  margin-bottom: var(--spacing-1);
}

.stat-label {
  color: var(--gray-600);
  font-size: var(--font-size-sm);
}

.users-section {
  margin-bottom: var(--spacing-6);
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: var(--spacing-4);
  gap: var(--spacing-4);
}

.card-header .header-actions {
  display: flex;
  gap: var(--spacing-3);
  align-items: center;
}

.search-box {
  min-width: 200px;
}

.filter-select {
  min-width: 120px;
}

.error-message {
  text-align: center;
  padding: var(--spacing-8);
  color: var(--danger-color);
}

.empty-state {
  text-align: center;
  padding: var(--spacing-10);
}

.empty-icon {
  font-size: 4rem;
  margin-bottom: var(--spacing-4);
}

.empty-state h3 {
  color: var(--gray-700);
  margin-bottom: var(--spacing-2);
}

.empty-state p {
  color: var(--gray-600);
  max-width: 400px;
  margin: 0 auto;
}

.user-prefix {
  background: var(--gray-100);
  padding: var(--spacing-1) var(--spacing-2);
  border-radius: var(--border-radius-sm);
  font-family: 'Courier New', monospace;
  font-size: var(--font-size-sm);
}

.user-email {
  font-weight: 500;
}

.webhook-status {
  font-size: var(--font-size-sm);
}

.has-webhook {
  color: var(--success-color);
}

.no-webhook {
  color: var(--gray-500);
}

.create-time {
  color: var(--gray-600);
  font-size: var(--font-size-sm);
}

.action-buttons {
  display: flex;
  gap: var(--spacing-2);
  align-items: center;
}

.ml-2 {
  margin-left: var(--spacing-2);
}

/* 响应式设计 */
@media (max-width: 768px) {
  .page-header {
    flex-direction: column;
    align-items: stretch;
  }
  
  .card-header {
    flex-direction: column;
    align-items: stretch;
    gap: var(--spacing-3);
  }
  
  .card-header .header-actions {
    flex-direction: column;
  }
  
  .search-box,
  .filter-select {
    min-width: auto;
  }
  
  .stats-section {
    grid-template-columns: repeat(2, 1fr);
  }
  
  .table-responsive {
    overflow-x: auto;
  }
  
  .table {
    min-width: 600px;
  }
  
  .action-buttons {
    flex-direction: column;
    gap: var(--spacing-1);
  }
  
  .action-buttons .btn {
    font-size: var(--font-size-sm);
    padding: var(--spacing-1) var(--spacing-2);
  }
}

@media (max-width: 480px) {
  .stats-section {
    grid-template-columns: 1fr;
  }
  
  .table {
    font-size: var(--font-size-sm);
  }
  
  .table th,
  .table td {
    padding: var(--spacing-2);
  }
}
</style>