<template>
  <div class="admin-page">
    <div class="page-header">
      <h1>{{ pageIcon }} {{ pageTitle }}</h1>
    </div>

    <div class="page-content">
      <LoadingOverlay v-if="loading" text="加载邮箱列表..." />

      <!-- 搜索和操作栏 - 根据配置显示 -->
      <div v-if="showSearch" class="search-bar">
        <div class="search-input-group">
          <input v-model="searchKeyword" type="text" class="form-control" placeholder="搜索邮箱地址或用户名..."
            @keyup.enter="() => handleSearch(searchKeyword)">
          <button class="btn btn-primary" @click="() => handleSearch(searchKeyword)" :disabled="loading">搜索</button>
        </div>
      </div>

      <div v-if="mailboxes.length === 0 && !loading" class="empty-state">
        <div class="empty-icon">{{ pageIcon }}</div>
        <p>暂无邮箱</p>
      </div>

      <div v-if="mailboxes.length > 0" class="list-container">
        <div v-for="mailbox in mailboxes" :key="mailbox.id" class="list-item">
          <div class="list-item-info">
            <div class="list-item-title">{{ mailbox.address }}</div>
            <div class="list-item-meta">
              <div class="list-item-meta-left">
                <span class="status-badge" :class="`status-${mailbox.status}`">
                  {{ getStatusText(mailbox.status) }}
                </span>
                <span class="owner-info">所有者: {{ mailbox.owner_username || '未知' }}</span>
              </div>
              <div class="list-item-meta-right">
                <span class="created-time">{{ formatTime(mailbox.created_at) }}</span>
              </div>
            </div>
          </div>
          <div v-if="showActions" class="list-item-actions">
            <button class="btn btn-info btn-sm" @click="showMailboxHistory(mailbox.id, mailbox.address)">历史记录</button>
            <button class="btn btn-sm" :class="mailbox.status === 'active' ? 'btn-warning' : 'btn-success'"
              @click="toggleMailboxStatus(mailbox.id, mailbox.status === 'active' ? 'disabled' : 'active')">
              {{ mailbox.status === 'active' ? '停用' : '启用' }}
            </button>
          </div>
        </div>
      </div>

      <!-- 分页 -->
      <div v-if="total > pageSize" class="pagination">
        <button class="btn btn-secondary btn-sm" @click="handlePageChange(currentPage - 1)"
          :disabled="currentPage <= 1">
          上一页
        </button>
        <span class="pagination-info">
          第 {{ currentPage }} 页，共 {{ Math.ceil(total / pageSize) }} 页，总计 {{ total }} 条
        </span>
        <button class="btn btn-secondary btn-sm" @click="handlePageChange(currentPage + 1)"
          :disabled="currentPage >= Math.ceil(total / pageSize)">
          下一页
        </button>
      </div>
    </div>

    <!-- 邮箱历史记录弹窗 -->
    <div v-if="showHistoryModal" class="modal-overlay" @click="closeHistoryModal">
      <div class="modal-content" @click.stop>
        <div class="modal-header">
          <h3>邮箱历史记录 - {{ currentMailboxAddress }}</h3>
          <button class="btn btn-secondary btn-sm" @click="closeHistoryModal">关闭</button>
        </div>
        <div class="modal-body">
          <LoadingOverlay v-if="historyLoading" text="加载历史记录..." />
          <div v-if="mailboxHistory.length === 0 && !historyLoading" class="empty-state">
            <div class="empty-icon">📋</div>
            <p>暂无历史记录</p>
          </div>
          <div v-if="mailboxHistory.length > 0" class="history-list">
            <div v-for="history in mailboxHistory" :key="history.id" class="history-item">
              <div class="history-info">
                <div class="history-action">
                  <span class="action-badge" :class="`action-${history.action_type}`">
                    {{ getActionText(history.action_type) }}
                  </span>
                  <span class="history-user">{{ history.user_username || '未知用户' }}</span>
                </div>
                <div class="history-time">{{ formatTime(history.created_at) }}</div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { adminApiService } from '@/composables/api'
import LoadingOverlay from '@/layouts/AppLoadingSpinner.vue'

// 简单的响应式数据 - 不用煞笔的 useSimplePageData
const mailboxesResponse = ref(null)
const loading = ref(false)
const searchKeyword = ref('')

// 页面信息
const pageTitle = computed(() => '邮箱管理')
const pageIcon = computed(() => '📮')
const showSearch = computed(() => true)
const showActions = computed(() => true)

// 提取数据
const mailboxes = computed(() => mailboxesResponse.value?.items || [])
const total = computed(() => mailboxesResponse.value?.total || 0)
const currentPage = ref(1)
const pageSize = ref(20)

// 加载数据
const refreshData = async () => {
  if (loading.value) return

  loading.value = true
  try {
    const params = {
      page: currentPage.value,
      pageSize: pageSize.value,
      scope: 'all',
      search: searchKeyword.value || undefined
    }

    const response = await adminApiService.getAllMailboxes(params)
    mailboxesResponse.value = response
  } catch (err) {
    console.error('加载邮箱失败:', err)
  } finally {
    loading.value = false
  }
}

// 搜索处理
const handleSearch = (query: string) => {
  searchKeyword.value = query
  currentPage.value = 1
  refreshData()
}

// 分页处理
const handlePageChange = (page: number) => {
  currentPage.value = page
  refreshData()
}

// 初始化
onMounted(() => {
  refreshData()
})

// 暴露刷新方法给全局刷新按钮使用，直接使用已有的refreshData函数
window.refreshCurrentPage = refreshData

// 历史记录相关
const showHistoryModal = ref(false)
const historyLoading = ref(false)
const mailboxHistory = ref<any[]>([])
const currentMailboxId = ref<number | null>(null)
const currentMailboxAddress = ref('')

// 数据加载逻辑已由 usePageData 处理

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

const getStatusText = (status: string) => {
  const statusMap: Record<string, string> = {
    active: '正常',
    disabled: '停用',
    deleted: '已删除'
  }
  return statusMap[status] || status
}

const getActionText = (actionType: string) => {
  const actionMap: Record<string, string> = {
    created: '创建',
    deleted: '删除',
    disabled: '停用',
    enabled: '启用'
  }
  return actionMap[actionType] || actionType
}

const showMailboxHistory = async (mailboxId: number, mailboxAddress: string) => {
  currentMailboxId.value = mailboxId
  currentMailboxAddress.value = mailboxAddress
  showHistoryModal.value = true
  await loadMailboxHistory()
}

const loadMailboxHistory = async () => {
  if (!currentMailboxId.value) return

  historyLoading.value = true
  try {
    const response = await apiService.getMailboxHistory(currentMailboxId.value)
    if (response.success && response.data) {
      mailboxHistory.value = response.data.history || []
    } else {
      console.warn('加载历史记录失败:', response)
    }
  } catch (error) {
    console.error('加载历史记录失败:', error)
  } finally {
    historyLoading.value = false
  }
}

const closeHistoryModal = () => {
  showHistoryModal.value = false
  currentMailboxId.value = null
  currentMailboxAddress.value = ''
  mailboxHistory.value = []
}

const toggleMailboxStatus = async (mailboxId: number, status: 'active' | 'disabled') => {
  const action = status === 'active' ? '启用' : '停用'
  if (!confirm(`确定要${action}这个邮箱吗？`)) {
    return
  }

  try {
    const response = await apiService.toggleMailboxStatus(mailboxId, status)
    if (response.success) {
      alert(`邮箱${action}成功`)
      await refreshData()
    } else {
      alert(`${action}失败：` + (response.message || '未知错误'))
    }
  } catch (error) {
    console.error(`${action}邮箱失败:`, error)
    alert(`${action}邮箱失败`)
  }
}

// 页面刷新逻辑已由 usePageData 处理
</script>

<style scoped>
/* 使用全局样式，这里只保留页面特定的样式 */

/* 搜索栏样式 */
.search-bar {
  display: flex;
  justify-content: flex-start;
  align-items: center;
  margin-bottom: 20px;
  padding: 15px;
  background: white;
  border-radius: 10px;
  box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
}

.search-input-group {
  display: flex;
  gap: 10px;
  max-width: 400px;
}

.search-input-group .form-control {
  flex: 1;
}

/* 状态徽章样式 */
.status-badge {
  padding: 4px 8px;
  border-radius: 12px;
  font-size: 12px;
  font-weight: 500;
  margin-right: 8px;
}

.status-active {
  background: #d4edda;
  color: #155724;
}

.status-disabled {
  background: #f8d7da;
  color: #721c24;
}

.status-deleted {
  background: #fff3cd;
  color: #856404;
}

/* 所有者信息 */
.owner-info {
  font-size: 12px;
  color: #6c757d;
}

/* 分页样式 */
.pagination {
  display: flex;
  justify-content: center;
  align-items: center;
  gap: 15px;
  margin-top: 20px;
  padding: 15px;
  background: white;
  border-radius: 10px;
  box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
}

.pagination-info {
  font-size: 14px;
  color: #6c757d;
}

/* 弹窗样式 */
.modal-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(0, 0, 0, 0.5);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
}

.modal-content {
  background: white;
  border-radius: 10px;
  width: 90%;
  max-width: 600px;
  max-height: 80vh;
  overflow: hidden;
  box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
}

.modal-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 20px;
  border-bottom: 1px solid #e0e0e0;
  background: #f8f9fa;
}

.modal-header h3 {
  margin: 0;
  color: #2c3e50;
  font-size: 18px;
}

.modal-body {
  padding: 20px;
  max-height: 60vh;
  overflow-y: auto;
}

/* 历史记录样式 */
.history-list {
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.history-item {
  padding: 15px;
  background: #f8f9fa;
  border-radius: 8px;
  border-left: 4px solid #3498db;
}

.history-info {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.history-action {
  display: flex;
  align-items: center;
  gap: 10px;
}

.action-badge {
  padding: 4px 8px;
  border-radius: 12px;
  font-size: 12px;
  font-weight: 500;
}

.action-created {
  background: #d4edda;
  color: #155724;
}

.action-deleted {
  background: #f8d7da;
  color: #721c24;
}

.action-disabled {
  background: #fff3cd;
  color: #856404;
}

.action-enabled {
  background: #d1ecf1;
  color: #0c5460;
}

.history-user {
  font-size: 14px;
  color: #2c3e50;
  font-weight: 500;
}

.history-time {
  font-size: 12px;
  color: #6c757d;
}

/* 按钮样式 */
.btn-info {
  background: #17a2b8;
  color: white;
}

.btn-info:hover {
  background: #138496;
}

/* 响应式设计 */
@media (max-width: 768px) {
  .search-bar {
    flex-direction: column;
    gap: 15px;
  }

  .search-input-group {
    max-width: 100%;
  }

  .pagination {
    flex-direction: column;
    gap: 10px;
  }

  .modal-content {
    width: 95%;
    margin: 10px;
  }

  .history-info {
    flex-direction: column;
    align-items: flex-start;
    gap: 5px;
  }
}
</style>