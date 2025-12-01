<template>
  <div class="page-content">
    <!-- 统一页面头部 -->
    <PageHeader :title="`${pageIcon} ${pageTitle}`" :show-search="false" :show-refresh="true" @refresh="refreshData" />

    <!-- 加载状态 -->
    <div v-if="loading" class="loading-overlay">
      <div class="loading-spinner"></div>
      <p>加载仪表板数据中...</p>
    </div>

    <div v-else class="dashboard-container">
      <!-- 系统统计卡片 -->
      <div class="stats-grid">
        <div class="stat-card clickable" @click="goToEmails">
          <div class="stat-icon">📧</div>
          <div class="stat-content">
            <div class="stat-number">{{ stats.email.total || 0 }}</div>
            <div class="stat-label">总邮件数</div>
            <div class="stat-sub">今日: {{ stats.email.today || 0 }} | 未读: {{ stats.email.unread || 0 }}</div>
          </div>
        </div>

        <div class="stat-card">
          <div class="stat-icon">📁</div>
          <div class="stat-content">
            <div class="stat-number">{{ stats.r2.fileCount || 0 }}</div>
            <div class="stat-label">R2 文件数</div>
          </div>
        </div>

        <div class="stat-card clickable" @click="showForwardLogsModal">
          <div class="stat-icon">✅</div>
          <div class="stat-content">
            <div class="stat-number">{{ stats.forward.success || 0 }}</div>
            <div class="stat-label">转发成功</div>
            <div class="stat-sub">失败: {{ stats.forward.failed || 0 }}</div>
          </div>
        </div>

        <div class="stat-card clickable action-card" @click="goToSettings">
          <div class="stat-icon">🛠️</div>
          <div class="stat-content">
            <div class="stat-number">{{ isDebugMode ? 'ON' : 'OFF' }}</div>
            <div class="stat-label">调试模式</div>
          </div>
        </div>
      </div>

      <!-- 快捷管理面板 -->
      <div class="management-section">
        <h2>快捷管理</h2>
        <div class="management-buttons">
          <button class="btn btn-secondary" @click="showDatabaseModal">
            🗄️ 数据库管理
          </button>
          <button class="btn btn-secondary" @click="showCacheModal">
            💾 缓存管理
          </button>
          <button class="btn btn-secondary" @click="showForwardLogsModal">
            📤 转发日志
          </button>
          <button class="btn btn-secondary" @click="showR2FilesModal">
            📁 R2 文件管理
          </button>
        </div>
      </div>

      <!-- 最近邮件 -->
      <div class="content-section recent-emails-section">
        <h2>最近邮件</h2>
        <div v-if="recentEmails.length === 0" class="empty-state">
          <p>暂无邮件</p>
        </div>
        <div v-else class="recent-emails">
          <div v-for="email in recentEmails" :key="email.id" class="email-item" @click="viewEmail(email.id)">
            <div class="email-subject">{{ email.subject }}</div>
            <div class="email-meta">
              <span class="email-from">{{ email.from }}</span>
              <span class="email-time">{{ formatTime(email.received_at) }}</span>
            </div>
          </div>
        </div>
      </div>

      <!-- 最近转发日志 -->
      <div v-if="stats.forward.recentLogs && stats.forward.recentLogs.length > 0" class="content-section forward-logs-section">
        <h2>最近转发记录</h2>
        <div class="forward-logs">
          <div v-for="log in stats.forward.recentLogs" :key="log.id" class="log-item" @click="viewForwardLogDetail(log)">
            <div class="log-status">
              <span :class="['status-badge', log.status === 0 ? 'success' : 'error']">
                {{ log.status === 0 ? '✅ 成功' : '❌ 失败' }}
              </span>
            </div>
            <div class="log-content">
              <div class="log-subject">{{ log.subject || '(无主题)' }}</div>
              <div class="log-meta">
                <span>发件人: {{ log.from_address }}</span>
                <span class="log-time">{{ formatTime(log.sent_at) }}</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- 转发日志模态窗口 -->
    <Modal v-if="forwardLogsModalVisible" @close="forwardLogsModalVisible = false">
      <template #header>
        <h2>📤 转发日志</h2>
      </template>
      <template #default>
        <div class="forward-logs-modal">
          <!-- 过滤器 -->
          <div class="filter-bar">
            <label>
              <input type="radio" v-model="forwardLogsFilter" value="" />
              全部
            </label>
            <label>
              <input type="radio" v-model="forwardLogsFilter" value="0" />
              成功
            </label>
            <label>
              <input type="radio" v-model="forwardLogsFilter" value="1" />
              失败
            </label>
          </div>

          <!-- 日志列表 -->
          <div v-if="loadingForwardLogs" class="loading-state">
            <div class="loading-spinner"></div>
            <p>加载转发日志中...</p>
          </div>
          <div v-else-if="forwardLogs.length === 0" class="empty-state">
            <p>暂无转发日志</p>
          </div>
          <div v-else class="logs-list">
            <div v-for="log in forwardLogs" :key="log.id" class="log-row" @click="viewForwardLogDetail(log)">
              <div class="log-status-col">
                <span :class="['status-badge', log.status === 0 ? 'success' : 'error']">
                  {{ log.status === 0 ? '✅' : '❌' }}
                </span>
              </div>
              <div class="log-info-col">
                <div class="log-subject">{{ log.subject || '(无主题)' }}</div>
                <div class="log-details">
                  <span>{{ log.from_address }}</span>
                  <span>{{ formatTime(log.sent_at) }}</span>
                  <span v-if="log.response_code">HTTP {{ log.response_code }}</span>
                </div>
                <div v-if="log.error_message" class="log-error">{{ log.error_message }}</div>
              </div>
            </div>
          </div>

          <!-- 分页 -->
          <Pagination
            v-if="forwardLogsPagination.totalPages > 1"
            :current-page="forwardLogsPagination.page"
            :total-pages="forwardLogsPagination.totalPages"
            @change-page="loadForwardLogs"
          />
        </div>
      </template>
    </Modal>

    <!-- 转发日志详情模态窗口 -->
    <Modal v-if="forwardLogDetailVisible" @close="forwardLogDetailVisible = false">
      <template #header>
        <h2>转发日志详情</h2>
      </template>
      <template #default>
        <div v-if="currentForwardLog" class="log-detail">
          <div class="detail-row">
            <label>状态:</label>
            <span :class="['status-badge', currentForwardLog.status === 0 ? 'success' : 'error']">
              {{ currentForwardLog.status === 0 ? '✅ 成功' : '❌ 失败' }}
            </span>
          </div>
          <div class="detail-row">
            <label>响应码:</label>
            <span>{{ currentForwardLog.response_code || '-' }}</span>
          </div>
          <div class="detail-row">
            <label>Webhook URL:</label>
            <span class="url-text">{{ currentForwardLog.webhook_url }}</span>
          </div>
          <div class="detail-row">
            <label>发送时间:</label>
            <span>{{ currentForwardLog.sent_at }}</span>
          </div>
          <div v-if="currentForwardLog.error_message" class="detail-row">
            <label>错误信息:</label>
            <span class="error-text">{{ currentForwardLog.error_message }}</span>
          </div>
          <div class="detail-divider"></div>
          <h3>关联邮件信息</h3>
          <div class="detail-row">
            <label>主题:</label>
            <span>{{ currentForwardLog.subject || '(无主题)' }}</span>
          </div>
          <div class="detail-row">
            <label>发件人:</label>
            <span>{{ currentForwardLog.from_address }}</span>
          </div>
          <div class="detail-row">
            <label>收件人:</label>
            <span>{{ currentForwardLog.to_address }}</span>
          </div>
        </div>
      </template>
    </Modal>

    <!-- 其他管理模态窗口的占位符 -->
    <!-- 这些可以后续补充，或者链接到 DebugView 页面 -->
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore } from '@/composables/stores'
import { useSystemStore } from '@/composables/system'
import { PageHeader, Modal, Pagination } from '@/components/common'
import { get } from '@/composables/api'

const router = useRouter()
const authStore = useAuthStore()
const systemStore = useSystemStore()

// 数据
const loading = ref(false)
const stats = ref({
  email: { total: 0, today: 0, unread: 0 },
  r2: { fileCount: 0 },
  forward: { total: 0, success: 0, failed: 0, recentLogs: [] }
})
const recentEmails = ref<any[]>([])

// 转发日志相关
const forwardLogsModalVisible = ref(false)
const forwardLogDetailVisible = ref(false)
const loadingForwardLogs = ref(false)
const forwardLogs = ref<any[]>([])
const forwardLogsFilter = ref('')
const forwardLogsPagination = ref({
  page: 1,
  limit: 20,
  total: 0,
  totalPages: 0
})
const currentForwardLog = ref<any>(null)

// 轮询相关
let pollingInterval: number | null = null
const POLLING_INTERVAL = 5000 // 5秒

// 计算属性
const pageTitle = computed(() => '仪表板')
const pageIcon = computed(() => '📊')
const isDebugMode = computed(() => systemStore.isDebugMode)

// 方法
const loadDashboardData = async (forceRefresh = false) => {
  if (loading.value) {
    console.log('📊 仪表板数据正在加载中，跳过重复请求')
    return
  }

  loading.value = true
  try {
    console.log('📊 开始加载仪表板数据', { forceRefresh })

    // 加载统计数据
    const statsResponse = await get('/api/dashboard/stats')
    if (statsResponse.success && statsResponse.data.stats) {
      stats.value = statsResponse.data.stats
      console.log('📊 统计数据已更新:', stats.value)
    }

    // 加载最近邮件（前10条）
    const emailsResponse = await get('/api/emails', { params: { page: 1, limit: 10 } })
    if (emailsResponse.success) {
      recentEmails.value = emailsResponse.data.items || []
      console.log('📧 最近邮件已更新:', recentEmails.value.length)
    }

    console.log('📊 仪表板数据加载完成')
  } catch (error) {
    console.error('加载仪表板数据失败:', error)
  } finally {
    loading.value = false
  }
}

const refreshData = async () => {
  console.log('🔄 手动刷新仪表板')
  await loadDashboardData(true)
}

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
  router.push({ name: 'all-emails', query: { email: emailId } })
}

const goToEmails = () => {
  router.push('/all-emails')
}

const goToSettings = () => {
  router.push('/system-settings')
}

// 转发日志相关方法
const showForwardLogsModal = async () => {
  forwardLogsModalVisible.value = true
  await loadForwardLogs(1)
}

const loadForwardLogs = async (page: number = 1) => {
  loadingForwardLogs.value = true
  try {
    const params: any = { page, limit: forwardLogsPagination.value.limit }
    if (forwardLogsFilter.value) {
      params.status = forwardLogsFilter.value
    }

    const response = await get('/api/dashboard/forward-logs', { params })
    if (response.success) {
      forwardLogs.value = response.data.items || []
      forwardLogsPagination.value = {
        page: response.data.page,
        limit: response.data.limit,
        total: response.data.total,
        totalPages: response.data.totalPages
      }
    }
  } catch (error) {
    console.error('加载转发日志失败:', error)
  } finally {
    loadingForwardLogs.value = false
  }
}

const viewForwardLogDetail = async (log: any) => {
  try {
    // 如果日志已经有完整信息，直接显示
    if (log.webhook_url) {
      currentForwardLog.value = log
      forwardLogDetailVisible.value = true
      return
    }

    // 否则从 API 加载详情
    const response = await get(`/api/dashboard/forward-logs/${log.id}`)
    if (response.success && response.data.log) {
      currentForwardLog.value = response.data.log
      forwardLogDetailVisible.value = true
    }
  } catch (error) {
    console.error('加载转发日志详情失败:', error)
  }
}

// 管理模态窗口（暂时跳转到对应路由）
const showDatabaseModal = () => {
  router.push('/debug#database')
}

const showCacheModal = () => {
  router.push('/debug#cache')
}

const showR2FilesModal = () => {
  router.push('/debug#r2')
}

// 启动轮询
const startPolling = () => {
  if (pollingInterval) return

  pollingInterval = window.setInterval(async () => {
    console.log('🔄 自动轮询更新仪表板数据')
    await loadDashboardData()
  }, POLLING_INTERVAL)

  console.log('✅ 仪表板轮询已启动（间隔 5 秒）')
}

// 停止轮询
const stopPolling = () => {
  if (pollingInterval) {
    clearInterval(pollingInterval)
    pollingInterval = null
    console.log('⏸️ 仪表板轮询已停止')
  }
}

// 监听过滤器变化
import { watch } from 'vue'
watch(forwardLogsFilter, () => {
  if (forwardLogsModalVisible.value) {
    loadForwardLogs(1)
  }
})

// 组件挂载时加载数据
onMounted(() => {
  loadDashboardData()
  startPolling()

  // 注册全局刷新函数
  window.refreshCurrentPage = refreshData
})

// 页面卸载时清理
onUnmounted(() => {
  stopPolling()
  
  // 清理全局刷新函数
  if (window.refreshCurrentPage === refreshData) {
    delete window.refreshCurrentPage
  }
})
</script>

<style scoped>
.loading-overlay {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 40px;
  color: #6c757d;
}

.loading-spinner {
  width: 32px;
  height: 32px;
  border: 3px solid #f3f3f3;
  border-top: 3px solid #007bff;
  border-radius: 50%;
  animation: spin 1s linear infinite;
  margin-bottom: 16px;
}

@keyframes spin {
  0% {
    transform: rotate(0deg);
  }

  100% {
    transform: rotate(360deg);
  }
}

.dashboard-container {
  display: flex;
  flex-direction: column;
  gap: 24px;
}

.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 16px;
  margin-bottom: 8px;
}

.stat-card {
  background: white;
  border-radius: 10px;
  padding: 20px;
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.08);
  display: flex;
  align-items: center;
  gap: 12px;
  transition: all 0.3s ease;
  border: 1px solid rgba(0, 0, 0, 0.05);
}

.stat-card:hover {
  transform: translateY(-4px);
  box-shadow: 0 8px 25px rgba(0, 0, 0, 0.15);
  border-color: rgba(52, 152, 219, 0.2);
}

.stat-card.clickable {
  cursor: pointer;
}

.stat-card.clickable:hover {
  background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
}

.stat-icon {
  font-size: 32px;
  width: 48px;
  height: 48px;
  display: flex;
  align-items: center;
  justify-content: center;
  background: #f8f9fa;
  border-radius: 8px;
  flex-shrink: 0;
}

.stat-content {
  flex: 1;
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.stat-number {
  font-size: 28px;
  font-weight: 700;
  color: #2c3e50;
  line-height: 1;
}

.stat-label {
  color: #6c757d;
  font-size: 14px;
  font-weight: 500;
}

.stat-sub {
  color: #95a5a6;
  font-size: 12px;
  margin-top: 4px;
}

.management-section {
  background: white;
  border-radius: 10px;
  padding: 20px;
  box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
}

.management-section h2 {
  margin: 0 0 16px 0;
  color: #2c3e50;
  font-size: 18px;
  font-weight: 600;
}

.management-buttons {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 12px;
}

.btn {
  padding: 12px 20px;
  border: none;
  border-radius: 8px;
  font-size: 14px;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.3s ease;
  text-align: center;
}

.btn-secondary {
  background: #f8f9fa;
  color: #2c3e50;
  border: 1px solid #e9ecef;
}

.btn-secondary:hover {
  background: #e9ecef;
  transform: translateY(-2px);
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
}

.content-section {
  background: white;
  border-radius: 10px;
  padding: 20px;
  box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
  display: flex;
  flex-direction: column;
}

.content-section h2 {
  margin: 0 0 16px 0;
  color: #2c3e50;
  font-size: 18px;
  font-weight: 600;
}

.empty-state {
  text-align: center;
  padding: 40px;
  color: #6c757d;
}

.recent-emails {
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.email-item {
  padding: 15px;
  background: #f8f9fa;
  border-radius: 8px;
  cursor: pointer;
  transition: all 0.3s ease;
  border: 1px solid #e9ecef;
}

.email-item:hover {
  background: #e9ecef;
  border-color: #3498db;
}

.email-subject {
  font-weight: 500;
  color: #2c3e50;
  margin-bottom: 5px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.email-meta {
  display: flex;
  justify-content: space-between;
  align-items: center;
  font-size: 12px;
  color: #6c757d;
}

.email-from {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  flex: 1;
  margin-right: 10px;
}

.forward-logs {
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.log-item {
  padding: 12px;
  background: #f8f9fa;
  border-radius: 8px;
  cursor: pointer;
  transition: all 0.3s ease;
  border: 1px solid #e9ecef;
  display: flex;
  gap: 12px;
  align-items: center;
}

.log-item:hover {
  background: #e9ecef;
  border-color: #3498db;
}

.log-status {
  flex-shrink: 0;
}

.status-badge {
  display: inline-block;
  padding: 4px 8px;
  border-radius: 4px;
  font-size: 12px;
  font-weight: 500;
}

.status-badge.success {
  background: #d4edda;
  color: #155724;
}

.status-badge.error {
  background: #f8d7da;
  color: #721c24;
}

.log-content {
  flex: 1;
  min-width: 0;
}

.log-subject {
  font-weight: 500;
  color: #2c3e50;
  margin-bottom: 4px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.log-meta {
  display: flex;
  gap: 12px;
  font-size: 12px;
  color: #6c757d;
}

.log-time {
  margin-left: auto;
}

/* 转发日志模态窗口样式 */
.forward-logs-modal {
  min-height: 400px;
  max-height: 600px;
  overflow-y: auto;
}

.filter-bar {
  display: flex;
  gap: 16px;
  margin-bottom: 16px;
  padding: 12px;
  background: #f8f9fa;
  border-radius: 8px;
}

.filter-bar label {
  display: flex;
  align-items: center;
  gap: 6px;
  cursor: pointer;
  font-size: 14px;
}

.filter-bar input[type="radio"] {
  cursor: pointer;
}

.logs-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.log-row {
  display: flex;
  gap: 12px;
  padding: 12px;
  background: #f8f9fa;
  border-radius: 8px;
  cursor: pointer;
  transition: all 0.2s ease;
  border: 1px solid #e9ecef;
}

.log-row:hover {
  background: #e9ecef;
  border-color: #3498db;
}

.log-status-col {
  flex-shrink: 0;
}

.log-info-col {
  flex: 1;
  min-width: 0;
}

.log-details {
  display: flex;
  gap: 12px;
  font-size: 12px;
  color: #6c757d;
  margin-top: 4px;
}

.log-error {
  font-size: 12px;
  color: #dc3545;
  margin-top: 4px;
}

/* 转发日志详情样式 */
.log-detail {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.detail-row {
  display: flex;
  gap: 12px;
}

.detail-row label {
  font-weight: 600;
  color: #6c757d;
  min-width: 100px;
  flex-shrink: 0;
}

.detail-row span {
  color: #2c3e50;
  word-break: break-word;
}

.url-text {
  font-family: monospace;
  font-size: 12px;
}

.error-text {
  color: #dc3545;
}

.detail-divider {
  height: 1px;
  background: #e9ecef;
  margin: 12px 0;
}

.log-detail h3 {
  margin: 8px 0;
  color: #2c3e50;
  font-size: 16px;
  font-weight: 600;
}

@media (max-width: 768px) {
  .stats-grid {
    grid-template-columns: repeat(2, 1fr);
    gap: 12px;
  }

  .stat-card {
    padding: 16px;
  }

  .stat-icon {
    font-size: 24px;
    width: 40px;
    height: 40px;
  }

  .stat-number {
    font-size: 20px;
  }

  .stat-label {
    font-size: 12px;
  }

  .management-buttons {
    grid-template-columns: 1fr 1fr;
  }
}
</style>
