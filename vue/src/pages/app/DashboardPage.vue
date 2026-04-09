<template>
  <div class="page-content">
    <!-- 统一页面头部 -->
    <PageHeader :title="`${pageIcon} ${pageTitle}`" :show-search="false" :show-refresh="false" />

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
            <div class="stat-label">邮件</div>
            <div class="stat-sub">今日: {{ stats.email.today || 0 }} | 未读: {{ stats.email.unread || 0 }}</div>
            <div class="stat-sub">总邮件数：{{ stats.email.total || 0 }}</div>
          </div>
        </div>

        <div class="stat-card">
          <div class="stat-icon">📁</div>
          <div class="stat-content">
            <div class="stat-label">R2</div>
            <div class="stat-sub">邮件：{{ stats.r2.emailCount || 0 }} | 附件：{{ stats.r2.attachmentCount || 0 }}</div>
          </div>
        </div>

        <div class="stat-card clickable" @click="goToRouting">
          <div class="stat-icon">📤</div>
          <div class="stat-content">
            <div class="stat-label">转发</div>
            <div class="stat-sub">成功：{{ stats.forward.success || 0 }} | 失败：{{ stats.forward.failed || 0 }}</div>
            <div class="stat-sub">总数：{{ stats.forward.total || 0 }}</div>
          </div>
        </div>

        <div class="stat-card clickable action-card" @click="() => goToTools()">
          <div class="stat-icon">🛠️</div>
          <div class="stat-content">
            <div class="stat-label">工具</div>
            <div class="stat-number">{{ isDebugMode ? 'ON' : 'OFF' }}</div>
          </div>
        </div>
      </div>

      <!-- 快捷跳转面板 -->
      <div class="management-section">
        <h2>快捷跳转</h2>
        <div class="management-buttons">
          <button class="btn btn-secondary" @click="goToTools('database')">
            🗄️ 数据库管理
          </button>
          <button class="btn btn-secondary" @click="goToTools('cache')">
            💾 缓存管理
          </button>
          <button class="btn btn-secondary" @click="goToRouting">
            🧭 消息路由
          </button>
          <button class="btn btn-secondary" @click="goToTools('r2')">
            📁 R2 文件管理
          </button>
          <button v-if="isDebugMode" class="btn btn-secondary" @click="goToTools('simulate')">
            📧 模拟邮件接收
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
            <span class="email-subject">{{ email.subject }}</span>
            <span class="email-separator">·</span>
            <span class="email-from">{{ email.from }}</span>
            <span class="email-time">{{ formatTime(email.received_at) }}</span>
          </div>
        </div>
      </div>
    </div>

  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useRouter } from 'vue-router'
import { useSystemStore } from '@/composables/system'
import { PageHeader } from '@/components/common'
import { get } from '@/composables/api-client'
import { cacheService } from '@/composables/cache'

const router = useRouter()
const systemStore = useSystemStore()

// 数据
const loading = ref(false)
const stats = ref({
  email: { total: 0, today: 0, unread: 0 },
  r2: { emailCount: 0, attachmentCount: 0 },
  forward: { total: 0, success: 0, failed: 0, recentLogs: [] }
})
const recentEmails = ref<any[]>([])

// 计算属性
const pageTitle = computed(() => '仪表板')
const pageIcon = computed(() => '📊')
const isDebugMode = computed(() => systemStore.isDebugMode)

// 缓存配置
const CACHE_KEYS = {
  DASHBOARD_STATS: 'dashboard:stats',
  DASHBOARD_EMAILS: 'dashboard:recent_emails'
}
const CACHE_TTL = 2 * 60 * 1000 // 2分钟（前端缓存，比后端5分钟短）

// 方法：加载统计数据（邮箱数、R2数、转发数）
const loadStats = async (forceRefresh = false) => {
  if (loading.value) {
    console.log('📊 统计数据正在加载中，跳过重复请求')
    return
  }

  loading.value = true
  try {
    console.log('📊 开始加载统计数据', { forceRefresh })

    // 加载统计数据（带前端缓存）
    let statsData = null
    if (!forceRefresh) {
      // 尝试从缓存获取
      const cachedStats = cacheService.get<any>(CACHE_KEYS.DASHBOARD_STATS)
      if (cachedStats !== undefined) {
        console.log('📦 从缓存读取统计数据')
        statsData = cachedStats
        // 使用缓存数据更新 ref（响应式更新）
        stats.value = cachedStats
      }
    }

    // 如果缓存未命中或强制刷新，从后端获取
    if (!statsData || forceRefresh) {
      const statsResponse = await get('/dashboard/stats')
      if (statsResponse.success && statsResponse.data.stats) {
        statsData = statsResponse.data.stats
        // 更新 ref（响应式更新，UI 会自动刷新）
        stats.value = statsData
        // 写入缓存
        cacheService.set(CACHE_KEYS.DASHBOARD_STATS, statsData, CACHE_TTL)
        console.log('📊 统计数据已更新（从后端）:', {
          cached: statsResponse.data.cached || false,
          timestamp: statsData.timestamp
        })
      }
    }

    console.log('📊 统计数据加载完成')
  } catch (error) {
    console.error('加载统计数据失败:', error)
  } finally {
    loading.value = false
  }
}

// 方法：加载最近邮件
const loadRecentEmails = async (forceRefresh = false) => {
  try {
    // 尝试从缓存获取
    const cachedEmails = forceRefresh ? undefined : cacheService.get<any[]>(CACHE_KEYS.DASHBOARD_EMAILS)
    if (cachedEmails !== undefined) {
      console.log('📦 从缓存读取最近邮件')
      recentEmails.value = cachedEmails
      return
    }

    // 缓存未命中，从后端获取
    const emailsResponse = await get('/emails', { params: { page: 1, limit: 10 } })
    if (emailsResponse.success) {
      const emailsData = emailsResponse.data.items || []
      // 更新 ref（响应式更新，UI 会自动刷新）
      recentEmails.value = emailsData
      // 写入缓存
      cacheService.set(CACHE_KEYS.DASHBOARD_EMAILS, emailsData, CACHE_TTL)
      console.log('📧 最近邮件已更新（从后端）:', emailsData.length)
    }
  } catch (error) {
    console.error('加载最近邮件失败:', error)
  }
}

// 方法：加载完整仪表板数据（首次加载时使用）
const loadDashboardData = async (forceRefresh = false) => {
  await Promise.all([
    loadStats(forceRefresh),
    loadRecentEmails(forceRefresh)
  ])
}

// 刷新功能：刷新当前仪表板所需数据
const refreshData = async () => {
  console.log('🔄 刷新仪表板数据')
  // 清除缓存，强制从后端获取最新数据
  cacheService.delete(CACHE_KEYS.DASHBOARD_STATS)
  cacheService.delete(CACHE_KEYS.DASHBOARD_EMAILS)
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

const goToRouting = () => {
  router.push('/routing')
}

const goToTools = (section?: string) => {
  if (section) {
    router.push({ path: '/tools', query: { section } })
  } else {
    router.push('/tools')
  }
}

// 组件挂载时加载数据
onMounted(() => {
  // 首次加载完整数据
  loadDashboardData()

  // 注册全局刷新函数
  window.refreshCurrentPage = refreshData
})

// 页面卸载时清理
onUnmounted(() => {
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
  max-width: 1280px;
  margin: 0 auto;
}

@media (min-width: 1200px) {
  .dashboard-container {
    display: flex;
    flex-direction: column;
    gap: 24px;
  }
}

.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 18px;
  margin-bottom: 8px;
}

@media (max-width: 768px) {
  .stats-grid {
    grid-template-columns: 1fr;
  }
}

.stat-card {
  background: linear-gradient(180deg, rgba(255, 255, 255, 0.98), rgba(245, 249, 253, 0.95));
  border-radius: 22px;
  padding: 22px;
  box-shadow: 0 24px 42px -36px rgba(15, 23, 42, 0.8);
  display: flex;
  align-items: center;
  gap: 14px;
  transition: all 0.3s ease;
  border: 1px solid rgba(15, 23, 42, 0.08);
  width: 100%;
  min-height: 110px;
  box-sizing: border-box;
}

.stat-card:hover {
  transform: translateY(-4px);
  box-shadow: 0 28px 46px -34px rgba(15, 23, 42, 0.55);
  border-color: rgba(43, 103, 246, 0.18);
}

.stat-card.clickable {
  cursor: pointer;
}

.stat-card.clickable:hover {
  background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
}

.stat-card.stat-success:hover {
  background: linear-gradient(135deg, #f0fff4 0%, #e0ffe0 100%);
  border-color: rgba(40, 167, 69, 0.2);
}

.stat-card.stat-error:hover {
  background: linear-gradient(135deg, #fff5f5 0%, #ffe0e0 100%);
  border-color: rgba(220, 53, 69, 0.2);
}

.stat-icon {
  font-size: 30px;
  width: 56px;
  height: 56px;
  display: flex;
  align-items: center;
  justify-content: center;
  background: linear-gradient(135deg, rgba(43, 103, 246, 0.12), rgba(245, 160, 67, 0.16));
  border-radius: 18px;
  flex-shrink: 0;
}

.stat-content {
  flex: 1;
  display: flex;
  flex-direction: column;
  gap: 4px;
  min-width: 0;
}

.stat-number {
  font-size: 30px;
  font-weight: 700;
  color: #17324a;
  line-height: 1;
}

.stat-label {
  color: #6c757d;
  font-size: 14px;
  font-weight: 500;
  margin-bottom: 4px;
}

.stat-sub {
  color: #95a5a6;
  font-size: 12px;
  margin-top: 4px;
}

.management-section {
  background: rgba(255, 255, 255, 0.96);
  border-radius: 24px;
  padding: 22px;
  box-shadow: 0 24px 42px -38px rgba(15, 23, 42, 0.85);
  border: 1px solid rgba(15, 23, 42, 0.08);
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
  gap: 14px;
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
  background: linear-gradient(180deg, #fbfcfe 0%, #edf3f8 100%);
  color: #21405c;
  border: 1px solid rgba(21, 52, 82, 0.08);
}

.btn-secondary:hover {
  background: #e9ecef;
  transform: translateY(-2px);
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
}

.content-section {
  background: rgba(255, 255, 255, 0.96);
  border-radius: 24px;
  padding: 22px;
  box-shadow: 0 24px 42px -38px rgba(15, 23, 42, 0.85);
  border: 1px solid rgba(15, 23, 42, 0.08);
  display: flex;
  flex-direction: column;
}

.recent-emails-section {
  max-width: 100%;
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
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(min(360px, 100%), 1fr));
  gap: 10px;
  width: 100%;
  min-width: 0;
}

.email-item {
  padding: 14px 16px;
  background: linear-gradient(180deg, rgba(247, 250, 252, 0.94), rgba(255, 255, 255, 0.98));
  border-radius: 16px;
  cursor: pointer;
  transition: all 0.3s ease;
  border: 1px solid #e9ecef;
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 14px;
  line-height: 1.5;
  width: 100%;
  min-width: 0;
  box-sizing: border-box;
}

.email-item:hover {
  background: #e9ecef;
  border-color: #3498db;
}

.email-subject {
  font-weight: 500;
  color: #2c3e50;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  flex: 1;
  min-width: 0;
}

.email-separator {
  color: #adb5bd;
  flex-shrink: 0;
}

.email-from {
  color: #6c757d;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  flex-shrink: 0;
  max-width: 200px;
}

.email-time {
  color: #6c757d;
  font-size: 12px;
  flex-shrink: 0;
  margin-left: auto;
}


@media (max-width: 1199px) {
  .dashboard-container {
    display: flex;
    flex-direction: column;
  }
}

@media (max-width: 768px) {
  .stats-grid {
    grid-template-columns: 1fr;
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
    grid-template-columns: 1fr;
  }

  .recent-emails-section {
    max-width: 100%;
  }

  .recent-emails {
    grid-template-columns: 1fr;
  }

  .email-item {
    font-size: 13px;
    padding: 10px 12px;
    gap: 6px;
    flex-wrap: wrap;
  }

  .email-from {
    max-width: 100%;
  }

  .email-time {
    font-size: 11px;
    width: 100%;
    margin-left: 0;
  }
}
</style>
