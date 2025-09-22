<template>
  <div class="page-content">
    <!-- 统一页面头部 -->
    <PageHeader :title="`${pageIcon} ${pageTitle}`" :show-search="false" :show-refresh="false" />

    <!-- 加载状态 -->
    <div v-if="loading" class="loading-overlay">
      <div class="loading-spinner"></div>
      <p>加载仪表板数据中...</p>
    </div>

    <div v-else class="dashboard-welcome">
      <p>欢迎使用邮箱管理系统</p>
    </div>

    <div class="dashboard-stats">
      <!-- 管理员专用统计 -->
      <div v-if="isAdmin" class="stat-card">
        <div class="stat-icon">📧</div>
        <div class="stat-content">
          <div class="stat-number">{{ emailStats?.total }}</div>
          <div class="stat-label">总邮件数</div>
        </div>
      </div>

      <!-- 我的邮箱 - 所有用户可见，可点击 -->
      <div class="stat-card clickable" @click="goToMailboxes">
        <div class="stat-icon">📮</div>
        <div class="stat-content">
          <div class="stat-number">{{ mailboxStats?.total }}</div>
          <div class="stat-label">我的邮箱</div>
        </div>
      </div>

      <!-- 管理员专用申请统计 -->
      <div v-if="isAdmin" class="stat-card">
        <div class="stat-icon">📝</div>
        <div class="stat-content">
          <div class="stat-number">{{ applicationStats?.total }}</div>
          <div class="stat-label">待审核申请</div>
        </div>
      </div>

      <!-- 管理员快捷操作 -->
      <div v-if="isAdmin" class="stat-card clickable action-card" @click="goToAdmin">
        <div class="stat-icon">👥</div>
        <div class="stat-content">
          <div class="action-label">用户管理</div>
        </div>
      </div>

      <div v-if="isAdmin" class="stat-card clickable action-card" @click="goToSettings">
        <div class="stat-icon">⚙️</div>
        <div class="stat-content">
          <div class="action-label">系统设置</div>
        </div>
      </div>
    </div>

    <div class="dashboard-content">
      <div class="content-grid">
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

        <!-- 安全概览 - 管理员专用 -->
        <div v-if="isAdmin" class="content-section security-section">
          <h2>安全概览</h2>
          <p>安全概览组件将在这里显示</p>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore } from '@/composables/stores'
import { apiService } from '@/composables/api'
import { smartCache, CacheKeys } from '@/composables/smartCache'
import PageHeader from '@/layouts/components/PageHeader.vue'
// import SecurityWidget from '@/components/SecurityWidget.vue'

const router = useRouter()
const authStore = useAuthStore()

// 数据
const emailStats = ref({ total: 0 })
const mailboxStats = ref({ total: 0 })
const applicationStats = ref({ total: 0 })
const recentEmails = ref<any[]>([])

// 计算属性
const isAdmin = computed(() => authStore.user?.user_type === 1)

// 页面标题和图标
const pageTitle = computed(() => '仪表板')
const pageIcon = computed(() => '📊')
const loading = ref(false)

// 智能预加载管理器
const preloadPageData = async (userId: number, forceRefresh = false) => {
  console.log('📊 智能预加载页面数据（仪表板复用）')

  // 预加载邮件数据（最近10封）
  const emailsRes = await loadEmailsData(userId, 1, 10, forceRefresh)

  return { emailsRes }
}

// 加载邮件数据（带缓存）
const loadEmailsData = async (userId: number, page: number, limit: number, forceRefresh = false) => {
  const cacheKey = CacheKeys.emailList(userId, page, limit, 'user')

  if (!forceRefresh) {
    const cached = smartCache.get(cacheKey)
    if (cached) {
      console.log('📧 从缓存加载邮件数据')
      return { success: true, data: cached }
    }
  }

  console.log('📧 从API加载邮件数据')
  const response = await apiService.getEmails({ page, limit })

  if (response.success) {
    // 缓存数据（10分钟）
    smartCache.set(cacheKey, response.data, {
      ttl: 10 * 60 * 1000,
      dependencies: ['new_email']
    })
  }

  return response
}


// 方法
const loadDashboardData = async (forceRefresh = false) => {
  loading.value = true
  try {
    const userId = authStore.user?.id
    if (!userId) {
      console.error('用户ID不存在')
      return
    }

    // 智能预加载页面数据
    const { emailsRes } = await preloadPageData(userId, forceRefresh)

    // 从预加载的数据中提取最近邮件
    if (emailsRes.success) {
      const emailsData = emailsRes.data
      recentEmails.value = emailsData?.items || []
    }

    console.log('📊 仪表板数据预加载完成，用户点击页面时将直接使用缓存数据')
  } catch (error) {
    console.error('加载仪表板数据失败:', error)
  } finally {
    loading.value = false
  }
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
  router.push({ name: 'emails', query: { email: emailId } })
}

// const goToEmails = () => {
//   router.push('/emails')
// }

const goToMailboxes = () => {
  router.push('/mailboxes')
}

const goToSettings = () => {
  router.push('/settings')
}

const goToAdmin = () => {
  router.push('/admin-users')
}

// 全局刷新事件处理
const handleGlobalRefresh = () => {
  console.log('🔄 仪表板页面收到全局刷新事件')
  loadDashboardData(true) // 强制刷新
}

// 暴露刷新方法给全局刷新按钮使用
const refreshDashboardPage = () => {
  console.log('📊 DashboardView 页面级刷新触发')
  loadDashboardData(true) // 强制刷新
}

// 组件挂载时加载数据
onMounted(() => {
  loadDashboardData()

  // 监听全局刷新事件
  window.addEventListener('global:refresh', handleGlobalRefresh)

  // 注册全局刷新函数
  window.refreshCurrentPage = refreshDashboardPage
})

// 页面卸载时清理事件监听
onUnmounted(() => {
  window.removeEventListener('global:refresh', handleGlobalRefresh)
  // 清理全局刷新函数
  if (window.refreshCurrentPage === refreshDashboardPage) {
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

.dashboard-page {
  padding: 20px;
  background: #f8f9fa;
  min-height: 100%;
}

.dashboard-header {
  margin-bottom: 30px;
}

.dashboard-header h1 {
  margin: 0 0 10px 0;
  color: #2c3e50;
  font-size: 28px;
  font-weight: 600;
}

.dashboard-header p {
  margin: 0;
  color: #6c757d;
  font-size: 16px;
}

.dashboard-stats {
  display: grid;
  grid-template-columns: repeat(auto-fit, 160px);
  gap: 15px;
  margin-bottom: 30px;
  justify-content: start
}

.stat-card {
  background: white;
  border-radius: 10px;
  padding: 16px;
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.08);
  display: flex;
  align-items: center;
  gap: 8px;
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
  transform: translateY(-4px);
  box-shadow: 0 8px 25px rgba(0, 0, 0, 0.15);
  border-color: rgba(52, 152, 219, 0.3);
  background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
}

.stat-icon {
  font-size: 24px;
  width: 36px;
  height: 36px;
  display: flex;
  align-items: center;
  justify-content: center;
  background: #f8f9fa;
  border-radius: 6px;
  flex-shrink: 0;
}

.stat-content {
  flex: 1;
  display: flex;
  flex-direction: column;
  align-items: center;
  text-align: center;
  min-width: 0;
}

.stat-number {
  font-size: 24px;
  font-weight: 700;
  color: #2c3e50;
  margin-bottom: 6px;
  line-height: 1;
}

.stat-label {
  color: #6c757d;
  font-size: 15px;
  font-weight: 500;
  line-height: 1.2;
}

.action-card {
  min-height: 80px;
}

.action-label {
  color: #2c3e50;
  font-size: 15px;
  font-weight: 600;
  line-height: 1.2;
}

.dashboard-content {
  display: grid;
  grid-template-columns: 1fr;
  gap: 20px;
}

.content-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 20px;
  align-items: start;
}

.content-section {
  background: white;
  border-radius: 10px;
  padding: 20px;
  box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
  min-height: 450px;
  display: flex;
  flex-direction: column;
}

.security-stats {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.security-stat-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 8px 0;
  border-bottom: 1px solid #f0f0f0;
}

.security-stat-item:last-child {
  border-bottom: none;
}

.security-stat-item .stat-label {
  color: #6c757d;
  font-size: 14px;
}

.security-stat-item .stat-value {
  color: #2c3e50;
  font-weight: 600;
  font-size: 16px;
}

.content-section h2 {
  margin: 0 0 20px 0;
  color: #2c3e50;
  font-size: 18px;
  font-weight: 600;
}

.empty-state {
  text-align: center;
  padding: 40px;
  color: #6c757d;
  flex: 1;
  display: flex;
  align-items: center;
  justify-content: center;
}

.recent-emails {
  display: flex;
  flex-direction: column;
  gap: 10px;
  flex: 1;
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

@media (max-width: 1200px) {
  .content-grid {
    grid-template-columns: 1fr 1fr;
  }
}

@media (max-width: 768px) {
  .dashboard-stats {
    grid-template-columns: repeat(2, 1fr);
    gap: 8px;
    margin-bottom: 20px;
  }

  .stat-card {
    padding: 12px;
    gap: 6px;
    min-height: 50px;
  }

  .stat-icon {
    font-size: 18px;
    width: 28px;
    height: 28px;
  }

  .stat-number {
    font-size: 16px;
    margin-bottom: 2px;
  }

  .stat-label {
    font-size: 10px;
    line-height: 1.2;
  }

  .action-card {
    min-height: 70px;
  }

  .dashboard-content {
    grid-template-columns: 1fr;
  }

  .content-grid {
    grid-template-columns: 1fr;
  }

  .content-section {
    min-height: 200px;
  }

  .email-meta {
    flex-direction: column;
    align-items: flex-start;
    gap: 5px;
  }

  .email-from {
    margin-right: 0;
  }
}

@media (max-width: 480px) {
  .dashboard-stats {
    grid-template-columns: 1fr 1fr 1fr;
    gap: 6px;
  }

  .stat-card {
    padding: 10px;
    gap: 4px;
    min-height: 45px;
  }

  .stat-icon {
    font-size: 16px;
    width: 24px;
    height: 24px;
  }

  .stat-number {
    font-size: 14px;
  }

  .stat-label {
    font-size: 10px;
  }

  .action-card {
    min-height: 60px;
  }
}

@media (max-width: 360px) {
  .dashboard-stats {
    gap: 4px;
  }

  .stat-card {
    padding: 8px;
    gap: 3px;
    min-height: 40px;
  }

  .stat-icon {
    font-size: 14px;
    width: 20px;
    height: 20px;
  }

  .stat-number {
    font-size: 12px;
  }

  .stat-label {
    font-size: 10px;
  }

  .action-card {
    min-height: 55px;
  }
}
</style>
