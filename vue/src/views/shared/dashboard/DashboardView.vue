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
      <div class="stat-card clickable" @click="goToEmails">
        <div class="stat-icon">📧</div>
        <div class="stat-content">
          <div class="stat-number">{{ emailStats?.total }}</div>
          <div class="stat-label">总邮件数</div>
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

      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore } from '@/composables/stores'
import { useSystemStore } from '@/composables/system'
import { useRouteApiManager } from '@/composables/routeApiManager'
import { PageHeader } from '@/components/common'
// import SecurityWidget from '@/components/SecurityWidget.vue'

const router = useRouter()
const authStore = useAuthStore()
const systemStore = useSystemStore()

// 使用统一接口管理器
const apiManager = useRouteApiManager()

// 数据
const emailStats = ref({ total: 0 })
const recentEmails = ref<any[]>([])

// 计算属性
// 页面标题和图标
const pageTitle = computed(() => '仪表板')
const pageIcon = computed(() => '📊')
const loading = ref(false)
// 调试模式
const isDebugMode = computed(() => systemStore.isDebugMode)


// 方法
const loadDashboardData = async (forceRefresh = false) => {
  // 防止重复调用
  if (loading.value) {
    console.log('📊 仪表板数据正在加载中，跳过重复请求', { forceRefresh })
    return
  }

  loading.value = true
  try {
    const userId = authStore.user?.id
    if (!userId) {
      console.error('用户ID不存在')
      return
    }

    console.log('📊 开始加载仪表板数据', { forceRefresh, userId })

    // 使用统一接口管理器加载路由的所有接口
    const results = await apiManager.loadRouteApis('dashboard', {
      forceRefresh,
      params: {
        getEmails: { page: 1, limit: 10 }
      }
    })

    console.log('📊 接口返回结果:', Object.keys(results))

    // 处理邮件数据
    if (results.getEmails?.success) {
      const emailsData = results.getEmails.data
      emailStats.value.total = emailsData?.total || 0
      recentEmails.value = emailsData?.items || []
      console.log('📧 邮件数据已更新:', { total: emailStats.value.total, count: recentEmails.value.length })
    }

    console.log('📊 仪表板数据加载完成')
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
  router.push({ name: 'all-emails', query: { email: emailId } })
}

const goToEmails = () => {
  router.push('/all-emails')
}

const goToSettings = () => {
  router.push('/system-settings')
}

// 全局刷新事件处理
const handleGlobalRefresh = () => {
  console.log('🔄 仪表板页面收到全局刷新事件')
  // 注意：这里不直接调用 loadDashboardData，因为 executeGlobalRefresh 会调用 refreshDashboardPage
  // 避免重复调用
}

// 暴露刷新方法给全局刷新按钮使用
const refreshDashboardPage = async () => {
  console.log('📊 DashboardView 页面级刷新触发')
  await loadDashboardData(true) // 使用统一的加载方法，传入强制刷新标志
}

// 组件挂载时加载数据
onMounted(() => {
  // 加载数据（路由配置已在 routeApiManager 中定义）
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
