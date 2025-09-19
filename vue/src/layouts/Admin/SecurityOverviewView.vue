<template>
  <div class="security-overview-page">
    <div class="page-header">
      <h1>🛡️ 安全概览</h1>
    </div>

    <div class="security-overview-content">
      <LoadingOverlay :show="loading" text="加载安全数据..." type="local" />

      <div v-if="!loading" class="security-stats">
        <div class="stat-card">
          <div class="stat-icon">🔒</div>
          <div class="stat-content">
            <div class="stat-number">{{ securityStats.totalUsers }}</div>
            <div class="stat-label">总用户数</div>
          </div>
        </div>

        <div class="stat-card">
          <div class="stat-icon">📧</div>
          <div class="stat-content">
            <div class="stat-number">{{ securityStats.totalEmails }}</div>
            <div class="stat-label">总邮件数</div>
          </div>
        </div>

        <div class="stat-card">
          <div class="stat-icon">⚠️</div>
          <div class="stat-content">
            <div class="stat-number">{{ securityStats.suspiciousActivities }}</div>
            <div class="stat-label">可疑活动</div>
          </div>
        </div>

        <div class="stat-card">
          <div class="stat-icon">🛡️</div>
          <div class="stat-content">
            <div class="stat-number">{{ securityStats.blockedEmails }}</div>
            <div class="stat-label">已拦截邮件</div>
          </div>
        </div>
      </div>

      <div v-if="!loading" class="security-details">
        <div class="detail-section">
          <h2>最近安全事件</h2>
          <div v-if="securityEvents.length === 0" class="empty-state">
            <p>暂无安全事件</p>
          </div>
          <div v-else class="events-list">
            <div v-for="event in securityEvents" :key="event.id" class="event-item">
              <div class="event-type">{{ event.type }}</div>
              <div class="event-description">{{ event.description }}</div>
              <div class="event-time">{{ formatTime(event.created_at) }}</div>
            </div>
          </div>
        </div>

        <div class="detail-section">
          <h2>系统状态</h2>
          <div class="system-status">
            <div class="status-item">
              <span class="status-label">数据库状态:</span>
              <span class="status-value status-healthy">正常</span>
            </div>
            <div class="status-item">
              <span class="status-label">邮件服务:</span>
              <span class="status-value status-healthy">正常</span>
            </div>
            <div class="status-item">
              <span class="status-label">存储服务:</span>
              <span class="status-value status-healthy">正常</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import LoadingOverlay from '@/layouts/AppLoadingSpinner.vue'

const securityStats = ref({
  totalUsers: 0,
  totalEmails: 0,
  suspiciousActivities: 0,
  blockedEmails: 0
})

const securityEvents = ref<any[]>([])
const loading = ref(false)

const loadSecurityData = async () => {
  loading.value = true
  try {
    // 这里可以调用 API 加载安全数据
    // const response = await apiService.getSecurityOverview()
    // if (response.success && response.data) {
    //   securityStats.value = response.data.stats
    //   securityEvents.value = response.data.events
    // }
  } catch (error) {
    console.error('加载安全数据失败:', error)
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

onMounted(() => {
  loadSecurityData()
})
</script>

<style scoped>
.security-overview-page {
  padding: 20px;
  background: #f8f9fa;
  min-height: 100%;
}

.page-header {
  margin-bottom: 20px;
}

.page-header h1 {
  margin: 0;
  color: #2c3e50;
  font-size: 24px;
  font-weight: 600;
}

.security-overview-content {
  position: relative;
  min-height: 200px;
}

.security-stats {
  display: grid;
  grid-template-columns: repeat(auto-fit, 200px);
  gap: 20px;
  margin-bottom: 30px;
}

.stat-card {
  background: white;
  border-radius: 10px;
  padding: 20px;
  box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
  display: flex;
  align-items: center;
  gap: 15px;
  transition: all 0.3s ease;
}

.stat-card:hover {
  transform: translateY(-2px);
  box-shadow: 0 4px 20px rgba(0, 0, 0, 0.15);
}

.stat-icon {
  font-size: 24px;
  width: 40px;
  height: 40px;
  display: flex;
  align-items: center;
  justify-content: center;
  background: #f8f9fa;
  border-radius: 8px;
}

.stat-content {
  display: flex;
  flex-direction: column;
}

.stat-number {
  font-size: 24px;
  font-weight: 700;
  color: #2c3e50;
  margin-bottom: 5px;
}

.stat-label {
  color: #6c757d;
  font-size: 14px;
  font-weight: 500;
}

.security-details {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 20px;
}

.detail-section {
  background: white;
  border-radius: 10px;
  padding: 20px;
  box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
}

.detail-section h2 {
  margin: 0 0 20px 0;
  color: #2c3e50;
  font-size: 18px;
  font-weight: 600;
}

.empty-state {
  text-align: center;
  padding: 20px;
  color: #6c757d;
}

.events-list {
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.event-item {
  padding: 15px;
  background: #f8f9fa;
  border-radius: 8px;
  border-left: 4px solid #3498db;
}

.event-type {
  font-weight: 500;
  color: #2c3e50;
  margin-bottom: 5px;
}

.event-description {
  color: #6c757d;
  font-size: 14px;
  margin-bottom: 5px;
}

.event-time {
  color: #6c757d;
  font-size: 12px;
}

.system-status {
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.status-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 10px;
  background: #f8f9fa;
  border-radius: 6px;
}

.status-label {
  color: #2c3e50;
  font-weight: 500;
}

.status-value {
  padding: 4px 8px;
  border-radius: 12px;
  font-size: 12px;
  font-weight: 500;
}

.status-healthy {
  background: #d4edda;
  color: #155724;
}

@media (max-width: 768px) {
  .security-stats {
    grid-template-columns: repeat(2, 1fr);
    gap: 15px;
  }

  .security-details {
    grid-template-columns: 1fr;
  }
}
</style>
