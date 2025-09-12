<template>
  <div class="dashboard-page">
    <div class="dashboard-header">
      <h1>仪表板</h1>
      <p>欢迎使用临时邮箱管理系统</p>
    </div>
    
    <div class="dashboard-stats">
      <div class="stat-card">
        <div class="stat-icon">📧</div>
        <div class="stat-content">
          <div class="stat-number">{{ emailStats.total }}</div>
          <div class="stat-label">总邮件数</div>
        </div>
      </div>
      
      <div class="stat-card">
        <div class="stat-icon">📮</div>
        <div class="stat-content">
          <div class="stat-number">{{ mailboxStats.total }}</div>
          <div class="stat-label">我的邮箱</div>
        </div>
      </div>
      
      <div class="stat-card">
        <div class="stat-icon">📝</div>
        <div class="stat-content">
          <div class="stat-number">{{ applicationStats.total }}</div>
          <div class="stat-label">待审核申请</div>
        </div>
      </div>
    </div>
    
    <div class="dashboard-content">
      <div class="content-section">
        <h2>最近邮件</h2>
        <div v-if="recentEmails.length === 0" class="empty-state">
          <p>暂无邮件</p>
        </div>
        <div v-else class="recent-emails">
          <div 
            v-for="email in recentEmails" 
            :key="email.id"
            class="email-item"
            @click="viewEmail(email.id)"
          >
            <div class="email-subject">{{ email.subject }}</div>
            <div class="email-meta">
              <span class="email-from">{{ email.from }}</span>
              <span class="email-time">{{ formatTime(email.received_at) }}</span>
            </div>
          </div>
        </div>
      </div>
      
      <div class="content-section">
        <h2>快速操作</h2>
        <div class="quick-actions">
          <button class="action-btn" @click="goToEmails">
            📧 查看邮件
          </button>
          <button class="action-btn" @click="goToMailboxes">
            📮 管理邮箱
          </button>
          <button class="action-btn" @click="goToSettings">
            ⚙️ 账户设置
          </button>
          <button v-if="isAdmin" class="action-btn admin-action" @click="goToAdmin">
            👥 管理面板
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import { apiService, type EmailSummary } from '@/api'

const router = useRouter()
const authStore = useAuthStore()

// 统计数据
const emailStats = ref({ total: 0 })
const mailboxStats = ref({ total: 0 })
const applicationStats = ref({ total: 0 })
const recentEmails = ref<EmailSummary[]>([])

// 计算属性
const isAdmin = computed(() => authStore.isAdmin)

// 方法
const loadDashboardData = async () => {
  try {
    // 加载邮件统计
    const emailResponse = await apiService.getEmails(1, 1)
    if (emailResponse.success && emailResponse.data) {
      emailStats.value.total = emailResponse.data.total
    }
    
    // 加载最近邮件
    const recentResponse = await apiService.getEmails(1, 5)
    if (recentResponse.success && recentResponse.data) {
      recentEmails.value = recentResponse.data.items
    }
    
    // 加载邮箱统计
    const mailboxResponse = await apiService.getMailboxes(1, 1)
    if (mailboxResponse.success && mailboxResponse.data) {
      mailboxStats.value.total = mailboxResponse.data.total
    }
    
    // 加载申请统计
    const applicationResponse = await apiService.getMailboxApplications(1, 1)
    if (applicationResponse.success && applicationResponse.data) {
      applicationStats.value.total = applicationResponse.data.total
    }
  } catch (error) {
    console.error('加载仪表板数据失败:', error)
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

const goToEmails = () => {
  router.push('/emails')
}

const goToMailboxes = () => {
  router.push('/mailboxes')
}

const goToSettings = () => {
  router.push('/settings')
}

const goToAdmin = () => {
  router.push('/admin-users')
}

// 组件挂载时加载数据
onMounted(() => {
  loadDashboardData()
})
</script>

<style scoped>
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
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
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
  transition: transform 0.3s ease;
}

.stat-card:hover {
  transform: translateY(-2px);
}

.stat-icon {
  font-size: 32px;
  width: 50px;
  height: 50px;
  display: flex;
  align-items: center;
  justify-content: center;
  background: #f8f9fa;
  border-radius: 10px;
}

.stat-content {
  flex: 1;
}

.stat-number {
  font-size: 24px;
  font-weight: 600;
  color: #2c3e50;
  margin-bottom: 5px;
}

.stat-label {
  color: #6c757d;
  font-size: 14px;
}

.dashboard-content {
  display: grid;
  grid-template-columns: 2fr 1fr;
  gap: 20px;
}

.content-section {
  background: white;
  border-radius: 10px;
  padding: 20px;
  box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
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

.quick-actions {
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.action-btn {
  padding: 12px 16px;
  background: #f8f9fa;
  border: 1px solid #e9ecef;
  border-radius: 8px;
  cursor: pointer;
  transition: all 0.3s ease;
  text-align: left;
  font-size: 14px;
  color: #2c3e50;
}

.action-btn:hover {
  background: #e9ecef;
  border-color: #3498db;
  transform: translateX(5px);
}

.admin-action {
  background: #fff3cd;
  border-color: #ffeaa7;
  color: #856404;
}

.admin-action:hover {
  background: #ffeaa7;
  border-color: #fdcb6e;
}

@media (max-width: 768px) {
  .dashboard-stats {
    grid-template-columns: 1fr;
  }
  
  .dashboard-content {
    grid-template-columns: 1fr;
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
</style>