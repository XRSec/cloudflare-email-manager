<template>
  <div class="dashboard-page">
    <div class="dashboard-header">
      <h1>仪表板</h1>
      <p>欢迎使用临时邮箱管理系统</p>
    </div>
    
    <div class="dashboard-stats">
      <!-- 管理员专用统计 -->
      <div v-if="isAdmin" class="stat-card">
        <div class="stat-icon">📧</div>
        <div class="stat-content">
          <div class="stat-number">{{ emailStats.total }}</div>
          <div class="stat-label">总邮件数</div>
        </div>
      </div>
      
      <!-- 我的邮箱 - 所有用户可见，可点击 -->
      <div class="stat-card clickable" @click="goToMailboxes">
        <div class="stat-icon">📮</div>
        <div class="stat-content">
          <div class="stat-number">{{ mailboxStats.total }}</div>
          <div class="stat-label">我的邮箱</div>
        </div>
      </div>
      
      <!-- 管理员专用申请统计 -->
      <div v-if="isAdmin" class="stat-card">
        <div class="stat-icon">📝</div>
        <div class="stat-content">
          <div class="stat-number">{{ applicationStats.total }}</div>
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

        <!-- 安全概览 - 管理员专用 -->
        <div v-if="isAdmin" class="content-section security-section">
          <SecurityWidget />
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
import SecurityWidget from '@/components/SecurityWidget.vue'

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
    min-height: 250px;
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