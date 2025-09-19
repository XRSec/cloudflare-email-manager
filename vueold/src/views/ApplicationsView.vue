<template>
  <div class="applications-page">
    <div class="page-header">
      <h1>📝 邮箱申请记录</h1>
    </div>
    
    <div class="applications-content">
      <LoadingOverlay 
        :show="loading"
        text="加载申请记录..."
        type="local"
      />
      
      <div v-if="!loading && applications.length === 0" class="empty-state">
        <div class="empty-icon">📝</div>
        <p>暂无申请记录</p>
      </div>
      
      <div v-if="!loading && applications.length > 0" class="applications-list">
        <div 
          v-for="application in applications" 
          :key="application.application_id"
          class="application-item"
        >
          <div class="application-info">
            <div class="application-id">申请 #{{ application.application_id }}</div>
            <div class="application-status">
              <span class="status-badge" :class="getStatusClass(application.status)">
                {{ getStatusText(application.status) }}
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { apiService, type MailboxApplicationResponse } from '@/api'
import LoadingOverlay from '@/components/UI/LoadingOverlay.vue'

const applications = ref<MailboxApplicationResponse[]>([])
const loading = ref(false)

const loadApplications = async () => {
  loading.value = true
  try {
    const response = await apiService.getMailboxApplications()
    if (response.success && response.data) {
      applications.value = response.data.items
    }
  } catch (error) {
    console.error('加载申请记录失败:', error)
  } finally {
    loading.value = false
  }
}

const getStatusClass = (status: string) => {
  const statusMap: Record<string, string> = {
    pending: 'status-pending',
    approved: 'status-approved',
    rejected: 'status-rejected'
  }
  return statusMap[status] || 'status-default'
}

const getStatusText = (status: string) => {
  const statusMap: Record<string, string> = {
    pending: '待审核',
    approved: '已通过',
    rejected: '已拒绝'
  }
  return statusMap[status] || status
}

onMounted(() => {
  loadApplications()
})
</script>

<style scoped>
.applications-page {
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

.loading {
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 40px;
  color: #6c757d;
}

.spinner {
  width: 20px;
  height: 20px;
  border: 2px solid #f3f3f3;
  border-top: 2px solid #3498db;
  border-radius: 50%;
  animation: spin 1s linear infinite;
  margin-right: 10px;
}

@keyframes spin {
  0% { transform: rotate(0deg); }
  100% { transform: rotate(360deg); }
}

.empty-state {
  text-align: center;
  padding: 40px;
  color: #6c757d;
}

.empty-icon {
  font-size: 48px;
  margin-bottom: 15px;
}

.applications-content {
  position: relative;
  min-height: 200px;
}

.applications-list {
  display: flex;
  flex-direction: column;
  gap: 15px;
}

.application-item {
  background: white;
  border-radius: 10px;
  padding: 20px;
  box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
}

.application-info {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.application-id {
  font-weight: 500;
  color: #2c3e50;
}

.status-badge {
  padding: 4px 8px;
  border-radius: 12px;
  font-size: 12px;
  font-weight: 500;
}

.status-pending {
  background: #fff3cd;
  color: #856404;
}

.status-approved {
  background: #d4edda;
  color: #155724;
}

.status-rejected {
  background: #f8d7da;
  color: #721c24;
}

.status-default {
  background: #e2e3e5;
  color: #383d41;
}
</style>
