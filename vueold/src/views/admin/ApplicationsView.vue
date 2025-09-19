<template>
  <div class="admin-applications-page">
    <div class="page-header">
      <h1>📋 邮箱申请审核</h1>
    </div>
    
    <div class="applications-content">
      <div v-if="loading" class="loading">
        <div class="spinner"></div>
        加载中...
      </div>
      
      <div v-else-if="applications.length === 0" class="empty-state">
        <div class="empty-icon">📋</div>
        <p>暂无待审核申请</p>
      </div>
      
      <div v-else class="applications-list">
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
          <div class="application-actions">
            <button 
              v-if="application.status === 'pending'"
              class="btn btn-success btn-sm"
              @click="processApplication(application.application_id, 'approve')"
            >
              通过
            </button>
            <button 
              v-if="application.status === 'pending'"
              class="btn btn-danger btn-sm"
              @click="processApplication(application.application_id, 'reject')"
            >
              拒绝
            </button>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { apiService, type MailboxApplicationResponse } from '@/api'

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

const processApplication = async (applicationId: number, action: 'approve' | 'reject') => {
  if (!confirm(`确定要${action === 'approve' ? '通过' : '拒绝'}这个申请吗？`)) {
    return
  }
  
  try {
    const response = await apiService.processMailboxApplication(applicationId, { action })
    if (response.success) {
      alert(`申请${action === 'approve' ? '通过' : '拒绝'}成功`)
      await loadApplications()
    } else {
      alert(response.message || '操作失败')
    }
  } catch (error) {
    console.error('处理申请失败:', error)
    alert('处理申请失败')
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
.admin-applications-page {
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
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.application-info {
  flex: 1;
}

.application-id {
  font-weight: 500;
  color: #2c3e50;
  margin-bottom: 5px;
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

.application-actions {
  display: flex;
  gap: 10px;
}

.btn {
  padding: 6px 12px;
  border: none;
  border-radius: 5px;
  font-size: 12px;
  cursor: pointer;
  transition: all 0.3s;
  font-weight: 500;
  display: inline-block;
}

.btn-success {
  background: #28a745;
  color: white;
}

.btn-success:hover {
  background: #218838;
}

.btn-danger {
  background: #dc3545;
  color: white;
}

.btn-danger:hover {
  background: #c82333;
}

.btn-sm {
  padding: 6px 12px;
  font-size: 12px;
}
</style>
