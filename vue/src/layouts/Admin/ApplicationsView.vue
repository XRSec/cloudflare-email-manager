<template>
  <div class="applications-page">
    <div class="page-header">
      <h1>📋 申请审核</h1>
    </div>

    <div class="applications-content">
      <LoadingOverlay :show="loading" text="加载申请列表..." type="local" />

      <div v-if="!loading && applications.length === 0" class="empty-state">
        <div class="empty-icon">📋</div>
        <p>暂无申请</p>
      </div>

      <div v-if="!loading && applications.length > 0" class="applications-list">
        <div v-for="application in applications" :key="application.application_id" class="application-item">
          <div class="application-info">
            <div class="application-id">申请 #{{ application.application_id }}</div>
            <div class="application-details">
              <div class="applicant-name">申请人: {{ application.applicant_name }}</div>
              <div class="application-time">申请时间: {{ formatTime(application.created_at) }}</div>
            </div>
            <div class="application-status">
              <span class="status-badge" :class="getStatusClass(application.status)">
                {{ getStatusText(application.status) }}
              </span>
            </div>
          </div>
          <div class="application-actions">
            <button v-if="application.status === 'pending'" class="btn btn-success btn-sm"
              @click="approveApplication(application.application_id)">通过</button>
            <button v-if="application.status === 'pending'" class="btn btn-danger btn-sm"
              @click="rejectApplication(application.application_id)">拒绝</button>
            <button class="btn btn-primary btn-sm" @click="viewApplication(application.application_id)">查看</button>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import LoadingOverlay from '@/layouts/AppLoadingSpinner.vue'

const applications = ref<any[]>([])
const loading = ref(false)

const loadApplications = async () => {
  loading.value = true
  try {
    // 这里可以调用 API 加载申请列表
    // const response = await apiService.getMailboxApplications()
    // if (response.success && response.data) {
    //   applications.value = response.data.items
    // }
  } catch (error) {
    console.error('加载申请列表失败:', error)
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

const approveApplication = (applicationId: string) => {
  // 通过申请逻辑
  console.log('通过申请:', applicationId)
}

const rejectApplication = (applicationId: string) => {
  // 拒绝申请逻辑
  console.log('拒绝申请:', applicationId)
}

const viewApplication = (applicationId: string) => {
  // 查看申请详情逻辑
  console.log('查看申请:', applicationId)
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

.applications-content {
  position: relative;
  min-height: 200px;
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
  font-size: 16px;
  margin-bottom: 10px;
}

.application-details {
  display: flex;
  flex-direction: column;
  gap: 5px;
  margin-bottom: 10px;
}

.applicant-name,
.application-time {
  color: #6c757d;
  font-size: 14px;
}

.application-status {
  display: flex;
  align-items: center;
  gap: 10px;
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
}

.btn-primary {
  background: #3498db;
  color: white;
}

.btn-primary:hover {
  background: #2980b9;
}

.btn-success {
  background: #28a745;
  color: white;
}

.btn-success:hover {
  background: #218838;
}

.btn-danger {
  background: #e74c3c;
  color: white;
}

.btn-danger:hover {
  background: #c0392b;
}

.btn-sm {
  padding: 4px 8px;
  font-size: 11px;
}
</style>