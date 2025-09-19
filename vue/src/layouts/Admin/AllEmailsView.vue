<template>
  <div class="all-emails-page">
    <div class="page-header">
      <h1>📨 全部邮件</h1>
    </div>

    <div class="all-emails-content">
      <LoadingOverlay :show="loading" text="加载邮件列表..." type="local" />

      <div v-if="!loading && emails.length === 0" class="empty-state">
        <div class="empty-icon">📨</div>
        <p>暂无邮件</p>
      </div>

      <div v-if="!loading && emails.length > 0" class="emails-list">
        <div v-for="email in emails" :key="email.id" class="email-item" @click="viewEmail(email.id)">
          <div class="email-subject">{{ email.subject }}</div>
          <div class="email-meta">
            <span class="email-from">{{ email.from }}</span>
            <span class="email-to">{{ email.to }}</span>
            <span class="email-time">{{ formatTime(email.received_at) }}</span>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import LoadingOverlay from '@/layouts/AppLoadingSpinner.vue'

const router = useRouter()
const emails = ref<any[]>([])
const loading = ref(false)

const loadEmails = async () => {
  loading.value = true
  try {
    // 这里可以调用 API 加载全部邮件
    // const response = await apiService.getAllEmails()
    // if (response.success && response.data) {
    //   emails.value = response.data.items
    // }
  } catch (error) {
    console.error('加载邮件列表失败:', error)
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
  router.push({ name: 'email-detail', params: { id: emailId } })
}

onMounted(() => {
  loadEmails()
})
</script>

<style scoped>
.all-emails-page {
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

.all-emails-content {
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

.emails-list {
  display: flex;
  flex-direction: column;
  gap: 15px;
}

.email-item {
  background: white;
  border-radius: 10px;
  padding: 20px;
  box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
  cursor: pointer;
  transition: all 0.3s ease;
}

.email-item:hover {
  transform: translateY(-2px);
  box-shadow: 0 4px 20px rgba(0, 0, 0, 0.15);
}

.email-subject {
  font-weight: 500;
  color: #2c3e50;
  margin-bottom: 10px;
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
  gap: 15px;
}

.email-from,
.email-to {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  flex: 1;
}

.email-time {
  flex-shrink: 0;
}
</style>