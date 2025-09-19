<template>
  <div class="mailboxes-page">
    <div class="page-header">
      <h1>📮 邮箱管理</h1>
    </div>

    <div class="mailboxes-content">
      <LoadingOverlay :show="loading" text="加载邮箱列表..." type="local" />

      <div v-if="!loading && mailboxes.length === 0" class="empty-state">
        <div class="empty-icon">📮</div>
        <p>暂无邮箱</p>
      </div>

      <div v-if="!loading && mailboxes.length > 0" class="mailboxes-list">
        <div v-for="mailbox in mailboxes" :key="mailbox.id" class="mailbox-item">
          <div class="mailbox-info">
            <div class="mailbox-address">{{ mailbox.address }}</div>
            <div class="mailbox-meta">
              <span class="mailbox-status">{{ mailbox.status }}</span>
              <span class="mailbox-time">{{ formatTime(mailbox.created_at) }}</span>
            </div>
          </div>
          <div class="mailbox-actions">
            <button class="btn btn-primary btn-sm" @click="editMailbox(mailbox.id)">编辑</button>
            <button class="btn btn-danger btn-sm" @click="deleteMailbox(mailbox.id)">删除</button>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import LoadingOverlay from '@/layouts/AppLoadingSpinner.vue'

const mailboxes = ref<any[]>([])
const loading = ref(false)

const loadMailboxes = async () => {
  loading.value = true
  try {
    // 这里可以调用 API 加载邮箱列表
    // const response = await apiService.getMailboxes()
    // if (response.success && response.data) {
    //   mailboxes.value = response.data.items
    // }
  } catch (error) {
    console.error('加载邮箱列表失败:', error)
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

const editMailbox = (mailboxId: string) => {
  // 编辑邮箱逻辑
  console.log('编辑邮箱:', mailboxId)
}

const deleteMailbox = (mailboxId: string) => {
  // 删除邮箱逻辑
  console.log('删除邮箱:', mailboxId)
}

onMounted(() => {
  loadMailboxes()
})
</script>

<style scoped>
.mailboxes-page {
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

.mailboxes-content {
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

.mailboxes-list {
  display: flex;
  flex-direction: column;
  gap: 15px;
}

.mailbox-item {
  background: white;
  border-radius: 10px;
  padding: 20px;
  box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.mailbox-info {
  flex: 1;
}

.mailbox-address {
  font-weight: 500;
  color: #2c3e50;
  font-size: 16px;
  margin-bottom: 5px;
}

.mailbox-meta {
  display: flex;
  align-items: center;
  gap: 15px;
  font-size: 12px;
  color: #6c757d;
}

.mailbox-status {
  padding: 2px 6px;
  border-radius: 8px;
  background: #e9ecef;
  color: #495057;
}

.mailbox-actions {
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