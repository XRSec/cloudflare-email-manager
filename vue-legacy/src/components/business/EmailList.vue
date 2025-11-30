<template>
  <div class="emails-list">
    <div v-for="email in emails" :key="email.id" class="email-item">
      <div class="email-header">
        <h3 class="email-subject">{{ email.subject || '无主题' }}</h3>
        <StatusBadge :status="email.status" type="email" />
      </div>
      <div class="email-meta">
        <div class="email-from">
          <strong>发件人:</strong> {{ email.from }}
        </div>
        <div class="email-to">
          <strong>收件人:</strong> {{ email.to }}
        </div>
        <div class="email-time">
          <strong>时间:</strong> {{ formatTime(email.received_at) }}
        </div>
        <div v-if="showOwner && email.owner_username" class="email-owner">
          <strong>所有者:</strong> {{ email.owner_username }}
        </div>
      </div>
      <div v-if="email.content" class="email-content">
        <strong>内容:</strong> {{ truncateText(email.content, 200) }}
      </div>
      <div v-if="showActions" class="email-actions">
        <slot name="actions" :email="email">
          <Button variant="danger" size="sm" @click="$emit('delete', email.id)">
            删除
          </Button>
        </slot>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { StatusBadge, Button } from '@/components/common'

interface Email {
  id: number
  subject?: string
  from: string
  to: string
  content?: string
  status: string
  received_at: string
  owner_username?: string
}

interface Props {
  emails: Email[]
  showOwner?: boolean
  showActions?: boolean
}

withDefaults(defineProps<Props>(), {
  showOwner: false,
  showActions: false
})

defineEmits<{
  delete: [id: number]
}>()

const formatTime = (dateString: string) => {
  return new Date(dateString).toLocaleString('zh-CN')
}

const truncateText = (text: string, maxLength: number) => {
  if (text.length <= maxLength) return text
  return text.substring(0, maxLength) + '...'
}
</script>

<style scoped>
.emails-list {
  display: flex;
  flex-direction: column;
  gap: 15px;
}

.email-item {
  background: white;
  border: 1px solid #e0e0e0;
  border-radius: 8px;
  padding: 20px;
  transition: box-shadow 0.2s;
}

.email-item:hover {
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
}

.email-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 10px;
}

.email-subject {
  margin: 0;
  color: #333;
  font-size: 16px;
}

.email-meta {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 10px;
  margin-bottom: 10px;
  font-size: 14px;
  color: #666;
}

.email-content {
  color: #555;
  line-height: 1.5;
  font-size: 14px;
  margin-bottom: 15px;
}

.email-actions {
  display: flex;
  gap: 10px;
  justify-content: flex-end;
}
</style>
