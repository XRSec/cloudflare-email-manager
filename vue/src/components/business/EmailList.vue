<template>
  <div class="emails-list">
    <div v-for="email in emails" :key="email.id" class="email-item"
      :class="{ 'email-unread': email.status === 'unread', 'email-selected': selectedIds.includes(email.id) }">
      <div class="email-header">
        <div class="email-checkbox-wrapper" v-if="enableSelection">
          <input type="checkbox" :checked="selectedIds.includes(email.id)"
            @change="handleCheckboxChange(email.id, $event)" />
        </div>
        <div class="email-subject-wrapper">
          <span v-if="email.status === 'unread'" class="unread-dot" title="未读"></span>
          <h3 class="email-subject">主题: {{ email.subject || '无主题' }}</h3>
        </div>
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
          <Button variant="primary" size="sm" @click="handleViewClick(email.id)">
            详情
          </Button>
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
  id: string
  subject?: string
  from: string
  to: string
  content?: string
  status: 'read' | 'unread' | string
  received_at: string
  owner_username?: string
  is_read?: number
}

interface Props {
  emails: Email[]
  showOwner?: boolean
  showActions?: boolean
  enableSelection?: boolean
  selectedIds?: string[]
}

const props = withDefaults(defineProps<Props>(), {
  showOwner: false,
  showActions: false,
  enableSelection: false,
  selectedIds: () => []
})

const emit = defineEmits<{
  delete: [id: string]
  view: [id: string]
  selectionChange: [ids: string[]]
}>()

const handleCheckboxChange = (emailId: string, event: Event) => {
  const checked = (event.target as HTMLInputElement).checked
  const currentSelected = [...(props.selectedIds || [])]

  if (checked) {
    if (!currentSelected.includes(emailId)) {
      currentSelected.push(emailId)
    }
  } else {
    const index = currentSelected.indexOf(emailId)
    if (index > -1) {
      currentSelected.splice(index, 1)
    }
  }

  emit('selectionChange', currentSelected)
}

const handleViewClick = (id: string) => {
  console.log('📧 [EmailList] 点击详情按钮')
  console.log('📁 文件名: EmailList.vue')
  console.log('📂 文件路径: vue/src/components/business/EmailList.vue')
  console.log('🆔 邮件ID:', id)
  emit('view', id)
}

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

.email-item.email-unread {
  border-left: 4px solid #ffc107;
  background: #fffbf0;
}

.email-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 10px;
  gap: 12px;
}

.email-checkbox-wrapper {
  flex-shrink: 0;
  display: flex;
  align-items: center;
  padding-top: 2px;
}

.email-checkbox-wrapper input[type="checkbox"] {
  width: 18px;
  height: 18px;
  cursor: pointer;
}

.email-item.email-selected {
  background: #f0f7ff;
  border-color: #4a90e2;
}

.email-subject-wrapper {
  display: flex;
  align-items: center;
  gap: 8px;
  flex: 1;
}

.unread-dot {
  width: 10px;
  height: 10px;
  background: #ff4444;
  border-radius: 50%;
  flex-shrink: 0;
  animation: pulse 2s infinite;
}

@keyframes pulse {

  0%,
  100% {
    opacity: 1;
  }

  50% {
    opacity: 0.5;
  }
}

.email-subject {
  margin: 0;
  color: #333;
  font-size: 16px;
  font-weight: 500;
}

.email-item.email-unread .email-subject {
  font-weight: 600;
  color: #000;
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
