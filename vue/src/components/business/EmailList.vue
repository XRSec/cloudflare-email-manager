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
      </div>
      <div v-if="email.content" class="email-content">
        <strong>内容:</strong> {{ truncateText(email.content, 200) }}
      </div>
      <div v-if="showActions" class="email-actions">
        <slot name="actions" :email="email">
          <Button variant="primary" size="sm" @click="handleViewClick(email.id)">
            详情
          </Button>
          <Button variant="info" size="sm" @click="$emit('forward', email.id)">
            转发
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
  is_read?: number
}

interface Props {
  emails: Email[]
  showActions?: boolean
  enableSelection?: boolean
  selectedIds?: string[]
}

const props = withDefaults(defineProps<Props>(), {
  showActions: false,
  enableSelection: false,
  selectedIds: () => []
})

const emit = defineEmits<{
  delete: [id: string]
  view: [id: string]
  forward: [id: string]
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
  background: linear-gradient(180deg, rgba(255, 255, 255, 0.98), rgba(247, 250, 252, 0.95));
  border: 1px solid rgba(21, 52, 82, 0.08);
  border-radius: 18px;
  padding: 20px;
  transition: box-shadow 0.25s ease, transform 0.25s ease, border-color 0.25s ease;
  box-shadow: 0 18px 30px -30px rgba(15, 23, 42, 0.65);
}

.email-item:hover {
  box-shadow: 0 24px 34px -28px rgba(15, 23, 42, 0.45);
  transform: translateY(-2px);
  border-color: rgba(43, 103, 246, 0.16);
}

.email-item.email-unread {
  border-left: 4px solid #f5a043;
  background: linear-gradient(180deg, rgba(255, 251, 240, 0.98), rgba(255, 247, 228, 0.96));
}

.email-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 12px;
  gap: 12px;
  min-width: 0;
}

.email-header :deep(.status-badge) {
  flex-shrink: 0;
}

.email-checkbox-wrapper {
  flex-shrink: 0;
  display: flex;
  align-items: center;
  padding-top: 4px;
}

.email-checkbox-wrapper input[type="checkbox"] {
  width: 18px;
  height: 18px;
  cursor: pointer;
}

.email-item.email-selected {
  background: linear-gradient(180deg, rgba(240, 247, 255, 0.98), rgba(233, 243, 255, 0.98));
  border-color: #4a90e2;
}

.email-subject-wrapper {
  display: flex;
  align-items: center;
  gap: 8px;
  flex: 1;
  min-width: 0;
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
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.email-item.email-unread .email-subject {
  font-weight: 600;
  color: #000;
}

.email-meta {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 10px 14px;
  margin-bottom: 14px;
  font-size: 14px;
  color: #666;
}

.email-from,
.email-to,
.email-time {
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  padding: 10px 12px;
  border-radius: 14px;
  background: rgba(247, 250, 252, 0.92);
  border: 1px solid rgba(15, 23, 42, 0.06);
}

.email-content {
  color: #555;
  line-height: 1.5;
  font-size: 14px;
  margin-bottom: 16px;
  overflow: hidden;
  word-break: break-word;
  padding: 12px 14px;
  border-radius: 16px;
  background: rgba(250, 252, 255, 0.92);
  border: 1px solid rgba(15, 23, 42, 0.06);
}

.email-actions {
  display: flex;
  gap: 10px;
  justify-content: flex-end;
  flex-wrap: wrap;
  min-width: 0;
  padding-top: 2px;
}

.email-actions :deep(.btn) {
  width: auto;
  min-width: 72px;
  flex: 0 0 auto;
}

@media (max-width: 720px) {
  .email-item {
    padding: 16px;
    border-radius: 16px;
  }

  .email-header {
    flex-wrap: wrap;
    gap: 10px;
  }

  .email-meta {
    grid-template-columns: 1fr;
  }

  .email-from,
  .email-to,
  .email-time {
    white-space: normal;
    overflow: visible;
    text-overflow: unset;
    word-break: break-word;
    padding: 8px 10px;
  }

  .email-actions {
    justify-content: stretch;
  }

  .email-actions :deep(.btn) {
    min-width: 68px;
  }
}
</style>
