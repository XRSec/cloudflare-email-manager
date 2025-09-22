<template>
  <div class="mailboxes-list">
    <div v-for="mailbox in mailboxes" :key="mailbox.id" class="mailbox-item">
      <div class="mailbox-header">
        <h3 class="mailbox-address">{{ mailbox.address }}</h3>
        <StatusBadge :status="mailbox.status" type="mailbox" />
      </div>
      <div class="mailbox-meta">
        <div v-if="showOwner" class="mailbox-owner">
          <strong>所有者:</strong> {{ mailbox.owner_username }} ({{ getOwnerTypeText(mailbox.owner_usertype) }})
        </div>
        <div class="mailbox-created">
          <strong>创建时间:</strong> {{ formatTime(mailbox.created_at) }}
        </div>
        <div class="mailbox-updated">
          <strong>更新时间:</strong> {{ formatTime(mailbox.updated_at) }}
        </div>
      </div>
      <div v-if="showActions" class="mailbox-actions">
        <slot name="actions" :mailbox="mailbox">
          <Button v-if="canToggleStatus" variant="warning" size="sm"
            @click="$emit('toggleStatus', mailbox.id, mailbox.status)">
            {{ mailbox.status === 1 ? '停用' : '启用' }}
          </Button>
          <Button variant="danger" size="sm" @click="$emit('delete', mailbox.id)">
            删除
          </Button>
        </slot>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { StatusBadge, Button } from '@/components/common'

interface Mailbox {
  id: number
  address: string
  status: number
  owner_username: string
  owner_usertype: number
  created_at: string
  updated_at: string
}

interface Props {
  mailboxes: Mailbox[]
  showOwner?: boolean
  showActions?: boolean
  canToggleStatus?: boolean
}

withDefaults(defineProps<Props>(), {
  showOwner: false,
  showActions: false,
  canToggleStatus: false
})

defineEmits<{
  delete: [id: number]
  toggleStatus: [id: number, currentStatus: number]
}>()

const getOwnerTypeText = (userType: number) => {
  return userType === 1 ? '管理员' : '普通用户'
}

const formatTime = (dateString: string) => {
  return new Date(dateString).toLocaleString('zh-CN')
}
</script>

<style scoped>
.mailboxes-list {
  display: flex;
  flex-direction: column;
  gap: 15px;
}

.mailbox-item {
  background: white;
  border: 1px solid #e0e0e0;
  border-radius: 8px;
  padding: 20px;
  transition: box-shadow 0.2s;
}

.mailbox-item:hover {
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
}

.mailbox-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 10px;
}

.mailbox-address {
  margin: 0;
  color: #333;
  font-size: 16px;
}

.mailbox-meta {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 10px;
  margin-bottom: 15px;
  font-size: 14px;
  color: #666;
}

.mailbox-actions {
  display: flex;
  gap: 10px;
  justify-content: flex-end;
}
</style>
