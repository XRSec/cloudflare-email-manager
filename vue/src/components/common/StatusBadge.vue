<template>
  <span class="status-badge" :class="statusClass">
    {{ statusText }}
  </span>
</template>

<script setup lang="ts">
import { computed } from 'vue'

interface Props {
  status: string | number
  type: 'email' | 'mailbox' | 'user'
}

const props = defineProps<Props>()

const statusClass = computed(() => {
  if (props.type === 'email') {
    const statusMap: Record<string, string> = {
      received: 'status-received',
      processed: 'status-processed',
      forwarded: 'status-forwarded',
      failed: 'status-failed',
      read: 'status-read',
      unread: 'status-unread'
    }
    return statusMap[String(props.status)] || 'status-unknown'
  } else if (props.type === 'mailbox') {
    const statusMap: Record<number, string> = {
      1: 'status-active',
      2: 'status-disabled',
      3: 'status-deleted'
    }
    return statusMap[Number(props.status)] || 'status-unknown'
  } else if (props.type === 'user') {
    const statusMap: Record<number, string> = {
      1: 'status-admin',
      2: 'status-user'
    }
    return statusMap[Number(props.status)] || 'status-unknown'
  }
  return 'status-unknown'
})

const statusText = computed(() => {
  if (props.type === 'email') {
    const statusMap: Record<string, string> = {
      received: '已接收',
      processed: '已处理',
      forwarded: '已转发',
      failed: '失败',
      read: '已读',
      unread: '未读'
    }
    return statusMap[String(props.status)] || '未知'
  } else if (props.type === 'mailbox') {
    const statusMap: Record<number, string> = {
      1: '正常',
      2: '停用',
      3: '已删除'
    }
    return statusMap[Number(props.status)] || '未知'
  } else if (props.type === 'user') {
    const statusMap: Record<number, string> = {
      1: '管理员',
      2: '普通用户'
    }
    return statusMap[Number(props.status)] || '未知'
  }
  return '未知'
})
</script>

<style scoped>
.status-badge {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: fit-content;
  max-width: max-content;
  flex: 0 0 auto;
  align-self: flex-start;
  padding: 4px 8px;
  border-radius: 4px;
  font-size: 12px;
  font-weight: bold;
  white-space: nowrap;
}

/* 邮件状态 */
.status-received {
  background: #d4edda;
  color: #155724;
}

.status-processed {
  background: #cce5ff;
  color: #004085;
}

.status-forwarded {
  background: #fff3cd;
  color: #856404;
}

.status-failed {
  background: #f8d7da;
  color: #721c24;
}

.status-read {
  background: #e2e3e5;
  color: #383d41;
}

.status-unread {
  background: #fff3cd;
  color: #856404;
  font-weight: 600;
}

/* 邮箱状态 */
.status-active {
  background: #d4edda;
  color: #155724;
}

.status-disabled {
  background: #fff3cd;
  color: #856404;
}

.status-deleted {
  background: #f8d7da;
  color: #721c24;
}

/* 用户状态 */
.status-admin {
  background: #d1ecf1;
  color: #0c5460;
}

.status-user {
  background: #e2e3e5;
  color: #383d41;
}

/* 未知状态 */
.status-unknown {
  background: #e2e3e5;
  color: #383d41;
}
</style>
