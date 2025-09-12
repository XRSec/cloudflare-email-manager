<template>
  <div class="mailbox-page">
    <MailboxList @mailbox-deleted="handleMailboxDeleted" />
  </div>
</template>

<script setup lang="ts">
import MailboxList from '@/components/Mailbox/MailboxList.vue'

const handleMailboxDeleted = (mailboxId: number) => {
  console.log('邮箱已删除:', mailboxId)
  // 这里可以显示成功消息或执行其他操作
}
</script>

<style scoped>
.mailbox-page {
  height: 100%;
  background: #f8f9fa;
}
</style>