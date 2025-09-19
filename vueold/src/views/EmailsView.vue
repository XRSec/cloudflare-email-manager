<template>
  <div class="emails-page">
    <div class="emails-container">
      <!-- 邮件列表 -->
      <div class="emails-list-section">
        <EmailList 
          @email-select="handleEmailSelect"
        />
      </div>
      
      <!-- 邮件详情 -->
      <div class="email-detail-section">
        <EmailDetail 
          :email-id="selectedEmailId"
          @close="handleEmailClose"
          @email-deleted="handleEmailDeleted"
        />
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import EmailList from '@/components/Email/EmailList.vue'
import EmailDetail from '@/components/Email/EmailDetail.vue'
import type { EmailSummary } from '@/api'

const selectedEmailId = ref<string | undefined>()

const handleEmailSelect = (email: EmailSummary) => {
  selectedEmailId.value = email.id
}

const handleEmailClose = () => {
  selectedEmailId.value = undefined
}

const handleEmailDeleted = (emailId: string) => {
  selectedEmailId.value = undefined
  // 这里可以触发邮件列表刷新
}
</script>

<style scoped>
.emails-page {
  height: 100%;
  background: #f8f9fa;
}

.emails-container {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 20px;
  height: 100%;
  min-height: 600px;
}

.emails-list-section {
  background: white;
  border-radius: 10px;
  box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
  overflow: hidden;
}

.email-detail-section {
  background: white;
  border-radius: 10px;
  box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
  overflow: hidden;
}

@media (max-width: 1024px) {
  .emails-container {
    grid-template-columns: 1fr;
    grid-template-rows: 1fr 1fr;
  }
}

@media (max-width: 768px) {
  .emails-container {
    grid-template-rows: auto 1fr;
    gap: 15px;
  }
}
</style>