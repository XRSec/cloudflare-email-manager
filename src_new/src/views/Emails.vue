<template>
  <div class="emails-page">
    <!-- 页面头部 -->
    <div class="page-header">
      <div class="header-content">
        <h2 class="page-title">邮件列表</h2>
        <p class="page-description">
          管理您收到的邮件，支持查看详情、下载附件和删除操作
        </p>
      </div>
      <div class="header-actions">
        <button
          class="btn btn-primary"
          @click="refreshEmails"
          :disabled="emailStore.loading"
        >
          <span v-if="emailStore.loading">刷新中...</span>
          <span v-else>🔄 刷新</span>
        </button>
      </div>
    </div>

    <!-- 搜索和过滤 -->
    <div class="filters-section card">
      <div class="search-box">
        <input
          v-model="searchQuery"
          type="text"
          class="form-control"
          placeholder="搜索邮件（发件人、主题、内容）"
          @input="handleSearch"
        >
      </div>
      
      <div class="filter-options">
        <div class="filter-group">
          <label class="form-label">按发件人过滤</label>
          <input
            v-model="senderFilter"
            type="text"
            class="form-control"
            placeholder="输入发件人邮箱"
            @input="handleFilterChange"
          >
        </div>
        
        <div class="filter-group">
          <label class="form-label">是否有附件</label>
          <select
            v-model="attachmentFilter"
            class="form-control"
            @change="handleFilterChange"
          >
            <option value="">全部</option>
            <option value="true">有附件</option>
            <option value="false">无附件</option>
          </select>
        </div>
        
        <div class="filter-group">
          <button
            class="btn btn-secondary"
            @click="clearFilters"
          >
            清除过滤
          </button>
        </div>
      </div>
    </div>

    <!-- 邮件统计 -->
    <div class="stats-section">
      <div class="stat-card">
        <div class="stat-number">{{ emailStore.pagination.total }}</div>
        <div class="stat-label">总邮件数</div>
      </div>
      <div class="stat-card">
        <div class="stat-number">{{ emailsWithAttachments }}</div>
        <div class="stat-label">有附件邮件</div>
      </div>
      <div class="stat-card">
        <div class="stat-number">{{ emailStore.pagination.page }}</div>
        <div class="stat-label">当前页</div>
      </div>
      <div class="stat-card">
        <div class="stat-number">{{ emailStore.totalPages }}</div>
        <div class="stat-label">总页数</div>
      </div>
    </div>

    <!-- 邮件列表 -->
    <div class="emails-section card">
      <!-- 加载状态 -->
      <div v-if="emailStore.loading" class="loading">
        正在加载邮件...
      </div>

      <!-- 错误状态 -->
      <div v-else-if="emailStore.error" class="error-message">
        <p>{{ emailStore.error }}</p>
        <button class="btn btn-primary" @click="refreshEmails">
          重试
        </button>
      </div>

      <!-- 空状态 -->
      <div v-else-if="!emailStore.hasEmails" class="empty-state">
        <div class="empty-icon">📭</div>
        <h3>暂无邮件</h3>
        <p>您还没有收到任何邮件，或者当前筛选条件下没有匹配的邮件。</p>
      </div>

      <!-- 邮件列表 -->
      <div v-else class="email-list">
        <div
          v-for="email in emailStore.emails"
          :key="email.id"
          class="email-item"
          @click="showEmailDetail(email)"
        >
          <div class="email-header">
            <div class="email-sender">
              <strong>{{ email.sender_email }}</strong>
            </div>
            <div class="email-time">
              {{ systemStore.formatDate(email.received_at) }}
            </div>
          </div>
          
          <div class="email-subject">
            {{ email.subject || '(无主题)' }}
          </div>
          
          <div class="email-preview">
            {{ getEmailPreview(email) }}
          </div>
          
          <div v-if="email.has_attachments" class="email-attachments">
            📎 有附件
          </div>
        </div>
      </div>

      <!-- 分页 -->
      <div v-if="emailStore.totalPages > 1" class="pagination-section">
        <div class="pagination">
          <button
            class="btn btn-light"
            :disabled="emailStore.pagination.page <= 1"
            @click="emailStore.previousPage()"
          >
            上一页
          </button>
          
          <div class="page-numbers">
            <button
              v-for="page in visiblePages"
              :key="page"
              :class="['btn', page === emailStore.pagination.page ? 'btn-primary' : 'btn-light']"
              @click="emailStore.goToPage(page)"
            >
              {{ page }}
            </button>
          </div>
          
          <button
            class="btn btn-light"
            :disabled="emailStore.pagination.page >= emailStore.totalPages"
            @click="emailStore.nextPage()"
          >
            下一页
          </button>
        </div>
        
        <div class="pagination-info">
          共 {{ emailStore.pagination.total }} 封邮件，
          第 {{ emailStore.pagination.page }} 页，
          共 {{ emailStore.totalPages }} 页
        </div>
      </div>
    </div>

    <!-- 邮件详情模态框 -->
    <EmailDetailModal
      v-if="selectedEmail"
      :email="selectedEmail"
      @close="selectedEmail = null"
      @delete="handleDeleteEmail"
    />
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useEmailStore } from '@/stores/emails'
import { useSystemStore } from '@/stores/system'
import type { Email } from '@/types'
import EmailDetailModal from '@/components/EmailDetailModal.vue'

// Composables
const emailStore = useEmailStore()
const systemStore = useSystemStore()

// State
const searchQuery = ref('')
const senderFilter = ref('')
const attachmentFilter = ref('')
const selectedEmail = ref<Email | null>(null)
let searchTimeout: NodeJS.Timeout | null = null

// Computed
const emailsWithAttachments = computed(() => {
  return emailStore.emails.filter(email => email.has_attachments).length
})

const visiblePages = computed(() => {
  const current = emailStore.pagination.page
  const total = emailStore.totalPages
  const pages: number[] = []
  
  // 显示当前页前后2页
  const start = Math.max(1, current - 2)
  const end = Math.min(total, current + 2)
  
  for (let i = start; i <= end; i++) {
    pages.push(i)
  }
  
  return pages
})

// Methods
const refreshEmails = async () => {
  await emailStore.loadEmails()
}

const handleSearch = () => {
  if (searchTimeout) {
    clearTimeout(searchTimeout)
  }
  
  searchTimeout = setTimeout(async () => {
    await emailStore.searchEmails(searchQuery.value)
  }, 500)
}

const handleFilterChange = async () => {
  const filters: any = {}
  
  if (senderFilter.value) {
    filters.sender = senderFilter.value
  }
  
  if (attachmentFilter.value !== '') {
    filters.has_attachments = attachmentFilter.value === 'true'
  }
  
  await emailStore.loadEmails(filters)
}

const clearFilters = async () => {
  searchQuery.value = ''
  senderFilter.value = ''
  attachmentFilter.value = ''
  await emailStore.loadEmails()
}

const showEmailDetail = (email: Email) => {
  selectedEmail.value = email
}

const handleDeleteEmail = async (emailId: number) => {
  const success = await emailStore.deleteEmail(emailId)
  if (success) {
    selectedEmail.value = null
  }
}

const getEmailPreview = (email: Email): string => {
  const content = email.text_content || email.html_content || '(无内容)'
  return content.length > 100 ? content.substring(0, 100) + '...' : content
}

// Lifecycle
onMounted(async () => {
  await refreshEmails()
})

onUnmounted(() => {
  if (searchTimeout) {
    clearTimeout(searchTimeout)
  }
  emailStore.reset()
})
</script>

<style scoped>
.emails-page {
  max-width: 1200px;
  margin: 0 auto;
}

.page-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: var(--spacing-6);
  gap: var(--spacing-4);
}

.header-content {
  flex: 1;
}

.page-title {
  font-size: var(--font-size-2xl);
  font-weight: 600;
  color: var(--gray-800);
  margin-bottom: var(--spacing-2);
}

.page-description {
  color: var(--gray-600);
  font-size: var(--font-size-base);
  margin: 0;
}

.header-actions {
  display: flex;
  gap: var(--spacing-3);
}

.filters-section {
  margin-bottom: var(--spacing-6);
}

.search-box {
  margin-bottom: var(--spacing-4);
}

.filter-options {
  display: grid;
  grid-template-columns: 1fr 1fr auto;
  gap: var(--spacing-4);
  align-items: end;
}

.filter-group {
  display: flex;
  flex-direction: column;
}

.stats-section {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: var(--spacing-4);
  margin-bottom: var(--spacing-6);
}

.stat-card {
  background: var(--white);
  padding: var(--spacing-5);
  border-radius: var(--border-radius-lg);
  text-align: center;
  box-shadow: var(--shadow);
}

.stat-number {
  font-size: var(--font-size-2xl);
  font-weight: 700;
  color: var(--primary-color);
  margin-bottom: var(--spacing-1);
}

.stat-label {
  color: var(--gray-600);
  font-size: var(--font-size-sm);
}

.emails-section {
  margin-bottom: var(--spacing-6);
}

.error-message {
  text-align: center;
  padding: var(--spacing-8);
  color: var(--danger-color);
}

.empty-state {
  text-align: center;
  padding: var(--spacing-10);
}

.empty-icon {
  font-size: 4rem;
  margin-bottom: var(--spacing-4);
}

.empty-state h3 {
  color: var(--gray-700);
  margin-bottom: var(--spacing-2);
}

.empty-state p {
  color: var(--gray-600);
  max-width: 400px;
  margin: 0 auto;
}

.email-list {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-3);
}

.email-item {
  border: 1px solid var(--gray-200);
  border-radius: var(--border-radius-lg);
  padding: var(--spacing-5);
  transition: var(--transition);
  cursor: pointer;
  background: var(--white);
}

.email-item:hover {
  box-shadow: var(--shadow-md);
  transform: translateY(-2px);
  border-color: var(--primary-color);
}

.email-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: var(--spacing-3);
  gap: var(--spacing-4);
}

.email-sender {
  color: var(--gray-800);
  font-size: var(--font-size-base);
}

.email-time {
  color: var(--gray-500);
  font-size: var(--font-size-sm);
  white-space: nowrap;
}

.email-subject {
  color: var(--primary-color);
  font-weight: 500;
  margin-bottom: var(--spacing-2);
  font-size: var(--font-size-base);
}

.email-preview {
  color: var(--gray-600);
  font-size: var(--font-size-sm);
  line-height: 1.5;
  margin-bottom: var(--spacing-2);
}

.email-attachments {
  color: var(--info-color);
  font-size: var(--font-size-sm);
  font-weight: 500;
}

.pagination-section {
  margin-top: var(--spacing-6);
  padding-top: var(--spacing-4);
  border-top: 1px solid var(--gray-200);
}

.pagination {
  display: flex;
  justify-content: center;
  align-items: center;
  gap: var(--spacing-2);
  margin-bottom: var(--spacing-3);
}

.page-numbers {
  display: flex;
  gap: var(--spacing-1);
}

.pagination-info {
  text-align: center;
  color: var(--gray-600);
  font-size: var(--font-size-sm);
}

/* 响应式设计 */
@media (max-width: 768px) {
  .page-header {
    flex-direction: column;
    align-items: stretch;
  }
  
  .filter-options {
    grid-template-columns: 1fr;
    gap: var(--spacing-3);
  }
  
  .stats-section {
    grid-template-columns: repeat(2, 1fr);
  }
  
  .email-header {
    flex-direction: column;
    align-items: flex-start;
    gap: var(--spacing-2);
  }
  
  .email-time {
    white-space: normal;
  }
  
  .pagination {
    flex-wrap: wrap;
    gap: var(--spacing-1);
  }
  
  .page-numbers {
    order: -1;
    width: 100%;
    justify-content: center;
    margin-bottom: var(--spacing-2);
  }
}
</style>