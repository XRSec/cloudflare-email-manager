<template>
  <div class="admin-emails-page">
    <!-- 页面头部 -->
    <div class="page-header">
      <div class="header-content">
        <h2 class="page-title">📬 所有邮件</h2>
        <p class="page-description">
          查看和管理系统中所有用户的邮件
        </p>
      </div>
      <div class="header-actions">
        <button
          class="btn btn-primary"
          @click="refreshEmails"
          :disabled="adminStore.loading"
        >
          <span v-if="adminStore.loading">刷新中...</span>
          <span v-else>🔄 刷新</span>
        </button>
      </div>
    </div>

    <!-- 邮件统计 -->
    <div class="stats-section">
      <div class="stat-card">
        <div class="stat-number">{{ adminStore.allEmails.length }}</div>
        <div class="stat-label">总邮件数</div>
      </div>
      <div class="stat-card">
        <div class="stat-number">{{ emailsWithAttachments }}</div>
        <div class="stat-label">有附件邮件</div>
      </div>
      <div class="stat-card">
        <div class="stat-number">{{ uniqueSenders }}</div>
        <div class="stat-label">发件人数量</div>
      </div>
      <div class="stat-card">
        <div class="stat-number">{{ todayEmails }}</div>
        <div class="stat-label">今日邮件</div>
      </div>
    </div>

    <!-- 搜索和过滤 -->
    <div class="filters-section card">
      <div class="search-box">
        <input
          v-model="searchQuery"
          type="text"
          class="form-control"
          placeholder="搜索邮件（发件人、收件人、主题、内容）"
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
          <label class="form-label">按收件人过滤</label>
          <input
            v-model="recipientFilter"
            type="text"
            class="form-control"
            placeholder="输入收件人邮箱"
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

    <!-- 邮件列表 -->
    <div class="emails-section card">
      <!-- 加载状态 -->
      <div v-if="adminStore.loading" class="loading">
        正在加载邮件...
      </div>

      <!-- 错误状态 -->
      <div v-else-if="adminStore.error" class="error-message">
        <p>{{ adminStore.error }}</p>
        <button class="btn btn-primary" @click="refreshEmails">
          重试
        </button>
      </div>

      <!-- 空状态 -->
      <div v-else-if="filteredEmails.length === 0" class="empty-state">
        <div class="empty-icon">📭</div>
        <h3>暂无邮件</h3>
        <p>当前筛选条件下没有找到匹配的邮件。</p>
      </div>

      <!-- 邮件列表 -->
      <div v-else class="email-list">
        <div
          v-for="email in paginatedEmails"
          :key="email.id"
          class="email-item"
          @click="showEmailDetail(email)"
        >
          <div class="email-header">
            <div class="email-sender">
              <strong>{{ email.sender_email }}</strong>
              <span class="arrow">→</span>
              <strong>{{ email.recipient_email }}</strong>
            </div>
            <div class="email-time">
              {{ formatDate(email.received_at) }}
            </div>
          </div>
          
          <div class="email-subject">
            {{ email.subject || '(无主题)' }}
          </div>
          
          <div class="email-preview">
            {{ getEmailPreview(email) }}
          </div>
          
          <div class="email-meta">
            <span v-if="email.has_attachments" class="email-attachments">
              📎 有附件
            </span>
            <span class="email-user">
              用户: {{ getUserPrefix(email.recipient_email) }}
            </span>
          </div>
        </div>
      </div>

      <!-- 分页 -->
      <div v-if="totalPages > 1" class="pagination-section">
        <div class="pagination">
          <button
            class="btn btn-light"
            :disabled="currentPage <= 1"
            @click="goToPage(currentPage - 1)"
          >
            上一页
          </button>
          
          <div class="page-numbers">
            <button
              v-for="page in visiblePages"
              :key="page"
              :class="['btn', page === currentPage ? 'btn-primary' : 'btn-light']"
              @click="goToPage(page)"
            >
              {{ page }}
            </button>
          </div>
          
          <button
            class="btn btn-light"
            :disabled="currentPage >= totalPages"
            @click="goToPage(currentPage + 1)"
          >
            下一页
          </button>
        </div>
        
        <div class="pagination-info">
          共 {{ filteredEmails.length }} 封邮件，
          第 {{ currentPage }} 页，
          共 {{ totalPages }} 页
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
import { useAdminStore } from '@/stores/admin'
import { useSystemStore } from '@/stores/system'
import type { Email } from '@/types'
import EmailDetailModal from '@/components/EmailDetailModal.vue'

// Composables
const adminStore = useAdminStore()
const systemStore = useSystemStore()

// State
const searchQuery = ref('')
const senderFilter = ref('')
const recipientFilter = ref('')
const attachmentFilter = ref('')
const selectedEmail = ref<Email | null>(null)
const currentPage = ref(1)
const pageSize = 20
let searchTimeout: NodeJS.Timeout | null = null

// Computed
const emailsWithAttachments = computed(() => {
  return adminStore.allEmails.filter(email => email.has_attachments).length
})

const uniqueSenders = computed(() => {
  const senders = new Set(adminStore.allEmails.map(email => email.sender_email))
  return senders.size
})

const todayEmails = computed(() => {
  const today = new Date().toDateString()
  return adminStore.allEmails.filter(email => 
    new Date(email.received_at).toDateString() === today
  ).length
})

const filteredEmails = computed(() => {
  let emails = adminStore.allEmails

  // 按搜索关键词过滤
  if (searchQuery.value.trim()) {
    const query = searchQuery.value.toLowerCase()
    emails = emails.filter(email =>
      email.sender_email.toLowerCase().includes(query) ||
      email.recipient_email.toLowerCase().includes(query) ||
      (email.subject && email.subject.toLowerCase().includes(query)) ||
      (email.text_content && email.text_content.toLowerCase().includes(query))
    )
  }

  // 按发件人过滤
  if (senderFilter.value.trim()) {
    const sender = senderFilter.value.toLowerCase()
    emails = emails.filter(email =>
      email.sender_email.toLowerCase().includes(sender)
    )
  }

  // 按收件人过滤
  if (recipientFilter.value.trim()) {
    const recipient = recipientFilter.value.toLowerCase()
    emails = emails.filter(email =>
      email.recipient_email.toLowerCase().includes(recipient)
    )
  }

  // 按附件过滤
  if (attachmentFilter.value !== '') {
    const hasAttachments = attachmentFilter.value === 'true'
    emails = emails.filter(email => !!email.has_attachments === hasAttachments)
  }

  return emails
})

const totalPages = computed(() => Math.ceil(filteredEmails.value.length / pageSize))

const paginatedEmails = computed(() => {
  const start = (currentPage.value - 1) * pageSize
  const end = start + pageSize
  return filteredEmails.value.slice(start, end)
})

const visiblePages = computed(() => {
  const current = currentPage.value
  const total = totalPages.value
  const pages: number[] = []
  
  const start = Math.max(1, current - 2)
  const end = Math.min(total, current + 2)
  
  for (let i = start; i <= end; i++) {
    pages.push(i)
  }
  
  return pages
})

// Methods
const refreshEmails = async () => {
  await adminStore.loadAllEmails()
}

const handleSearch = () => {
  if (searchTimeout) {
    clearTimeout(searchTimeout)
  }
  
  searchTimeout = setTimeout(() => {
    currentPage.value = 1 // 重置到第一页
  }, 500)
}

const handleFilterChange = () => {
  currentPage.value = 1 // 重置到第一页
}

const clearFilters = () => {
  searchQuery.value = ''
  senderFilter.value = ''
  recipientFilter.value = ''
  attachmentFilter.value = ''
  currentPage.value = 1
}

const goToPage = (page: number) => {
  if (page >= 1 && page <= totalPages.value) {
    currentPage.value = page
  }
}

const showEmailDetail = (email: any) => {
  selectedEmail.value = email
}

const handleDeleteEmail = async (emailId: number) => {
  // 管理员可以删除任何邮件
  // 这里需要调用相应的 API
  console.log('删除邮件:', emailId)
  selectedEmail.value = null
  await refreshEmails()
}

const getEmailPreview = (email: any): string => {
  const content = email.text_content || email.html_content || '(无内容)'
  return content.length > 100 ? content.substring(0, 100) + '...' : content
}

const getUserPrefix = (recipientEmail: string): string => {
  const atIndex = recipientEmail.indexOf('@')
  return atIndex > 0 ? recipientEmail.substring(0, atIndex) : recipientEmail
}

const formatDate = (dateString: string): string => {
  return systemStore.formatDate(dateString)
}

// Lifecycle
onMounted(async () => {
  await refreshEmails()
})

onUnmounted(() => {
  if (searchTimeout) {
    clearTimeout(searchTimeout)
  }
})
</script>

<style scoped>
.admin-emails-page {
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

.filters-section {
  margin-bottom: var(--spacing-6);
}

.search-box {
  margin-bottom: var(--spacing-4);
}

.filter-options {
  display: grid;
  grid-template-columns: 1fr 1fr 1fr auto;
  gap: var(--spacing-4);
  align-items: end;
}

.filter-group {
  display: flex;
  flex-direction: column;
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
  display: flex;
  align-items: center;
  gap: var(--spacing-2);
}

.arrow {
  color: var(--gray-500);
  font-weight: normal;
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
  margin-bottom: var(--spacing-3);
}

.email-meta {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: var(--spacing-3);
}

.email-attachments {
  color: var(--info-color);
  font-size: var(--font-size-sm);
  font-weight: 500;
}

.email-user {
  color: var(--gray-500);
  font-size: var(--font-size-sm);
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
  
  .email-sender {
    flex-direction: column;
    align-items: flex-start;
    gap: var(--spacing-1);
  }
  
  .email-time {
    white-space: normal;
  }
  
  .email-meta {
    flex-direction: column;
    align-items: flex-start;
    gap: var(--spacing-1);
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