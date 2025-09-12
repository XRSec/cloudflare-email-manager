<template>
  <div class="email-list-container">
    <!-- 搜索和筛选 -->
    <div class="email-controls">
      <div class="search-box">
        <input 
          v-model="searchQuery"
          type="text" 
          class="search-input" 
          placeholder="搜索邮件..."
          @input="handleSearch"
        >
        <span class="search-icon">🔍</span>
      </div>
      
      <div class="filter-controls">
        <select v-model="statusFilter" @change="handleFilterChange" class="form-control">
          <option value="">全部状态</option>
          <option value="received">已接收</option>
          <option value="processed">已处理</option>
          <option value="forwarded">已转发</option>
          <option value="failed">失败</option>
        </select>
        
        <button 
          v-if="isAdmin && !showAllEmails"
          class="btn btn-secondary btn-sm"
          @click="toggleScope"
        >
          查看全部邮件
        </button>
        <button 
          v-if="isAdmin && showAllEmails"
          class="btn btn-primary btn-sm"
          @click="toggleScope"
        >
          查看我的邮件
        </button>
      </div>
    </div>

    <!-- 邮件列表 -->
    <div class="email-list">
      <div v-if="loading" class="loading">
        <div class="spinner"></div>
        加载中...
      </div>
      
      <div v-else-if="emails.length === 0" class="empty-state">
        <div class="empty-icon">📧</div>
        <p>暂无邮件</p>
      </div>
      
      <div v-else class="email-items">
        <div 
          v-for="email in emails" 
          :key="email.id"
          class="email-item"
          @click="selectEmail(email)"
        >
          <div class="email-header">
            <div class="email-subject">{{ email.subject }}</div>
            <div class="email-time">{{ formatTime(email.received_at) }}</div>
          </div>
          <div class="email-meta">
            <div class="email-from">发件人: {{ email.from }}</div>
            <div class="email-to">收件人: {{ email.to }}</div>
          </div>
          <div class="email-status">
            <span class="status-badge" :class="getStatusClass(email.status)">
              {{ getStatusText(email.status) }}
            </span>
            <div class="email-actions">
              <button 
                class="btn-icon" 
                @click.stop="deleteEmail(email.id)"
                title="删除邮件"
              >
                🗑️
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- 分页 -->
    <div v-if="totalPages > 1" class="pagination">
      <button 
        class="btn btn-secondary btn-sm"
        :disabled="currentPage === 1"
        @click="goToPage(currentPage - 1)"
      >
        上一页
      </button>
      
      <span class="page-info">
        第 {{ currentPage }} 页，共 {{ totalPages }} 页
      </span>
      
      <button 
        class="btn btn-secondary btn-sm"
        :disabled="currentPage === totalPages"
        @click="goToPage(currentPage + 1)"
      >
        下一页
      </button>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, watch } from 'vue'
import { useAuthStore } from '@/stores/auth'
import { apiService, type EmailSummary } from '@/api'

interface Props {
  title?: string
}

interface Emits {
  (e: 'email-select', email: EmailSummary): void
}

const props = withDefaults(defineProps<Props>(), {
  title: '邮件列表'
})

const emit = defineEmits<Emits>()

const authStore = useAuthStore()

// 响应式数据
const emails = ref<EmailSummary[]>([])
const loading = ref(false)
const searchQuery = ref('')
const statusFilter = ref('')
const currentPage = ref(1)
const pageSize = ref(20)
const total = ref(0)
const showAllEmails = ref(false)

// 计算属性
const isAdmin = computed(() => authStore.isAdmin)
const totalPages = computed(() => Math.ceil(total.value / pageSize.value))

// 搜索防抖
let searchTimeout: number | undefined

// 方法
const loadEmails = async () => {
  loading.value = true
  try {
    const response = await apiService.getEmails(
      currentPage.value,
      pageSize.value,
      showAllEmails.value ? 'all' : undefined,
      searchQuery.value || undefined,
      statusFilter.value || undefined
    )
    
    if (response.success && response.data) {
      emails.value = response.data.items
      total.value = response.data.total
    }
  } catch (error) {
    console.error('加载邮件失败:', error)
    alert('加载邮件失败')
  } finally {
    loading.value = false
  }
}

const handleSearch = () => {
  clearTimeout(searchTimeout)
  searchTimeout = setTimeout(() => {
    currentPage.value = 1
    loadEmails()
  }, 500)
}

const handleFilterChange = () => {
  currentPage.value = 1
  loadEmails()
}

const toggleScope = () => {
  showAllEmails.value = !showAllEmails.value
  currentPage.value = 1
  loadEmails()
}

const goToPage = (page: number) => {
  if (page >= 1 && page <= totalPages.value) {
    currentPage.value = page
    loadEmails()
  }
}

const selectEmail = (email: EmailSummary) => {
  emit('email-select', email)
}

const deleteEmail = async (emailId: string) => {
  if (!confirm('确定要删除这封邮件吗？')) {
    return
  }
  
  try {
    const response = await apiService.deleteEmail(emailId)
    if (response.success) {
      await loadEmails()
      alert('邮件删除成功')
    } else {
      alert(response.message || '删除失败')
    }
  } catch (error) {
    console.error('删除邮件失败:', error)
    alert('删除邮件失败')
  }
}

const formatTime = (dateString: string) => {
  const date = new Date(dateString)
  const now = new Date()
  const diff = now.getTime() - date.getTime()
  
  if (diff < 60000) { // 1分钟内
    return '刚刚'
  } else if (diff < 3600000) { // 1小时内
    return `${Math.floor(diff / 60000)}分钟前`
  } else if (diff < 86400000) { // 1天内
    return `${Math.floor(diff / 3600000)}小时前`
  } else {
    return date.toLocaleDateString('zh-CN')
  }
}

const getStatusClass = (status: string) => {
  const statusMap: Record<string, string> = {
    received: 'status-received',
    processed: 'status-processed',
    forwarded: 'status-forwarded',
    failed: 'status-failed'
  }
  return statusMap[status] || 'status-default'
}

const getStatusText = (status: string) => {
  const statusMap: Record<string, string> = {
    received: '已接收',
    processed: '已处理',
    forwarded: '已转发',
    failed: '失败'
  }
  return statusMap[status] || status
}

// 监听分页变化
watch(currentPage, loadEmails)

// 组件挂载时加载数据
onMounted(() => {
  loadEmails()
})
</script>

<style scoped>
.email-list-container {
  background: white;
  border-radius: 10px;
  padding: 20px;
  box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
}

.email-controls {
  display: flex;
  gap: 15px;
  margin-bottom: 20px;
  flex-wrap: wrap;
}

.search-box {
  position: relative;
  flex: 1;
  min-width: 200px;
}

.search-input {
  width: 100%;
  padding: 10px 40px 10px 15px;
  border: 1px solid #ddd;
  border-radius: 25px;
  font-size: 14px;
}

.search-icon {
  position: absolute;
  right: 15px;
  top: 50%;
  transform: translateY(-50%);
  color: #7f8c8d;
}

.filter-controls {
  display: flex;
  gap: 10px;
  align-items: center;
}

.form-control {
  padding: 8px 12px;
  border: 1px solid #ddd;
  border-radius: 5px;
  font-size: 14px;
}

.btn {
  padding: 8px 16px;
  border: none;
  border-radius: 5px;
  font-size: 14px;
  cursor: pointer;
  transition: all 0.3s;
  font-weight: 500;
}

.btn-secondary {
  background: #6c757d;
  color: white;
}

.btn-primary {
  background: #3498db;
  color: white;
}

.btn-sm {
  padding: 6px 12px;
  font-size: 12px;
}

.btn:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.loading {
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 40px;
  color: #6c757d;
}

.spinner {
  width: 20px;
  height: 20px;
  border: 2px solid #f3f3f3;
  border-top: 2px solid #3498db;
  border-radius: 50%;
  animation: spin 1s linear infinite;
  margin-right: 10px;
}

@keyframes spin {
  0% { transform: rotate(0deg); }
  100% { transform: rotate(360deg); }
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

.email-items {
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.email-item {
  border: 1px solid #e9ecef;
  border-radius: 8px;
  padding: 15px;
  cursor: pointer;
  transition: all 0.3s ease;
  background: #fafafa;
}

.email-item:hover {
  background: #f8f9fa;
  border-color: #3498db;
  transform: translateY(-1px);
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
}

.email-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 8px;
}

.email-subject {
  font-weight: 600;
  color: #2c3e50;
  flex: 1;
  margin-right: 15px;
}

.email-time {
  color: #6c757d;
  font-size: 12px;
  white-space: nowrap;
}

.email-meta {
  display: flex;
  flex-direction: column;
  gap: 4px;
  margin-bottom: 10px;
  font-size: 14px;
  color: #555;
}

.email-from,
.email-to {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.email-status {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.status-badge {
  padding: 4px 8px;
  border-radius: 12px;
  font-size: 12px;
  font-weight: 500;
}

.status-received {
  background: #d4edda;
  color: #155724;
}

.status-processed {
  background: #d1ecf1;
  color: #0c5460;
}

.status-forwarded {
  background: #fff3cd;
  color: #856404;
}

.status-failed {
  background: #f8d7da;
  color: #721c24;
}

.status-default {
  background: #e2e3e5;
  color: #383d41;
}

.email-actions {
  display: flex;
  gap: 5px;
}

.btn-icon {
  background: none;
  border: none;
  cursor: pointer;
  padding: 4px;
  border-radius: 4px;
  transition: background 0.3s;
}

.btn-icon:hover {
  background: #e9ecef;
}

.pagination {
  display: flex;
  justify-content: center;
  align-items: center;
  gap: 15px;
  margin-top: 20px;
  padding: 15px 0;
}

.page-info {
  color: #6c757d;
  font-size: 14px;
}

@media (max-width: 768px) {
  .email-controls {
    flex-direction: column;
  }
  
  .search-box {
    min-width: auto;
  }
  
  .filter-controls {
    flex-direction: column;
    align-items: stretch;
  }
  
  .email-header {
    flex-direction: column;
    gap: 5px;
  }
  
  .email-subject {
    margin-right: 0;
  }
}
</style>
