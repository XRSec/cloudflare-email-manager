<template>
  <div class="mailbox-list-container">
    <div class="mailbox-header">
      <h2>📮 我的邮箱</h2>
      <button class="btn btn-primary" @click="showCreateModal">
        + 申请新邮箱
      </button>
    </div>

    <div v-if="loading" class="loading">
      <div class="spinner"></div>
      加载中...
    </div>
    
    <div v-else-if="mailboxes.length === 0" class="empty-state">
      <div class="empty-icon">📮</div>
      <p>暂无邮箱</p>
      <button class="btn btn-primary" @click="showCreateModal">
        申请第一个邮箱
      </button>
    </div>
    
    <div v-else class="mailbox-list">
      <div 
        v-for="mailbox in mailboxes" 
        :key="mailbox.id"
        class="mailbox-item"
      >
        <div class="mailbox-info">
          <div class="mailbox-address">{{ mailbox.address }}</div>
          <div class="mailbox-meta">
            <span class="status-badge" :class="getStatusClass(mailbox.status)">
              {{ getStatusText(mailbox.status) }}
            </span>
            <span class="created-time">
              创建于 {{ formatDate(mailbox.created_at) }}
            </span>
          </div>
        </div>
        <div class="mailbox-actions">
          <button 
            v-if="canDelete(mailbox)"
            class="btn btn-danger btn-sm"
            @click="deleteMailbox(mailbox.id)"
          >
            🗑️ 删除
          </button>
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

    <!-- 申请邮箱模态框 -->
    <div v-if="showModal" class="modal" @click="closeModal">
      <div class="modal-content" @click.stop>
        <div class="modal-header">
          <h3>申请新邮箱</h3>
          <button class="close-btn" @click="closeModal">×</button>
        </div>
        
        <form @submit.prevent="submitApplication">
          <div class="form-group">
            <label class="form-label">申请理由</label>
            <textarea 
              v-model="applicationForm.reason"
              class="form-control"
              placeholder="请说明申请邮箱的用途..."
              rows="4"
            ></textarea>
          </div>
          
          <div class="modal-footer">
            <button type="button" class="btn btn-secondary" @click="closeModal">
              取消
            </button>
            <button 
              type="submit" 
              class="btn btn-primary"
              :disabled="submitting"
            >
              {{ submitting ? '提交中...' : '提交申请' }}
            </button>
          </div>
        </form>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { apiService, type Mailbox, type MailboxApplicationRequest } from '@/api'

interface Emits {
  (e: 'mailbox-deleted', mailboxId: number): void
}

const emit = defineEmits<Emits>()

// 响应式数据
const mailboxes = ref<Mailbox[]>([])
const loading = ref(false)
const currentPage = ref(1)
const pageSize = ref(20)
const total = ref(0)
const showModal = ref(false)
const submitting = ref(false)

// 申请表单
const applicationForm = ref<MailboxApplicationRequest>({
  reason: ''
})

// 计算属性
const totalPages = computed(() => Math.ceil(total.value / pageSize.value))

// 方法
const loadMailboxes = async () => {
  loading.value = true
  try {
    // 我的邮箱页面：不传 scope 参数，始终返回当前用户的邮箱
    const response = await apiService.getMailboxes(currentPage.value, pageSize.value)
    if (response.success && response.data) {
      mailboxes.value = response.data.items
      total.value = response.data.total
    }
  } catch (error) {
    console.error('加载邮箱列表失败:', error)
    alert('加载邮箱列表失败')
  } finally {
    loading.value = false
  }
}

const showCreateModal = () => {
  showModal.value = true
  applicationForm.value.reason = ''
}

const closeModal = () => {
  showModal.value = false
  applicationForm.value.reason = ''
}

const submitApplication = async () => {
  submitting.value = true
  try {
    const response = await apiService.createMailboxApplication(applicationForm.value)
    if (response.success) {
      alert('申请提交成功，请等待审核')
      closeModal()
      await loadMailboxes()
    } else {
      alert(response.message || '申请提交失败')
    }
  } catch (error) {
    console.error('提交申请失败:', error)
    alert('提交申请失败')
  } finally {
    submitting.value = false
  }
}

const deleteMailbox = async (mailboxId: number) => {
  if (!confirm('确定要删除这个邮箱吗？删除后无法恢复。')) {
    return
  }
  
  try {
    const response = await apiService.deleteMailbox(mailboxId)
    if (response.success) {
      emit('mailbox-deleted', mailboxId)
      await loadMailboxes()
      alert('邮箱删除成功')
    } else {
      alert(response.message || '删除失败')
    }
  } catch (error) {
    console.error('删除邮箱失败:', error)
    alert('删除邮箱失败')
  }
}

const canDelete = (mailbox: Mailbox) => {
  // 这里可以根据业务规则判断是否可以删除
  // 比如默认邮箱不能删除等
  return mailbox.status === 'active'
}

const goToPage = (page: number) => {
  if (page >= 1 && page <= totalPages.value) {
    currentPage.value = page
    loadMailboxes()
  }
}

const formatDate = (dateString: string) => {
  const date = new Date(dateString)
  return date.toLocaleDateString('zh-CN')
}

const getStatusClass = (status: string) => {
  const statusMap: Record<string, string> = {
    active: 'status-active',
    disabled: 'status-disabled',
    pending: 'status-pending'
  }
  return statusMap[status] || 'status-default'
}

const getStatusText = (status: string) => {
  const statusMap: Record<string, string> = {
    active: '正常',
    disabled: '已禁用',
    pending: '待审核'
  }
  return statusMap[status] || status
}

// 组件挂载时加载数据
onMounted(() => {
  loadMailboxes()
})
</script>

<style scoped>
.mailbox-list-container {
  background: white;
  border-radius: 10px;
  padding: 20px;
  box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
}

.mailbox-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 20px;
  padding-bottom: 15px;
  border-bottom: 1px solid #e9ecef;
}

.mailbox-header h2 {
  margin: 0;
  color: #2c3e50;
  font-size: 20px;
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

.mailbox-list {
  display: flex;
  flex-direction: column;
  gap: 15px;
}

.mailbox-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 20px;
  background: #f8f9fa;
  border-radius: 8px;
  border: 1px solid #e9ecef;
  transition: all 0.3s ease;
}

.mailbox-item:hover {
  background: #e9ecef;
  border-color: #3498db;
}

.mailbox-info {
  flex: 1;
}

.mailbox-address {
  font-size: 18px;
  font-weight: 600;
  color: #2c3e50;
  margin-bottom: 8px;
}

.mailbox-meta {
  display: flex;
  align-items: center;
  gap: 15px;
  flex-wrap: wrap;
}

.status-badge {
  padding: 4px 8px;
  border-radius: 12px;
  font-size: 12px;
  font-weight: 500;
}

.status-active {
  background: #d4edda;
  color: #155724;
}

.status-disabled {
  background: #f8d7da;
  color: #721c24;
}

.status-pending {
  background: #fff3cd;
  color: #856404;
}

.status-default {
  background: #e2e3e5;
  color: #383d41;
}

.created-time {
  color: #6c757d;
  font-size: 14px;
}

.mailbox-actions {
  display: flex;
  gap: 10px;
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

.btn {
  padding: 8px 16px;
  border: none;
  border-radius: 5px;
  font-size: 14px;
  cursor: pointer;
  transition: all 0.3s;
  font-weight: 500;
  display: inline-block;
}

.btn-primary {
  background: #3498db;
  color: white;
}

.btn-primary:hover:not(:disabled) {
  background: #2980b9;
  transform: translateY(-1px);
}

.btn-danger {
  background: #dc3545;
  color: white;
}

.btn-danger:hover:not(:disabled) {
  background: #c82333;
}

.btn-secondary {
  background: #6c757d;
  color: white;
}

.btn-secondary:hover:not(:disabled) {
  background: #5a6268;
}

.btn-sm {
  padding: 6px 12px;
  font-size: 12px;
}

.btn:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

/* 模态框样式 */
.modal {
  position: fixed;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  background: rgba(0, 0, 0, 0.5);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
}

.modal-content {
  background: white;
  border-radius: 10px;
  padding: 30px;
  max-width: 500px;
  width: 90%;
  max-height: 90vh;
  overflow-y: auto;
}

.modal-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 20px;
  padding-bottom: 15px;
  border-bottom: 1px solid #e9ecef;
}

.modal-header h3 {
  margin: 0;
  color: #2c3e50;
}

.close-btn {
  background: none;
  border: none;
  font-size: 24px;
  cursor: pointer;
  color: #6c757d;
  padding: 0;
  width: 30px;
  height: 30px;
  display: flex;
  align-items: center;
  justify-content: center;
}

.close-btn:hover {
  color: #2c3e50;
}

.form-group {
  margin-bottom: 20px;
}

.form-label {
  display: block;
  margin-bottom: 5px;
  font-weight: 500;
  color: #555;
}

.form-control {
  width: 100%;
  padding: 10px;
  border: 1px solid #ddd;
  border-radius: 5px;
  font-size: 14px;
  transition: border-color 0.3s;
  font-family: inherit;
}

.form-control:focus {
  outline: none;
  border-color: #3498db;
  box-shadow: 0 0 0 3px rgba(52, 152, 219, 0.1);
}

.modal-footer {
  display: flex;
  justify-content: flex-end;
  gap: 10px;
  margin-top: 20px;
  padding-top: 15px;
  border-top: 1px solid #e9ecef;
}

@media (max-width: 768px) {
  .mailbox-header {
    flex-direction: column;
    gap: 15px;
    align-items: flex-start;
  }
  
  .mailbox-item {
    flex-direction: column;
    align-items: flex-start;
    gap: 15px;
  }
  
  .mailbox-actions {
    width: 100%;
    justify-content: flex-end;
  }
  
  .mailbox-meta {
    flex-direction: column;
    align-items: flex-start;
    gap: 8px;
  }
}
</style>
