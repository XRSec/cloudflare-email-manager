<template>
  <div class="email-detail-container">
    <div v-if="loading" class="loading">
      <div class="spinner"></div>
      加载中...
    </div>
    
    <div v-else-if="!email" class="empty-state">
      <div class="empty-icon">📧</div>
      <p>请选择一封邮件查看详情</p>
    </div>
    
    <div v-else class="email-detail">
      <!-- 邮件头部信息 -->
      <div class="email-header">
        <div class="email-subject">{{ email.subject }}</div>
        <div class="email-actions">
          <button class="btn btn-danger btn-sm" @click="deleteEmail">
            🗑️ 删除
          </button>
          <button class="btn btn-secondary btn-sm" @click="closeDetail">
            ✕ 关闭
          </button>
        </div>
      </div>
      
      <!-- 邮件元信息 -->
      <div class="email-meta">
        <div class="meta-row">
          <span class="meta-label">发件人:</span>
          <span class="meta-value">{{ email.from }}</span>
        </div>
        <div class="meta-row">
          <span class="meta-label">收件人:</span>
          <span class="meta-value">{{ email.to }}</span>
        </div>
        <div class="meta-row">
          <span class="meta-label">时间:</span>
          <span class="meta-value">{{ formatDateTime(email.received_at) }}</span>
        </div>
        <div class="meta-row">
          <span class="meta-label">状态:</span>
          <span class="status-badge" :class="getStatusClass(email.status)">
            {{ getStatusText(email.status) }}
          </span>
        </div>
      </div>
      
      <!-- 邮件内容 -->
      <div class="email-content">
        <div class="content-header">
          <h4>邮件内容</h4>
        </div>
        <div class="content-body">
          <div 
            v-if="email.content_type === 'html'"
            v-html="email.content"
            class="html-content"
          ></div>
          <div 
            v-else
            class="text-content"
          >{{ email.content }}</div>
        </div>
      </div>
      
      <!-- 附件列表 -->
      <div v-if="email.attachments && email.attachments.length > 0" class="attachments">
        <div class="attachments-header">
          <h4>附件 ({{ email.attachments.length }})</h4>
        </div>
        <div class="attachments-list">
          <div 
            v-for="attachment in email.attachments" 
            :key="attachment.id"
            class="attachment-item"
          >
            <div class="attachment-info">
              <div class="attachment-name">{{ attachment.filename }}</div>
              <div class="attachment-size">{{ formatFileSize(attachment.size) }}</div>
            </div>
            <button 
              class="btn btn-primary btn-sm"
              @click="downloadAttachment(attachment.id)"
            >
              📥 下载
            </button>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue'
import { apiService, type EmailDetail } from '@/api'

interface Props {
  emailId?: string
}

interface Emits {
  (e: 'close'): void
  (e: 'email-deleted', emailId: string): void
}

const props = defineProps<Props>()
const emit = defineEmits<Emits>()

const email = ref<EmailDetail | null>(null)
const loading = ref(false)

// 加载邮件详情
const loadEmailDetail = async (emailId: string) => {
  loading.value = true
  try {
    const response = await apiService.getEmail(emailId)
    if (response.success && response.data) {
      email.value = response.data
    } else {
      alert(response.message || '加载邮件详情失败')
    }
  } catch (error) {
    console.error('加载邮件详情失败:', error)
    alert('加载邮件详情失败')
  } finally {
    loading.value = false
  }
}

// 删除邮件
const deleteEmail = async () => {
  if (!email.value || !confirm('确定要删除这封邮件吗？')) {
    return
  }
  
  try {
    const response = await apiService.deleteEmail(email.value.id)
    if (response.success) {
      emit('email-deleted', email.value.id)
      closeDetail()
      alert('邮件删除成功')
    } else {
      alert(response.message || '删除失败')
    }
  } catch (error) {
    console.error('删除邮件失败:', error)
    alert('删除邮件失败')
  }
}

// 下载附件
const downloadAttachment = async (attachmentId: string) => {
  if (!email.value) return
  
  try {
    const blob = await apiService.downloadAttachment(email.value.id, attachmentId)
    const url = window.URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `attachment-${attachmentId}`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    window.URL.revokeObjectURL(url)
  } catch (error) {
    console.error('下载附件失败:', error)
    alert('下载附件失败')
  }
}

// 关闭详情
const closeDetail = () => {
  emit('close')
}

// 格式化时间
const formatDateTime = (dateString: string) => {
  const date = new Date(dateString)
  return date.toLocaleString('zh-CN', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit'
  })
}

// 格式化文件大小
const formatFileSize = (bytes: number) => {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
}

// 获取状态样式类
const getStatusClass = (status: string) => {
  const statusMap: Record<string, string> = {
    received: 'status-received',
    processed: 'status-processed',
    forwarded: 'status-forwarded',
    failed: 'status-failed'
  }
  return statusMap[status] || 'status-default'
}

// 获取状态文本
const getStatusText = (status: string) => {
  const statusMap: Record<string, string> = {
    received: '已接收',
    processed: '已处理',
    forwarded: '已转发',
    failed: '失败'
  }
  return statusMap[status] || status
}

// 监听 emailId 变化
watch(() => props.emailId, (newId) => {
  if (newId) {
    loadEmailDetail(newId)
  } else {
    email.value = null
  }
}, { immediate: true })
</script>

<style scoped>
.email-detail-container {
  background: white;
  border-radius: 10px;
  padding: 20px;
  box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
  height: 100%;
  overflow-y: auto;
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

.email-detail {
  display: flex;
  flex-direction: column;
  height: 100%;
}

.email-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 20px;
  padding-bottom: 15px;
  border-bottom: 1px solid #e9ecef;
}

.email-subject {
  font-size: 20px;
  font-weight: 600;
  color: #2c3e50;
  flex: 1;
  margin-right: 15px;
}

.email-actions {
  display: flex;
  gap: 10px;
}

.email-meta {
  margin-bottom: 20px;
  padding: 15px;
  background: #f8f9fa;
  border-radius: 8px;
}

.meta-row {
  display: flex;
  margin-bottom: 8px;
  align-items: center;
}

.meta-row:last-child {
  margin-bottom: 0;
}

.meta-label {
  font-weight: 500;
  color: #555;
  min-width: 80px;
  margin-right: 10px;
}

.meta-value {
  color: #2c3e50;
  flex: 1;
  word-break: break-all;
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

.email-content {
  flex: 1;
  margin-bottom: 20px;
}

.content-header {
  margin-bottom: 15px;
  padding-bottom: 10px;
  border-bottom: 1px solid #e9ecef;
}

.content-header h4 {
  margin: 0;
  color: #2c3e50;
  font-size: 16px;
}

.content-body {
  background: #fafafa;
  border-radius: 8px;
  padding: 20px;
  min-height: 200px;
  max-height: 400px;
  overflow-y: auto;
}

.html-content {
  line-height: 1.6;
}

.text-content {
  white-space: pre-wrap;
  line-height: 1.6;
  font-family: inherit;
}

.attachments {
  border-top: 1px solid #e9ecef;
  padding-top: 20px;
}

.attachments-header {
  margin-bottom: 15px;
}

.attachments-header h4 {
  margin: 0;
  color: #2c3e50;
  font-size: 16px;
}

.attachments-list {
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.attachment-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 12px;
  background: #f8f9fa;
  border-radius: 8px;
  border: 1px solid #e9ecef;
}

.attachment-info {
  flex: 1;
  margin-right: 15px;
}

.attachment-name {
  font-weight: 500;
  color: #2c3e50;
  margin-bottom: 4px;
  word-break: break-all;
}

.attachment-size {
  font-size: 12px;
  color: #6c757d;
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

.btn-danger {
  background: #dc3545;
  color: white;
}

.btn-danger:hover {
  background: #c82333;
}

.btn-secondary {
  background: #6c757d;
  color: white;
}

.btn-secondary:hover {
  background: #5a6268;
}

.btn-primary {
  background: #3498db;
  color: white;
}

.btn-primary:hover {
  background: #2980b9;
}

.btn-sm {
  padding: 6px 12px;
  font-size: 12px;
}

@media (max-width: 768px) {
  .email-header {
    flex-direction: column;
    gap: 15px;
  }
  
  .email-subject {
    margin-right: 0;
  }
  
  .email-actions {
    width: 100%;
    justify-content: flex-end;
  }
  
  .attachment-item {
    flex-direction: column;
    align-items: flex-start;
    gap: 10px;
  }
  
  .attachment-info {
    margin-right: 0;
  }
}
</style>
