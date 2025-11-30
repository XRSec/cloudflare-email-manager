<template>
  <Modal :show="show" :title="'邮件详情'" @close="$emit('close')" size="large">
    <div v-if="loading" class="loading-container">
      <div class="loading-spinner"></div>
      <p>正在加载邮件详情...</p>
    </div>

    <div v-else-if="error" class="error-container">
      <p class="error-message">{{ error }}</p>
      <Button @click="loadEmailDetail">重试</Button>
    </div>

    <div v-else-if="emailDetail" class="email-detail">
      <!-- 基本信息 -->
      <div class="detail-section">
        <div class="section-header">
          <h3 class="section-title">基本信息</h3>
          <Button variant="primary" size="sm" @click="downloadEml">
            📥 下载原始邮件 (.eml)
          </Button>
        </div>
        <div class="detail-grid">
          <div class="detail-item">
            <strong>主题:</strong>
            <span>{{ emailDetail.subject || '无主题' }}</span>
          </div>
          <div class="detail-item">
            <strong>发件人:</strong>
            <span>{{ emailDetail.from || emailDetail.from_address || '-' }}</span>
          </div>
          <div class="detail-item">
            <strong>收件人:</strong>
            <span>{{ emailDetail.to || emailDetail.to_address || '-' }}</span>
          </div>
          <div class="detail-item">
            <strong>时间:</strong>
            <span>{{ formatTime(emailDetail.received_at) }}</span>
          </div>
          <div class="detail-item">
            <strong>状态:</strong>
            <StatusBadge :status="emailDetail.status || (emailDetail.is_read ? 'read' : 'unread')" type="email" />
          </div>
        </div>
      </div>

      <!-- 邮件内容 -->
      <div class="detail-section">
        <h3 class="section-title">邮件内容</h3>
        <div class="email-content-wrapper">
          <div v-if="emailDetail.full_content_type === 'html'" ref="htmlContentRef" class="email-content-html"
            v-html="emailDetail.full_content || emailDetail.content"></div>
          <div v-else class="email-content-text" v-text="emailDetail.full_content || emailDetail.content || '无内容'">
          </div>
        </div>
      </div>

      <!-- 附件列表（仅显示非图片附件，图片已通过 postal-mime 渲染在邮件内容中） -->
      <div v-if="nonImageAttachments.length > 0" class="detail-section">
        <h3 class="section-title">附件 ({{ nonImageAttachments.length }})</h3>
        <div class="attachments-list">
          <div v-for="attachment in nonImageAttachments" :key="attachment.id" class="attachment-item">
            <!-- 附件信息区域 -->
            <div class="attachment-info">
              <div class="attachment-name">{{ attachment.filename }}</div>
              <div class="attachment-meta">
                <span class="attachment-size">{{ formatFileSize(attachment.size_bytes) }}</span>
                <span class="attachment-type">{{ attachment.content_type }}</span>
              </div>
              <div v-if="attachment.r2_key" class="attachment-path" title="R2存储路径">
                <span class="path-label">存储路径:</span>
                <span class="path-value">{{ attachment.r2_key }}</span>
              </div>
            </div>
            <!-- 附件操作区域 -->
            <div class="attachment-preview-section">
              <!-- 下载按钮 -->
              <div class="attachment-actions">
                <Button v-if="attachment.id" size="sm" variant="primary" @click="downloadAttachment(attachment)">
                  下载
                </Button>
                <span v-else class="attachment-error">附件 ID 缺失</span>
              </div>
            </div>
          </div>
        </div>
      </div>
      <div v-else-if="emailDetail && (!emailDetail.attachments || emailDetail.attachments.length === 0)"
        class="detail-section">
        <p class="no-attachments">此邮件没有附件</p>
      </div>
    </div>
  </Modal>
</template>

<script setup lang="ts">
import { ref, watch, computed, nextTick } from 'vue'
import { Modal, Button, StatusBadge } from '@/components/common'
import { apiService } from '@/composables/api'
import { cacheService } from '@/composables/cache'

interface Attachment {
  id: string
  filename: string
  content_type: string
  size_bytes: number
  r2_key?: string
  url?: string
  content_id?: string | null
}

interface EmailDetail {
  id: string
  subject?: string
  from?: string
  from_address?: string
  to?: string
  to_address?: string
  content?: string
  full_content?: string
  full_content_type?: 'text' | 'html'
  status?: string
  is_read?: number
  received_at: string
  attachments?: Attachment[]
}

interface Props {
  show: boolean
  emailId: string | null
}

const props = defineProps<Props>()

defineEmits<{
  close: []
}>()

const loading = ref(false)
const error = ref<string | null>(null)
const emailDetail = ref<EmailDetail | null>(null)
const lastLoadedEmailId = ref<string | null>(null) // 记录上次加载的 emailId，避免重复请求
const htmlContentRef = ref<HTMLElement | null>(null) // 邮件 HTML 内容容器的引用

// 监听 show 和 emailId 变化，统一处理加载逻辑
watch([() => props.show, () => props.emailId], ([newShow, newId]) => {
  if (newShow && newId && newId !== lastLoadedEmailId.value) {
    // 只有在模态窗口打开、有 emailId 且与上次不同时才加载
    lastLoadedEmailId.value = newId
    loadEmailDetail()
  } else if (!newShow) {
    // 关闭模态窗口时重置状态
    emailDetail.value = null
    error.value = null
    lastLoadedEmailId.value = null
  }
}, { immediate: true })

const loadEmailDetail = async () => {
  if (!props.emailId) return

  console.log('🆔 邮件ID:', props.emailId)

  // 1. 尝试从 localStorage 缓存读取
  const cacheKey = `email_detail_${props.emailId}`
  const cached = cacheService.get<EmailDetail>(cacheKey)

  if (cached) {
    // 检查缓存数据是否完整（必须包含 attachments 字段）
    // 邮件列表 API 返回的数据没有 attachments 字段，只有详情 API 返回的数据才有
    if (cached.attachments !== undefined) {
      console.log('📦 [EmailDetailModal] 从 localStorage 缓存加载邮件详情')
      emailDetail.value = cached

      // 打印附件信息
      if (cached.attachments && cached.attachments.length > 0) {
        console.log('📎 [EmailDetailModal] 附件信息 (来自缓存):')
        console.log('📦 附件数量:', cached.attachments.length)
      }

      // 如果是 HTML 内容，为图片添加错误处理
      if (cached.full_content_type === 'html') {
        attachImageErrorHandlers()
      }

      return // 使用缓存，无需继续请求 API
    } else {
      // 缓存数据不完整（可能是列表数据），强制请求 API
      console.log('⚠️ [EmailDetailModal] 缓存数据不完整（缺少 attachments 字段），将重新请求 API')
    }
  }

  // 2. 缓存未命中或不完整，从 API 加载（会利用 HTTP 缓存）
  console.log('🌐 [EmailDetailModal] 从 API 加载完整邮件详情')

  loading.value = true
  error.value = null

  try {
    const response = await apiService.getEmail(props.emailId)
    if (response.success && response.data) {
      emailDetail.value = response.data

      // 3. 写入 localStorage 缓存（24 小时）
      cacheService.set(cacheKey, response.data, 24 * 60 * 60 * 1000)
      console.log('✅ [EmailDetailModal] 已缓存邮件详情到 localStorage')
      const detail = emailDetail.value

      // 打印附件信息
      if (detail && detail.attachments && detail.attachments.length > 0) {
        console.log('📎 [EmailDetailModal] 附件信息:')
        console.log('📦 附件数量:', detail.attachments.length)
        detail.attachments.forEach((att: Attachment, index: number) => {
          console.log(`📎 附件 ${index + 1}:`)
          console.log('  📁 文件名:', att.filename)
          console.log('  📂 文件路径 (r2_key):', att.r2_key || '未提供')
          console.log('  🆔 附件ID:', att.id)
          console.log('  📏 文件大小:', att.size_bytes, 'bytes')
          console.log('  🏷️  内容类型:', att.content_type)
          console.log('  🔗 访问URL:', att.url || '未提供')
        })
      } else {
        console.log('📎 [EmailDetailModal] 此邮件没有附件')
        console.log('📧 邮件数据:', detail)
      }

      // 如果是 HTML 内容，为图片添加错误处理
      if (detail && detail.full_content_type === 'html') {
        attachImageErrorHandlers()
      }
    } else {
      error.value = response.message || '加载邮件详情失败'
    }
  } catch (err: any) {
    error.value = err.message || '加载邮件详情失败'
    console.error('加载邮件详情失败:', err)
  } finally {
    loading.value = false
  }
}

const formatTime = (dateString: string) => {
  return new Date(dateString).toLocaleString('zh-CN')
}

const formatFileSize = (bytes: number) => {
  if (bytes < 1024) return bytes + ' B'
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(2) + ' KB'
  return (bytes / (1024 * 1024)).toFixed(2) + ' MB'
}

const isImage = (contentType: string) => {
  return contentType.startsWith('image/')
}

// 过滤掉图片附件，只显示非图片附件（图片已通过 postal-mime 渲染在邮件内容中）
const nonImageAttachments = computed(() => {
  if (!emailDetail.value || !emailDetail.value.attachments) {
    return []
  }
  return emailDetail.value.attachments.filter(att => !isImage(att.content_type))
})

const getAttachmentUrl = (attachment: Attachment) => {
  // 检查附件 ID 是否存在
  if (!attachment.id) {
    console.warn('附件 ID 不存在:', attachment)
    return ''
  }

  // 使用 API 返回的 URL 或构建 URL
  if (attachment.url) {
    return attachment.url
  }
  // 如果没有 URL，使用 emailId 和 attachmentId 构建
  if (emailDetail.value?.id) {
    return `/api/emails/${emailDetail.value.id}/attachments/${attachment.id}`
  }
  console.warn('📎 [getAttachmentUrl] 无法构建URL，emailId或attachmentId缺失')
  return ''
}

const handleImageError = (event: Event) => {
  const img = event.target as HTMLImageElement
  if (img) {
    // 隐藏加载失败的图片
    img.style.display = 'none'
    // 可选：添加一个占位符或错误提示
    console.warn('图片加载失败:', img.src)
  }
}

// 为 HTML 内容中的所有图片添加错误处理
const attachImageErrorHandlers = () => {
  nextTick(() => {
    if (htmlContentRef.value) {
      const images = htmlContentRef.value.querySelectorAll('img')
      images.forEach((img) => {
        // 如果图片还没有绑定错误处理，则绑定
        if (!img.hasAttribute('data-error-handled')) {
          img.setAttribute('data-error-handled', 'true')
          img.addEventListener('error', handleImageError)
        }
      })
    }
  })
}

const downloadAttachment = (attachment: Attachment) => {
  if (!attachment.id) {
    console.error('无法下载附件：附件 ID 不存在', attachment)
    return
  }
  const url = getAttachmentUrl(attachment)
  if (url) {
    window.open(url, '_blank')
  } else {
    console.error('无法下载附件：URL 构建失败', attachment)
  }
}

// 下载原始邮件 .eml 文件
const downloadEml = () => {
  if (!emailDetail.value?.id) {
    console.error('无法下载邮件：邮件 ID 不存在')
    return
  }

  const url = `/api/emails/${emailDetail.value.id}/raw`
  const filename = `email_${emailDetail.value.id}.eml`

  // 创建隐藏的下载链接
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  link.style.display = 'none'
  document.body.appendChild(link)
  link.click()
  document.body.removeChild(link)
}
</script>

<style scoped>
.loading-container,
.error-container {
  text-align: center;
  padding: 40px;
}

.loading-spinner {
  border: 3px solid #f3f3f3;
  border-top: 3px solid #3498db;
  border-radius: 50%;
  width: 40px;
  height: 40px;
  animation: spin 1s linear infinite;
  margin: 0 auto 20px;
}

@keyframes spin {
  0% {
    transform: rotate(0deg);
  }

  100% {
    transform: rotate(360deg);
  }
}

.error-message {
  color: #e74c3c;
  margin-bottom: 20px;
}

.email-detail {
  padding: 20px 0;
}

.detail-section {
  margin-bottom: 30px;
}

.section-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 15px;
  padding-bottom: 8px;
  border-bottom: 2px solid #e0e0e0;
}

.section-title {
  font-size: 18px;
  font-weight: 600;
  margin: 0;
  color: #333;
}

.detail-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
  gap: 15px;
}

.detail-item {
  display: flex;
  flex-direction: column;
  gap: 5px;
}

.detail-item strong {
  color: #666;
  font-size: 14px;
}

.detail-item span {
  color: #333;
  font-size: 15px;
}

.email-content-wrapper {
  background: #f9f9f9;
  border: 1px solid #e0e0e0;
  border-radius: 6px;
  padding: 20px;
  max-height: 500px;
  overflow-y: auto;
}

.email-content-text {
  white-space: pre-wrap;
  word-wrap: break-word;
  line-height: 1.6;
  color: #333;
}

.email-content-html {
  line-height: 1.6;
  color: #333;
}

.email-content-html :deep(img) {
  max-width: 100%;
  height: auto;
  margin: 10px 0;
}

.attachments-list {
  display: flex;
  flex-direction: column;
  gap: 15px;
}

.attachment-item {
  display: flex;
  flex-direction: column;
  gap: 15px;
  padding: 15px;
  background: #f9f9f9;
  border: 1px solid #e0e0e0;
  border-radius: 6px;
}

.attachment-info {
  flex: 1;
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.attachment-name {
  font-weight: 500;
  color: #333;
  font-size: 15px;
  word-break: break-word;
}

.attachment-meta {
  display: flex;
  gap: 12px;
  align-items: center;
  font-size: 12px;
  color: #666;
}

.attachment-size {
  color: #666;
}

.attachment-type {
  padding: 2px 8px;
  background: #e0e0e0;
  border-radius: 4px;
  font-size: 11px;
}

.attachment-path {
  display: flex;
  flex-direction: column;
  gap: 4px;
  font-size: 11px;
  color: #999;
  padding-top: 8px;
  border-top: 1px solid #e8e8e8;
}

.path-label {
  color: #999;
  font-size: 11px;
}

.path-value {
  font-family: monospace;
  word-break: break-all;
  color: #666;
  font-size: 10px;
}

.attachment-error {
  color: #e74c3c;
  font-size: 12px;
}

.no-attachments {
  color: #999;
  font-style: italic;
  text-align: center;
  padding: 20px;
}

.attachment-preview-section {
  display: flex;
  flex-direction: column;
  gap: 10px;
  align-items: flex-start;
}

.attachment-actions {
  display: flex;
  align-items: center;
}
</style>
