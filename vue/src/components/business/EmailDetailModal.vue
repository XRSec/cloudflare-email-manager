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

      <!-- 附件列表 -->
      <div v-if="displayAttachments.length > 0" class="detail-section">
        <h3 class="section-title">附件 ({{ displayAttachments.length }})</h3>
        <div class="attachments-list">
          <div v-for="attachment in displayAttachments" :key="attachment.id" class="attachment-item">
            <div class="attachment-file-icon" :class="{ 'attachment-file-icon-image': isImageAttachment(attachment) }">
              {{ getAttachmentIcon(attachment) }}
            </div>
            <div class="attachment-info">
              <div class="attachment-name" :title="attachment.filename">{{ attachment.filename }}</div>
              <div class="attachment-meta">
                <span class="attachment-size">{{ formatFileSize(attachment.size_bytes) }}</span>
                <span class="attachment-type">{{ attachment.content_type }}</span>
                <span v-if="attachment.content_id" class="attachment-type">内嵌</span>
                <span v-if="attachment.deleted_at" class="attachment-type">已删除</span>
              </div>
            </div>
            <div class="attachment-actions">
              <button v-if="isImageAttachment(attachment)" class="attachment-icon-button" type="button"
                :disabled="Boolean(attachment.deleted_at)" title="预览" aria-label="预览附件"
                @click="previewAttachment(attachment)">
                <svg viewBox="0 0 24 24" aria-hidden="true">
                  <path d="M2.5 12s3.5-6 9.5-6 9.5 6 9.5 6-3.5 6-9.5 6-9.5-6-9.5-6Z" />
                  <circle cx="12" cy="12" r="3" />
                </svg>
              </button>
              <button class="attachment-icon-button" type="button" :disabled="Boolean(attachment.deleted_at)"
                title="下载" aria-label="下载附件" @click="downloadAttachment(attachment)">
                <svg viewBox="0 0 24 24" aria-hidden="true">
                  <path d="M12 3v12" />
                  <path d="m7 10 5 5 5-5" />
                  <path d="M5 21h14" />
                </svg>
              </button>
              <span v-if="!attachment.id" class="attachment-error">附件 ID 缺失</span>
            </div>
          </div>
        </div>
      </div>
      <div
        v-else-if="emailDetail && (!emailDetail.attachments || emailDetail.attachments.length === 0)"
        class="detail-section">
        <p class="no-attachments">此邮件没有附件</p>
      </div>
    </div>
    <div v-if="previewImageUrl" class="image-preview-overlay" @click="closeImagePreview">
      <div class="image-preview-dialog" @click.stop>
        <button class="image-preview-close" type="button" aria-label="关闭预览" @click="closeImagePreview">×</button>
        <img :src="previewImageUrl" :alt="previewImageName" @error="handleImageError" />
        <div class="image-preview-caption">{{ previewImageName }}</div>
      </div>
    </div>
  </Modal>
</template>

<script setup lang="ts">
import { ref, watch, computed, nextTick, onBeforeUnmount } from 'vue'
import { Modal, Button, StatusBadge } from '@/components/common'
import { emailApiService } from '@/composables/api-email'
import { cacheService } from '@/composables/cache'
import { formatDateTime } from '@/utils/time'

interface Attachment {
  id: string
  filename: string
  content_type: string
  size_bytes: number
  r2_key?: string
  url?: string
  content_id?: string | null
  deleted_at?: string | null
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
const previewImageUrl = ref('')
const previewImageName = ref('')

const loadEmailDetail = async () => {
  if (!props.emailId) return

  // 1. 尝试从 localStorage 缓存读取
  const cacheKey = `email_detail_v3_${props.emailId}`
  const cached = cacheService.get<EmailDetail>(cacheKey)

  if (cached) {
    // 检查缓存数据是否完整（必须包含 attachments 字段）
    // 邮件列表 API 返回的数据没有 attachments 字段，只有详情 API 返回的数据才有
    if (cached.attachments !== undefined) {
      emailDetail.value = cached

      // 如果是 HTML 内容，为图片添加错误处理
      if (cached.full_content_type === 'html') {
        attachImageErrorHandlers()
      }

      return // 使用缓存，无需继续请求 API
    } else {
      // 缓存数据不完整（可能是列表数据），强制请求 API
      console.warn('⚠️ [EmailDetailModal] 缓存数据不完整（缺少 attachments 字段），将重新请求 API')
    }
  }

  // 2. 缓存未命中或不完整，从 API 加载（会利用 HTTP 缓存）

  loading.value = true
  error.value = null

  try {
    const response = await emailApiService.getEmail(props.emailId)
    if (response.success && response.data) {
      emailDetail.value = response.data

      // 3. 写入 localStorage 缓存（24 小时）
      cacheService.set(cacheKey, response.data, 24 * 60 * 60 * 1000)
      const detail = emailDetail.value

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
  return formatDateTime(dateString)
}

const formatFileSize = (bytes: number) => {
  if (bytes < 1024) return bytes + ' B'
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(2) + ' KB'
  return (bytes / (1024 * 1024)).toFixed(2) + ' MB'
}

const isImage = (contentType: string) => {
  return contentType.startsWith('image/')
}

const IMAGE_EXTENSIONS = new Set(['png', 'jpg', 'jpeg', 'gif', 'webp', 'svg', 'bmp', 'tif', 'tiff', 'avif', 'heic', 'heif'])
const IMAGE_MIME_BY_EXTENSION: Record<string, string> = {
  png: 'image/png',
  jpg: 'image/jpeg',
  jpeg: 'image/jpeg',
  gif: 'image/gif',
  webp: 'image/webp',
  svg: 'image/svg+xml',
  bmp: 'image/bmp',
  tif: 'image/tiff',
  tiff: 'image/tiff',
  avif: 'image/avif',
  heic: 'image/heic',
  heif: 'image/heif'
}

const isImageAttachment = (attachment: Attachment) => {
  return isImage(attachment.content_type) || IMAGE_EXTENSIONS.has(getFileExtension(attachment.filename))
}

const getImageMimeTypeFromFilename = (filename: string) => IMAGE_MIME_BY_EXTENSION[getFileExtension(filename)] || ''

const displayAttachments = computed(() => {
  if (!emailDetail.value || !emailDetail.value.attachments) {
    return []
  }
  return emailDetail.value.attachments
})

// 缓存图片 blob URLs，使用普通对象以便 Vue 监测变化
const imageBlobUrls = ref<Record<string, string>>({})

const getFileExtension = (filename: string) => {
  const index = filename.lastIndexOf('.')
  return index >= 0 ? filename.slice(index + 1).toLowerCase() : ''
}

const getAttachmentIcon = (attachment: Attachment) => {
  const ext = getFileExtension(attachment.filename)
  if (isImageAttachment(attachment)) return 'IMG'
  if (ext === 'pdf') return 'PDF'
  if (['zip', 'rar', '7z', 'tar', 'gz'].includes(ext)) return 'ZIP'
  if (['doc', 'docx'].includes(ext)) return 'DOC'
  if (['xls', 'xlsx', 'csv'].includes(ext)) return 'XLS'
  if (['ppt', 'pptx'].includes(ext)) return 'PPT'
  if (['txt', 'md', 'log'].includes(ext)) return 'TXT'
  return 'FILE'
}

const getAttachmentUrl = (attachment: Attachment) => {
  // 检查附件 ID 是否存在
  if (!attachment.id) {
    console.warn('附件 ID 不存在:', attachment)
    return ''
  }

  // 对于图片附件，返回 blob URL（如果已缓存）或触发异步加载
  if (isImageAttachment(attachment)) {
    const cachedUrl = imageBlobUrls.value[attachment.id]
    if (cachedUrl) {
      return cachedUrl
    }
    // 如果还没有 blob URL，触发异步加载
    loadImageBlob(attachment)
    // 临时返回 API URL，图片加载后会自动更新
    if (emailDetail.value?.id) {
      return `/api/emails/${emailDetail.value.id}/attachments/${attachment.id}`
    }
    return ''
  }

  // 非图片附件：使用 API 返回的 URL 或构建 URL
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

// 异步加载图片为 blob URL
const loadImageBlob = async (attachment: Attachment) => {
  if (!attachment.id || !emailDetail.value?.id) return ''

  // 如果已经在加载或已加载，直接返回
  if (imageBlobUrls.value[attachment.id]) return imageBlobUrls.value[attachment.id]

  try {
    const url = `/api/emails/${emailDetail.value.id}/attachments/${attachment.id}`
    const response = await fetch(url, {
      credentials: 'include' // 发送 cookies
    })

    if (!response.ok) {
      console.error('加载图片失败:', response.status)
      return ''
    }

    const blob = await response.blob()
    const imageMimeType = getImageMimeTypeFromFilename(attachment.filename)
    const previewBlob = imageMimeType && !isImage(blob.type)
      ? new Blob([blob], { type: imageMimeType })
      : blob
    const blobUrl = URL.createObjectURL(previewBlob)
    // 使用对象赋值以触发 Vue 响应式更新
    imageBlobUrls.value = {
      ...imageBlobUrls.value,
      [attachment.id]: blobUrl
    }
    return blobUrl
  } catch (error) {
    console.error('加载图片失败:', error)
    return ''
  }
}

// 清理 blob URLs
onBeforeUnmount(() => {
  Object.values(imageBlobUrls.value).forEach(url => URL.revokeObjectURL(url))
  imageBlobUrls.value = {}
})

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
  if (attachment.deleted_at) {
    console.warn('附件不存在或已删除', attachment)
    return
  }
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

const previewAttachment = async (attachment: Attachment) => {
  if (attachment.deleted_at || !isImageAttachment(attachment)) return

  const url = await loadImageBlob(attachment)
  if (!url) return

  previewImageUrl.value = url
  previewImageName.value = attachment.filename
}

const closeImagePreview = () => {
  previewImageUrl.value = ''
  previewImageName.value = ''
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
    closeImagePreview()
  }
}, { immediate: true })
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
  /* max-height: 500px; */
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
  gap: 10px;
  width: min(620px, 100%);
}

.attachment-item {
  display: grid;
  grid-template-columns: auto minmax(0, 1fr) auto;
  gap: 10px;
  align-items: center;
  padding: 9px 10px;
  background: #f8fafc;
  border: 1px solid #e0e0e0;
  border-radius: 6px;
  min-width: 0;
}

.attachment-file-icon {
  width: 38px;
  height: 30px;
  border-radius: 4px;
  background: #eaf1fb;
  color: #2f5f98;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  font-size: 10px;
  font-weight: 700;
  letter-spacing: 0;
  border: 1px solid #d4e2f4;
}

.attachment-file-icon-image {
  background: #eaf7ef;
  color: #237044;
  border-color: #cdebd8;
}

.attachment-info {
  display: flex;
  flex-direction: column;
  gap: 5px;
  min-width: 0;
}

.attachment-name {
  font-weight: 500;
  color: #333;
  font-size: 14px;
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.attachment-meta {
  display: flex;
  gap: 8px;
  align-items: center;
  flex-wrap: wrap;
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

.attachment-actions {
  display: flex;
  align-items: center;
  gap: 8px;
}

.attachment-icon-button {
  width: 30px;
  height: 30px;
  border: 1px solid #d5dde8;
  border-radius: 4px;
  background: #fff;
  color: #4b5d72;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  cursor: pointer;
  transition: background 0.2s, border-color 0.2s, color 0.2s;
}

.attachment-icon-button:hover:not(:disabled) {
  background: #edf4ff;
  border-color: #9dbce6;
  color: #1f5fba;
}

.attachment-icon-button:disabled {
  opacity: 0.45;
  cursor: not-allowed;
}

.attachment-icon-button svg {
  width: 17px;
  height: 17px;
  fill: none;
  stroke: currentColor;
  stroke-width: 1.8;
  stroke-linecap: round;
  stroke-linejoin: round;
}

.image-preview-overlay {
  position: fixed;
  inset: 0;
  z-index: 2100;
  background: rgba(15, 23, 42, 0.74);
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 24px;
}

.image-preview-dialog {
  position: relative;
  max-width: min(920px, 96vw);
  max-height: 90vh;
  display: flex;
  flex-direction: column;
  gap: 10px;
  align-items: center;
}

.image-preview-dialog img {
  max-width: 100%;
  max-height: calc(90vh - 70px);
  object-fit: contain;
  background: #fff;
  border-radius: 6px;
}

.image-preview-close {
  position: absolute;
  top: -12px;
  right: -12px;
  width: 32px;
  height: 32px;
  border: 0;
  border-radius: 50%;
  background: #fff;
  color: #333;
  font-size: 22px;
  line-height: 1;
  cursor: pointer;
}

.image-preview-caption {
  max-width: 100%;
  color: #fff;
  font-size: 13px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

@media (max-width: 640px) {
  .attachment-item {
    grid-template-columns: auto minmax(0, 1fr);
  }

  .attachment-actions {
    grid-column: 2;
    justify-content: flex-start;
  }
}
</style>
