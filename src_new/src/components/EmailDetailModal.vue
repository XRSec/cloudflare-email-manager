<template>
  <Teleport to="body">
    <div class="modal" @click.self="$emit('close')">
      <div class="modal-content">
        <!-- 模态框头部 -->
        <div class="modal-header">
          <h3 class="modal-title">邮件详情</h3>
          <button
            class="modal-close"
            @click="$emit('close')"
          >
            ×
          </button>
        </div>

        <!-- 邮件信息 -->
        <div class="email-meta">
          <div class="meta-row">
            <strong>发件人:</strong>
            <span>{{ email.sender_email }}</span>
          </div>
          <div class="meta-row">
            <strong>收件人:</strong>
            <span>{{ email.recipient_email }}</span>
          </div>
          <div class="meta-row">
            <strong>主题:</strong>
            <span>{{ email.subject || '(无主题)' }}</span>
          </div>
          <div class="meta-row">
            <strong>时间:</strong>
            <span>{{ formatDate(email.received_at) }}</span>
          </div>
          <div class="meta-row">
            <strong>邮件ID:</strong>
            <span class="text-muted">{{ email.message_id }}</span>
          </div>
        </div>

        <!-- 附件列表 -->
        <div v-if="email.attachments && email.attachments.length > 0" class="attachments-section">
          <h4>附件 ({{ email.attachments.length }})</h4>
          <div class="attachments-list">
            <div
              v-for="attachment in email.attachments"
              :key="attachment.id"
              class="attachment-item"
            >
              <div class="attachment-info">
                <div class="attachment-name">
                  📎 {{ attachment.filename }}
                </div>
                <div class="attachment-meta">
                  {{ formatFileSize(attachment.size_bytes) }} • {{ attachment.content_type }}
                </div>
              </div>
              <button
                class="btn btn-sm btn-primary"
                @click="downloadAttachment(attachment)"
                :disabled="downloading === attachment.id"
              >
                <span v-if="downloading === attachment.id">下载中...</span>
                <span v-else>下载</span>
              </button>
            </div>
          </div>
        </div>

        <!-- 邮件内容 -->
        <div class="email-content-section">
          <h4>邮件内容</h4>
          <div class="content-tabs">
            <button
              :class="['tab-btn', { active: activeTab === 'html' }]"
              @click="activeTab = 'html'"
              v-if="email.html_content"
            >
              HTML
            </button>
            <button
              :class="['tab-btn', { active: activeTab === 'text' }]"
              @click="activeTab = 'text'"
              v-if="email.text_content"
            >
              纯文本
            </button>
            <button
              :class="['tab-btn', { active: activeTab === 'raw' }]"
              @click="activeTab = 'raw'"
              v-if="email.raw_email"
            >
              原始邮件
            </button>
          </div>
          
          <div class="content-display">
            <!-- HTML 内容 -->
            <div
              v-if="activeTab === 'html' && email.html_content"
              class="html-content"
              v-html="sanitizeHtml(email.html_content)"
            ></div>
            
            <!-- 纯文本内容 -->
            <div
              v-else-if="activeTab === 'text' && email.text_content"
              class="text-content"
            >
              <pre>{{ email.text_content }}</pre>
            </div>
            
            <!-- 原始邮件 -->
            <div
              v-else-if="activeTab === 'raw' && email.raw_email"
              class="raw-content"
            >
              <pre>{{ email.raw_email }}</pre>
            </div>
            
            <!-- 无内容 -->
            <div v-else class="no-content">
              <p>此邮件没有内容</p>
            </div>
          </div>
        </div>

        <!-- 操作按钮 -->
        <div class="modal-actions">
          <button
            class="btn btn-danger"
            @click="handleDelete"
            :disabled="deleting"
          >
            <span v-if="deleting">删除中...</span>
            <span v-else">🗑️ 删除邮件</span>
          </button>
          <button
            class="btn btn-light"
            @click="$emit('close')"
          >
            关闭
          </button>
        </div>
      </div>
    </div>
  </Teleport>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useEmailStore } from '@/stores/emails'
import { useSystemStore } from '@/stores/system'
import type { Email, Attachment } from '@/types'

// Props
interface Props {
  email: Email
}

const props = defineProps<Props>()

// Emits
const emit = defineEmits<{
  close: []
  delete: [emailId: number]
}>()

// Composables
const emailStore = useEmailStore()
const systemStore = useSystemStore()

// State
const activeTab = ref<'html' | 'text' | 'raw'>('html')
const downloading = ref<number | null>(null)
const deleting = ref(false)

// Computed
const formatDate = computed(() => systemStore.formatDate)
const formatFileSize = computed(() => systemStore.formatFileSize)

// Methods
const downloadAttachment = async (attachment: Attachment) => {
  downloading.value = attachment.id
  try {
    await emailStore.downloadAttachment(attachment)
  } catch (error) {
    console.error('下载附件失败:', error)
  } finally {
    downloading.value = null
  }
}

const handleDelete = async () => {
  if (!confirm('确定要删除这封邮件吗？此操作不可恢复！')) {
    return
  }
  
  deleting.value = true
  try {
    emit('delete', props.email.id)
  } finally {
    deleting.value = false
  }
}

const sanitizeHtml = (html: string): string => {
  // 简单的 HTML 清理，移除危险标签
  // 在生产环境中建议使用专门的 HTML 清理库如 DOMPurify
  return html
    .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
    .replace(/<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/gi, '')
    .replace(/<object\b[^<]*(?:(?!<\/object>)<[^<]*)*<\/object>/gi, '')
    .replace(/<embed\b[^<]*(?:(?!<\/embed>)<[^<]*)*<\/embed>/gi, '')
    .replace(/javascript:/gi, '')
    .replace(/on\w+\s*=/gi, '')
}

const determineDefaultTab = () => {
  if (props.email.html_content) {
    activeTab.value = 'html'
  } else if (props.email.text_content) {
    activeTab.value = 'text'
  } else if (props.email.raw_email) {
    activeTab.value = 'raw'
  }
}

// Lifecycle
onMounted(() => {
  determineDefaultTab()
})
</script>

<style scoped>
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
  z-index: 10000;
  padding: var(--spacing-4);
}

.modal-content {
  background: var(--white);
  border-radius: var(--border-radius-xl);
  padding: var(--spacing-6);
  max-width: 800px;
  width: 100%;
  max-height: 90vh;
  overflow-y: auto;
  box-shadow: var(--shadow-xl);
}

.modal-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: var(--spacing-6);
  padding-bottom: var(--spacing-4);
  border-bottom: 1px solid var(--gray-200);
}

.modal-title {
  font-size: var(--font-size-xl);
  font-weight: 600;
  color: var(--gray-800);
  margin: 0;
}

.modal-close {
  background: none;
  border: none;
  font-size: 1.5rem;
  cursor: pointer;
  color: var(--gray-500);
  padding: var(--spacing-2);
  border-radius: var(--border-radius);
  transition: var(--transition);
  width: 32px;
  height: 32px;
  display: flex;
  align-items: center;
  justify-content: center;
}

.modal-close:hover {
  background: var(--gray-100);
  color: var(--gray-700);
}

.email-meta {
  margin-bottom: var(--spacing-6);
  background: var(--gray-100);
  padding: var(--spacing-4);
  border-radius: var(--border-radius);
}

.meta-row {
  display: flex;
  margin-bottom: var(--spacing-2);
  gap: var(--spacing-3);
}

.meta-row:last-child {
  margin-bottom: 0;
}

.meta-row strong {
  min-width: 80px;
  color: var(--gray-700);
  font-size: var(--font-size-sm);
}

.meta-row span {
  flex: 1;
  word-break: break-all;
}

.attachments-section {
  margin-bottom: var(--spacing-6);
}

.attachments-section h4 {
  margin-bottom: var(--spacing-4);
  color: var(--gray-800);
  font-size: var(--font-size-lg);
}

.attachments-list {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-3);
}

.attachment-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: var(--spacing-3);
  background: var(--gray-100);
  border-radius: var(--border-radius);
  gap: var(--spacing-4);
}

.attachment-info {
  flex: 1;
}

.attachment-name {
  font-weight: 500;
  color: var(--gray-800);
  margin-bottom: var(--spacing-1);
}

.attachment-meta {
  font-size: var(--font-size-sm);
  color: var(--gray-600);
}

.email-content-section {
  margin-bottom: var(--spacing-6);
}

.email-content-section h4 {
  margin-bottom: var(--spacing-4);
  color: var(--gray-800);
  font-size: var(--font-size-lg);
}

.content-tabs {
  display: flex;
  gap: var(--spacing-2);
  margin-bottom: var(--spacing-4);
  border-bottom: 1px solid var(--gray-200);
}

.tab-btn {
  padding: var(--spacing-2) var(--spacing-4);
  background: none;
  border: none;
  cursor: pointer;
  color: var(--gray-600);
  font-weight: 500;
  border-bottom: 2px solid transparent;
  transition: var(--transition);
}

.tab-btn.active {
  color: var(--primary-color);
  border-bottom-color: var(--primary-color);
}

.tab-btn:hover:not(.active) {
  color: var(--gray-800);
}

.content-display {
  border: 1px solid var(--gray-200);
  border-radius: var(--border-radius);
  max-height: 400px;
  overflow-y: auto;
}

.html-content {
  padding: var(--spacing-4);
}

.text-content,
.raw-content {
  padding: var(--spacing-4);
}

.text-content pre,
.raw-content pre {
  margin: 0;
  white-space: pre-wrap;
  word-wrap: break-word;
  font-family: 'Courier New', monospace;
  font-size: var(--font-size-sm);
  line-height: 1.4;
}

.no-content {
  padding: var(--spacing-8);
  text-align: center;
  color: var(--gray-500);
}

.modal-actions {
  display: flex;
  justify-content: space-between;
  gap: var(--spacing-3);
  padding-top: var(--spacing-4);
  border-top: 1px solid var(--gray-200);
}

/* 响应式设计 */
@media (max-width: 768px) {
  .modal {
    padding: var(--spacing-2);
  }
  
  .modal-content {
    padding: var(--spacing-4);
  }
  
  .meta-row {
    flex-direction: column;
    gap: var(--spacing-1);
  }
  
  .meta-row strong {
    min-width: auto;
  }
  
  .attachment-item {
    flex-direction: column;
    align-items: stretch;
    gap: var(--spacing-3);
  }
  
  .content-tabs {
    flex-wrap: wrap;
  }
  
  .modal-actions {
    flex-direction: column-reverse;
  }
}

/* HTML 内容样式重置 */
.html-content :deep(img) {
  max-width: 100%;
  height: auto;
}

.html-content :deep(table) {
  width: 100%;
  border-collapse: collapse;
}

.html-content :deep(table td),
.html-content :deep(table th) {
  padding: var(--spacing-2);
  border: 1px solid var(--gray-300);
}

.html-content :deep(blockquote) {
  margin: var(--spacing-4) 0;
  padding: var(--spacing-3) var(--spacing-4);
  border-left: 4px solid var(--primary-color);
  background: var(--gray-100);
}

.html-content :deep(code) {
  background: var(--gray-100);
  padding: var(--spacing-1) var(--spacing-2);
  border-radius: var(--border-radius-sm);
  font-family: 'Courier New', monospace;
  font-size: var(--font-size-sm);
}

.html-content :deep(pre) {
  background: var(--gray-100);
  padding: var(--spacing-3);
  border-radius: var(--border-radius);
  overflow-x: auto;
  margin: var(--spacing-4) 0;
}
</style>