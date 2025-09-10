<template>
  <Teleport to="body">
    <div class="modal" @click.self="$emit('close')">
      <div class="modal-content">
        <!-- 模态框头部 -->
        <div class="modal-header">
          <h3 class="modal-title">用户详情</h3>
          <button
            class="modal-close"
            @click="$emit('close')"
          >
            ×
          </button>
        </div>

        <!-- 用户基本信息 -->
        <div class="user-info-section">
          <h4>基本信息</h4>
          <div class="info-grid">
            <div class="info-item">
              <label>用户 ID</label>
              <span>{{ user.id }}</span>
            </div>
            <div class="info-item">
              <label>邮箱前缀</label>
              <span><code>{{ user.email_prefix }}</code></span>
            </div>
            <div class="info-item">
              <label>完整邮箱</label>
              <span>{{ fullEmail }}</span>
            </div>
            <div class="info-item">
              <label>用户类型</label>
              <span :class="['badge', user.user_type === 'admin' ? 'badge-primary' : 'badge-success']">
                {{ user.user_type === 'admin' ? '管理员' : '普通用户' }}
              </span>
            </div>
            <div class="info-item">
              <label>注册时间</label>
              <span>{{ formatDate(user.created_at) }}</span>
            </div>
            <div class="info-item">
              <label>最后更新</label>
              <span>{{ formatDate(user.updated_at) }}</span>
            </div>
          </div>
        </div>

        <!-- Webhook 配置 -->
        <div class="webhook-section">
          <h4>Webhook 配置</h4>
          <div class="webhook-info">
            <div class="info-item">
              <label>Webhook URL</label>
              <div class="webhook-url">
                <span v-if="user.webhook_url" class="url-text">{{ user.webhook_url }}</span>
                <span v-else class="text-muted">未配置</span>
                <button
                  v-if="user.webhook_url"
                  class="btn btn-sm btn-light ml-2"
                  @click="copyToClipboard(user.webhook_url)"
                >
                  📋 复制
                </button>
              </div>
            </div>
            <div class="info-item">
              <label>Webhook 密钥</label>
              <span v-if="user.webhook_secret" class="text-success">✅ 已设置</span>
              <span v-else class="text-muted">未设置</span>
            </div>
          </div>

          <!-- Webhook 测试 -->
          <div v-if="user.webhook_url" class="webhook-test">
            <button
              class="btn btn-outline-primary"
              @click="testWebhook"
              :disabled="testing"
            >
              <span v-if="testing">测试中...</span>
              <span v-else>🧪 测试 Webhook</span>
            </button>
            <small class="text-muted">发送测试请求到用户的 Webhook 地址</small>
          </div>
        </div>

        <!-- 用户统计 -->
        <div class="stats-section">
          <h4>用户统计</h4>
          <div class="stats-grid">
            <div class="stat-item">
              <div class="stat-number">{{ userStats.emailCount }}</div>
              <div class="stat-label">邮件总数</div>
            </div>
            <div class="stat-item">
              <div class="stat-number">{{ userStats.attachmentCount }}</div>
              <div class="stat-label">附件总数</div>
            </div>
            <div class="stat-item">
              <div class="stat-number">{{ userStats.storageUsed }}</div>
              <div class="stat-label">存储使用</div>
            </div>
            <div class="stat-item">
              <div class="stat-number">{{ userStats.lastEmailDate }}</div>
              <div class="stat-label">最后邮件</div>
            </div>
          </div>
        </div>

        <!-- 最近邮件 -->
        <div class="recent-emails-section">
          <h4>最近邮件 (最近 5 封)</h4>
          <div v-if="recentEmails.length === 0" class="no-emails">
            <p class="text-muted">暂无邮件</p>
          </div>
          <div v-else class="emails-list">
            <div
              v-for="email in recentEmails"
              :key="email.id"
              class="email-item"
            >
              <div class="email-header">
                <div class="email-sender">{{ email.sender_email }}</div>
                <div class="email-time">{{ formatDate(email.received_at) }}</div>
              </div>
              <div class="email-subject">{{ email.subject || '(无主题)' }}</div>
              <div class="email-preview">{{ getEmailPreview(email) }}</div>
            </div>
          </div>
        </div>

        <!-- 操作按钮 -->
        <div class="modal-actions">
          <button
            class="btn btn-info"
            @click="sendUserInfo"
            :disabled="sendingInfo"
          >
            <span v-if="sendingInfo">发送中...</span>
            <span v-else">📧 发送用户信息</span>
          </button>
          <button
            v-if="user.user_type !== 'admin'"
            class="btn btn-danger"
            @click="deleteUser"
            :disabled="deleting"
          >
            <span v-if="deleting">删除中...</span>
            <span v-else">🗑️ 删除用户</span>
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
import { useSystemStore } from '@/stores/system'
import { useAdminStore } from '@/stores/admin'
import type { User, Email } from '@/types'

// Props
interface Props {
  user: User
}

const props = defineProps<Props>()

// Emits
const emit = defineEmits<{
  close: []
  updated: []
}>()

// Composables
const systemStore = useSystemStore()
const adminStore = useAdminStore()

// State
const testing = ref(false)
const sendingInfo = ref(false)
const deleting = ref(false)
const recentEmails = ref<Email[]>([])
const userStats = ref({
  emailCount: 0,
  attachmentCount: 0,
  storageUsed: '0 B',
  lastEmailDate: '-'
})

// Computed
const fullEmail = computed(() => {
  return systemStore.getFullEmailAddress(props.user.email_prefix)
})

// Methods
const formatDate = (dateString?: string): string => {
  if (!dateString) return '-'
  return systemStore.formatDate(dateString)
}

const copyToClipboard = async (text: string) => {
  try {
    await navigator.clipboard.writeText(text)
    showMessage('已复制到剪贴板', 'success')
  } catch (error) {
    // 降级方案
    const textArea = document.createElement('textarea')
    textArea.value = text
    document.body.appendChild(textArea)
    textArea.select()
    document.execCommand('copy')
    document.body.removeChild(textArea)
    showMessage('已复制到剪贴板', 'success')
  }
}

const testWebhook = async () => {
  if (!props.user.webhook_url) return

  testing.value = true
  try {
    // 这里应该调用测试 Webhook 的 API
    // 暂时模拟测试
    await new Promise(resolve => setTimeout(resolve, 2000))
    showMessage('Webhook 测试成功', 'success')
  } catch (error) {
    showMessage('Webhook 测试失败', 'error')
  } finally {
    testing.value = false
  }
}

const sendUserInfo = async () => {
  if (!confirm(`确定要发送用户信息到 ${fullEmail.value} 吗？`)) {
    return
  }

  sendingInfo.value = true
  try {
    const success = await adminStore.sendUserInfo(props.user.id)
    if (success) {
      showMessage('用户信息发送成功', 'success')
    }
  } catch (error) {
    console.error('发送用户信息失败:', error)
  } finally {
    sendingInfo.value = false
  }
}

const deleteUser = async () => {
  const confirmText = `确定要删除用户 ${props.user.email_prefix} 吗？\n\n此操作将：\n- 删除用户账户\n- 删除所有相关邮件\n- 删除所有附件\n\n此操作不可恢复！`
  
  if (!confirm(confirmText)) {
    return
  }

  deleting.value = true
  try {
    const success = await adminStore.deleteUser(props.user.id)
    if (success) {
      showMessage(`用户 ${props.user.email_prefix} 删除成功`, 'success')
      emit('updated')
      emit('close')
    }
  } catch (error) {
    console.error('删除用户失败:', error)
  } finally {
    deleting.value = false
  }
}

const getEmailPreview = (email: Email): string => {
  const content = email.text_content || email.html_content || '(无内容)'
  return content.length > 50 ? content.substring(0, 50) + '...' : content
}

const loadUserStats = async () => {
  try {
    // 这里应该调用获取用户统计信息的 API
    // 暂时使用模拟数据
    userStats.value = {
      emailCount: Math.floor(Math.random() * 100),
      attachmentCount: Math.floor(Math.random() * 20),
      storageUsed: systemStore.formatFileSize(Math.floor(Math.random() * 1024 * 1024 * 100)),
      lastEmailDate: Math.random() > 0.5 ? formatDate(new Date().toISOString()) : '-'
    }
  } catch (error) {
    console.error('加载用户统计失败:', error)
  }
}

const loadRecentEmails = async () => {
  try {
    // 这里应该调用获取用户最近邮件的 API
    // 暂时使用空数组
    recentEmails.value = []
  } catch (error) {
    console.error('加载最近邮件失败:', error)
  }
}

const showMessage = (message: string, type: 'success' | 'error' | 'info' = 'info') => {
  // 这里应该使用全局消息组件
  console.log(`[${type.toUpperCase()}] ${message}`)
}

// Lifecycle
onMounted(async () => {
  await Promise.all([
    loadUserStats(),
    loadRecentEmails()
  ])
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

.user-info-section,
.webhook-section,
.stats-section,
.recent-emails-section {
  margin-bottom: var(--spacing-6);
}

.user-info-section h4,
.webhook-section h4,
.stats-section h4,
.recent-emails-section h4 {
  font-size: var(--font-size-lg);
  font-weight: 600;
  color: var(--gray-800);
  margin-bottom: var(--spacing-4);
}

.info-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
  gap: var(--spacing-4);
}

.info-item {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-1);
}

.info-item label {
  font-weight: 500;
  color: var(--gray-700);
  font-size: var(--font-size-sm);
}

.info-item span,
.info-item .webhook-url {
  color: var(--gray-800);
}

.info-item code {
  background: var(--gray-100);
  padding: var(--spacing-1) var(--spacing-2);
  border-radius: var(--border-radius-sm);
  font-family: 'Courier New', monospace;
  font-size: var(--font-size-sm);
}

.webhook-info {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-4);
  margin-bottom: var(--spacing-4);
}

.webhook-url {
  display: flex;
  align-items: center;
  gap: var(--spacing-2);
}

.url-text {
  word-break: break-all;
  flex: 1;
}

.webhook-test {
  padding-top: var(--spacing-4);
  border-top: 1px solid var(--gray-200);
}

.webhook-test small {
  display: block;
  margin-top: var(--spacing-2);
}

.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: var(--spacing-4);
}

.stat-item {
  text-align: center;
  padding: var(--spacing-4);
  background: var(--gray-100);
  border-radius: var(--border-radius);
}

.stat-number {
  font-size: var(--font-size-lg);
  font-weight: 600;
  color: var(--primary-color);
  margin-bottom: var(--spacing-1);
}

.stat-label {
  color: var(--gray-600);
  font-size: var(--font-size-sm);
}

.no-emails {
  text-align: center;
  padding: var(--spacing-6);
}

.emails-list {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-3);
}

.email-item {
  border: 1px solid var(--gray-200);
  border-radius: var(--border-radius);
  padding: var(--spacing-4);
  background: var(--gray-50);
}

.email-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: var(--spacing-2);
  gap: var(--spacing-3);
}

.email-sender {
  font-weight: 500;
  color: var(--gray-800);
  font-size: var(--font-size-sm);
}

.email-time {
  color: var(--gray-500);
  font-size: var(--font-size-sm);
  white-space: nowrap;
}

.email-subject {
  color: var(--primary-color);
  font-weight: 500;
  margin-bottom: var(--spacing-1);
  font-size: var(--font-size-sm);
}

.email-preview {
  color: var(--gray-600);
  font-size: var(--font-size-sm);
  line-height: 1.4;
}

.modal-actions {
  display: flex;
  justify-content: space-between;
  gap: var(--spacing-3);
  padding-top: var(--spacing-4);
  border-top: 1px solid var(--gray-200);
}

.ml-2 {
  margin-left: var(--spacing-2);
}

/* 响应式设计 */
@media (max-width: 768px) {
  .modal {
    padding: var(--spacing-2);
  }
  
  .modal-content {
    padding: var(--spacing-4);
  }
  
  .info-grid {
    grid-template-columns: 1fr;
  }
  
  .stats-grid {
    grid-template-columns: repeat(2, 1fr);
  }
  
  .webhook-url {
    flex-direction: column;
    align-items: flex-start;
  }
  
  .email-header {
    flex-direction: column;
    gap: var(--spacing-1);
  }
  
  .modal-actions {
    flex-direction: column;
  }
}
</style>