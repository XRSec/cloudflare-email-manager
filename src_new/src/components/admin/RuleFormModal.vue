<template>
  <Teleport to="body">
    <div class="modal" @click.self="$emit('close')">
      <div class="modal-content">
        <!-- 模态框头部 -->
        <div class="modal-header">
          <h3 class="modal-title">
            {{ isEditing ? '编辑转发规则' : '新建转发规则' }}
          </h3>
          <button
            class="modal-close"
            @click="$emit('close')"
          >
            ×
          </button>
        </div>

        <!-- 表单内容 -->
        <form @submit.prevent="handleSubmit">
          <!-- 基本信息 -->
          <div class="form-section">
            <h4 class="section-title">基本信息</h4>
            
            <div class="form-group">
              <label for="ruleName" class="form-label">规则名称 *</label>
              <input
                id="ruleName"
                v-model="formData.rule_name"
                type="text"
                class="form-control"
                placeholder="输入规则名称"
                required
                :disabled="saving"
              >
            </div>

            <div class="form-group">
              <label for="webhookType" class="form-label">Webhook 类型 *</label>
              <select
                id="webhookType"
                v-model="formData.webhook_type"
                class="form-control"
                required
                :disabled="saving"
              >
                <option value="dingtalk">钉钉</option>
                <option value="feishu">飞书</option>
                <option value="custom">自定义</option>
              </select>
            </div>

            <div class="form-group">
              <label for="webhookUrl" class="form-label">Webhook URL *</label>
              <input
                id="webhookUrl"
                v-model="formData.webhook_url"
                type="url"
                class="form-control"
                placeholder="https://oapi.dingtalk.com/robot/send?access_token=..."
                required
                :disabled="saving"
              >
              <small class="form-text text-muted">
                {{ getWebhookUrlHint(formData.webhook_type || 'custom') }}
              </small>
            </div>

            <div class="form-group">
              <label for="webhookSecret" class="form-label">Webhook 密钥</label>
              <input
                id="webhookSecret"
                v-model="formData.webhook_secret"
                type="password"
                class="form-control"
                :placeholder="isEditing ? '留空表示不修改' : '可选，用于签名验证'"
                :disabled="saving"
              >
              <small class="form-text text-muted">
                用于验证 Webhook 请求的安全性
              </small>
            </div>
          </div>

          <!-- 过滤条件 -->
          <div class="form-section">
            <h4 class="section-title">过滤条件</h4>
            <p class="section-description">
              设置邮件过滤条件，只有满足条件的邮件才会触发转发。留空表示不过滤。
            </p>

            <div class="form-group">
              <label for="senderFilter" class="form-label">发件人过滤</label>
              <input
                id="senderFilter"
                v-model="formData.sender_filter"
                type="text"
                class="form-control"
                placeholder="example@domain.com 或 @domain.com"
                :disabled="saving"
              >
              <small class="form-text text-muted">
                支持完整邮箱地址或域名匹配
              </small>
            </div>

            <div class="form-group">
              <label for="recipientFilter" class="form-label">收件人过滤</label>
              <input
                id="recipientFilter"
                v-model="formData.recipient_filter"
                type="text"
                class="form-control"
                placeholder="user@yourdomain.com 或 @yourdomain.com"
                :disabled="saving"
              >
              <small class="form-text text-muted">
                支持完整邮箱地址或域名匹配
              </small>
            </div>

            <div class="form-group">
              <label for="keywordFilter" class="form-label">关键字过滤</label>
              <input
                id="keywordFilter"
                v-model="formData.keyword_filter"
                type="text"
                class="form-control"
                placeholder="重要,紧急,通知"
                :disabled="saving"
              >
              <small class="form-text text-muted">
                多个关键字用逗号分隔，匹配邮件主题或内容
              </small>
            </div>
          </div>

          <!-- 规则状态 -->
          <div class="form-section">
            <h4 class="section-title">规则状态</h4>
            
            <div class="form-group">
              <label class="checkbox-label">
                <input
                  v-model="formData.enabled"
                  type="checkbox"
                  class="checkbox-input"
                  :disabled="saving"
                >
                <span class="checkbox-text">启用此规则</span>
              </label>
              <small class="form-text text-muted">
                只有启用的规则才会执行邮件转发
              </small>
            </div>
          </div>

          <!-- 错误信息 -->
          <div v-if="error" class="alert alert-danger">
            {{ error }}
          </div>

          <!-- 操作按钮 -->
          <div class="form-actions">
            <button
              type="submit"
              class="btn btn-primary"
              :disabled="saving || !isFormValid"
            >
              <span v-if="saving">{{ isEditing ? '更新中...' : '创建中...' }}</span>
              <span v-else">{{ isEditing ? '💾 更新规则' : '✅ 创建规则' }}</span>
            </button>
            <button
              type="button"
              class="btn btn-light"
              @click="$emit('close')"
              :disabled="saving"
            >
              取消
            </button>
          </div>
        </form>
      </div>
    </div>
  </Teleport>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import type { ForwardRule } from '@/types'

// Props
interface Props {
  rule?: ForwardRule | null
}

const props = defineProps<Props>()

// Emits
const emit = defineEmits<{
  close: []
  saved: []
}>()

// State
const saving = ref(false)
const error = ref<string | null>(null)

const formData = ref<Partial<ForwardRule>>({
  rule_name: '',
  webhook_type: 'dingtalk',
  webhook_url: '',
  webhook_secret: '',
  sender_filter: '',
  recipient_filter: '',
  keyword_filter: '',
  enabled: true
})

// Computed
const isEditing = computed(() => !!props.rule)

const isFormValid = computed(() => {
  return formData.value.rule_name?.trim() &&
         formData.value.webhook_url?.trim() &&
         formData.value.webhook_type
})

// Methods
const getWebhookUrlHint = (type: string): string => {
  const hints: Record<string, string> = {
    dingtalk: '钉钉机器人的 Webhook 地址',
    feishu: '飞书机器人的 Webhook 地址',
    custom: '自定义的 HTTP POST 接口地址'
  }
  return hints[type] || '请输入有效的 HTTP/HTTPS 地址'
}

const handleSubmit = async () => {
  error.value = null
  saving.value = true

  try {
    // 验证表单
    if (!isFormValid.value) {
      throw new Error('请填写所有必填字段')
    }

    // 这里应该调用相应的 API 来创建或更新规则
    await new Promise(resolve => setTimeout(resolve, 2000))

    // 模拟成功
    emit('saved')
    showMessage(isEditing.value ? '规则更新成功' : '规则创建成功', 'success')
  } catch (err: any) {
    error.value = err.message || (isEditing.value ? '更新规则失败' : '创建规则失败')
  } finally {
    saving.value = false
  }
}

const loadRuleData = () => {
  if (props.rule) {
    formData.value = {
      rule_name: props.rule.rule_name,
      webhook_type: props.rule.webhook_type,
      webhook_url: props.rule.webhook_url,
      webhook_secret: '', // 不显示现有密钥
      sender_filter: props.rule.sender_filter || '',
      recipient_filter: props.rule.recipient_filter || '',
      keyword_filter: props.rule.keyword_filter || '',
      enabled: !!props.rule.enabled
    }
  }
}

const showMessage = (message: string, type: 'success' | 'error' | 'info' = 'info') => {
  // 这里应该使用全局消息组件
  console.log(`[${type.toUpperCase()}] ${message}`)
}

// Lifecycle
onMounted(() => {
  loadRuleData()
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
  max-width: 600px;
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

.form-section {
  margin-bottom: var(--spacing-6);
  padding-bottom: var(--spacing-4);
  border-bottom: 1px solid var(--gray-200);
}

.form-section:last-of-type {
  border-bottom: none;
  margin-bottom: var(--spacing-4);
}

.section-title {
  font-size: var(--font-size-lg);
  font-weight: 600;
  color: var(--gray-800);
  margin-bottom: var(--spacing-3);
}

.section-description {
  color: var(--gray-600);
  font-size: var(--font-size-sm);
  margin-bottom: var(--spacing-4);
  line-height: 1.5;
}

.form-group {
  margin-bottom: var(--spacing-4);
}

.form-label {
  display: block;
  margin-bottom: var(--spacing-2);
  font-weight: 500;
  color: var(--gray-700);
  font-size: var(--font-size-sm);
}

.form-control {
  width: 100%;
  padding: var(--spacing-3);
  border: 2px solid var(--gray-200);
  border-radius: var(--border-radius);
  font-size: var(--font-size-base);
  transition: var(--transition);
}

.form-control:focus {
  outline: none;
  border-color: var(--primary-color);
  box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
}

.form-control:disabled {
  background: var(--gray-100);
  color: var(--gray-500);
  cursor: not-allowed;
}

.form-text {
  font-size: var(--font-size-sm);
  margin-top: var(--spacing-1);
}

.checkbox-label {
  display: flex;
  align-items: center;
  gap: var(--spacing-2);
  cursor: pointer;
  font-weight: 500;
  color: var(--gray-700);
}

.checkbox-input {
  width: 18px;
  height: 18px;
  margin: 0;
  cursor: pointer;
}

.checkbox-text {
  user-select: none;
}

.alert {
  padding: var(--spacing-3);
  border-radius: var(--border-radius);
  margin-bottom: var(--spacing-4);
}

.alert-danger {
  background: linear-gradient(135deg, var(--danger-color) 0%, var(--danger-light) 100%);
  color: var(--white);
  border: none;
}

.form-actions {
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
  
  .form-actions {
    flex-direction: column-reverse;
  }
  
  .form-actions .btn {
    width: 100%;
  }
}
</style>