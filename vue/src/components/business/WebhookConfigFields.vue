<template>
  <div class="webhook-config-fields" :class="{ 'layout-horizontal': layout === 'horizontal' }">
    <div class="webhook-field" :class="{ 'webhook-url-field': layout === 'horizontal' }">
      <FormField :model-value="localWebhookData.url" label="Webhook URL" type="url" :placeholder="urlPlaceholder"
        :required="required" :error="error" :help="layout === 'vertical' ? urlHelp : undefined"
        @update:model-value="updateField('url', $event)" />
    </div>
    <div class="webhook-field" :class="{ 'webhook-type-field': layout === 'horizontal' }">
      <div class="form-group">
        <label :for="fieldId + '_type'">Webhook 类型</label>
        <select :id="fieldId + '_type'" :value="localWebhookData.type"
          @change="updateField('type', ($event.target as HTMLSelectElement).value)" class="form-control">
          <option value="custom">Custom</option>
          <option value="dingtalk">钉钉 (DingTalk)</option>
          <option value="feishu">飞书 (Feishu)</option>
          <option value="bark">Bark</option>
        </select>
      </div>
    </div>
    <div class="webhook-field" :class="{ 'webhook-secret-field': layout === 'horizontal' }">
      <FormField :model-value="localWebhookData.secret" label="Webhook 密钥（可选）" type="password" placeholder="留空则不使用密钥"
        :help="layout === 'vertical' ? '用于验证 webhook 请求的安全性' : undefined"
        @update:model-value="updateField('secret', $event)" />
    </div>
    <div v-if="urlHelp && layout === 'vertical'" class="form-help">{{ urlHelp }}</div>
    <div v-if="urlHelp && layout === 'horizontal'" class="form-help-horizontal">{{ urlHelp }}</div>
  </div>
  <!-- 自定义消息模板单独显示，不跟其他字段挤在一起 -->
  <div class="webhook-message-field-full">
    <FormField :model-value="(localWebhookData.custom_message || '') as string" label="自定义消息模板（可选）" type="textarea"
      placeholder="支持变量：{{from}}, {{to}}, {{subject}}, {{content}}, {{received_at}}, {{attachment_count}}"
      :help="customMessageHelp" :rows="3" @update:model-value="updateField('custom_message', $event)" />
  </div>
  <!-- 关键字验证提示 -->
  <div class="webhook-keyword-hint">
    <div class="hint-icon">💡</div>
    <div class="hint-content">
      <div class="hint-title">关键字验证提示</div>
      <div class="hint-text">如果需要关键字验证，可选字段：接收时间、附件信息、发件人、收件人、主题、内容预览（任选其一）</div>
    </div>
  </div>
</template>

<script setup lang="ts">
import {computed, ref, watch} from 'vue'
import {FormField} from '@/components'

interface WebhookData {
  url: string
  type?: 'custom' | 'dingtalk' | 'feishu' | 'bark'
  secret: string
  custom_message?: string
}

interface Props {
  modelValue: WebhookData
  urlPlaceholder?: string
  urlHelp?: string
  required?: boolean
  error?: string
  layout?: 'vertical' | 'horizontal'
}

const props = withDefaults(defineProps<Props>(), {
  urlPlaceholder: 'https://example.com/webhook',
  urlHelp: '',
  required: false,
  layout: 'vertical'
})

const emit = defineEmits<{
  'update:modelValue': [value: WebhookData]
}>()

// 使用本地状态来管理数据
const localWebhookData = ref<WebhookData>({
  url: props.modelValue.url || '',
  type: props.modelValue.type || 'custom',
  secret: props.modelValue.secret || '',
  custom_message: props.modelValue.custom_message || ''
})

// 标记是否正在更新（避免循环更新）
const isUpdating = ref(false)

// 监听 props 变化，同步到本地状态（只在非更新状态时同步）
watch(() => props.modelValue, (newValue) => {
  if (!isUpdating.value) {
    localWebhookData.value = {
      url: newValue.url || '',
      type: newValue.type || 'custom',
      secret: newValue.secret || '',
      custom_message: newValue.custom_message || ''
    }
  }
}, { deep: true })

// 更新字段的方法
const updateField = (field: keyof WebhookData, value: any) => {
  isUpdating.value = true

  const updated = {
    ...localWebhookData.value,
    [field]: value
  }

  localWebhookData.value = updated
  emit('update:modelValue', updated)

  // 延迟重置标记，确保父组件有时间处理更新
  setTimeout(() => {
    isUpdating.value = false
  }, 0)
}

const fieldId = computed(() => `webhook-${Math.random().toString(36).substr(2, 9)}`)

// 自定义消息模板的帮助文本
const customMessageHelp = computed(() => {
  return '自定义发送到 webhook 的消息内容。支持变量：{{from}}（发件人）、{{to}}（收件人）、{{subject}}（主题）、{{content}}（内容）、{{received_at}}（接收时间）、{{attachment_count}}（附件数量）。留空则使用默认格式。'
})
</script>

<style scoped>
.webhook-config-fields {
  display: flex;
  flex-direction: column;
  gap: 0;
}

.webhook-config-fields.layout-horizontal {
  flex-direction: row;
  gap: 16px;
  align-items: flex-start;
  flex-wrap: wrap;
}

.webhook-field {
  flex: 1;
  min-width: 0;
}

.layout-horizontal .webhook-url-field {
  flex: 2;
}

.layout-horizontal .webhook-type-field {
  flex: 1;
  min-width: 150px;
}

.layout-horizontal .webhook-secret-field {
  flex: 1;
  min-width: 150px;
}

/* 自定义消息模板单独显示，占满整行 */
.webhook-message-field-full {
  width: 100%;
  margin-top: 16px;
  clear: both;
}

.webhook-config-fields .form-group {
  margin-bottom: 15px;
}

.layout-horizontal .form-group {
  margin-bottom: 0;
}

.webhook-config-fields .form-group label {
  display: block;
  margin-bottom: 5px;
  font-weight: 500;
  color: #555;
  font-size: 14px;
}

.webhook-config-fields select.form-control {
  width: 100%;
  padding: 10px;
  border: 1px solid #ddd;
  border-radius: 4px;
  font-size: 14px;
  background: white;
  transition: border-color 0.2s;
  box-sizing: border-box;
}

.webhook-config-fields select.form-control:focus {
  outline: none;
  border-color: #007bff;
  box-shadow: 0 0 0 2px rgba(0, 123, 255, 0.25);
}

.form-help {
  font-size: 12px;
  color: #6c757d;
  margin-top: 5px;
}

.form-help-horizontal {
  font-size: 12px;
  color: #6c757d;
  margin-top: 8px;
  width: 100%;
  flex-basis: 100%;
}

/* 关键字验证提示样式 */
.webhook-keyword-hint {
  display: flex;
  align-items: flex-start;
  gap: 12px;
  margin-top: 16px;
  padding: 12px;
  background-color: #f0f7ff;
  border: 1px solid #b3d9ff;
  border-radius: 6px;
  font-size: 13px;
}

.hint-icon {
  font-size: 18px;
  flex-shrink: 0;
  margin-top: 2px;
}

.hint-content {
  flex: 1;
}

.hint-title {
  font-weight: 600;
  color: #0066cc;
  margin-bottom: 4px;
}

.hint-text {
  color: #555;
  line-height: 1.5;
}

/* 响应式布局：小屏幕时改为垂直排列 */
@media (max-width: 768px) {
  .webhook-config-fields.layout-horizontal {
    flex-direction: column;
    gap: 0;
  }

  .layout-horizontal .webhook-field {
    width: 100%;
    margin-bottom: 15px;
  }

  .layout-horizontal .webhook-field:last-child {
    margin-bottom: 0;
  }

  .layout-horizontal .form-group {
    margin-bottom: 15px;
  }
}
</style>
