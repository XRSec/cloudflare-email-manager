<template>
  <div class="domain-list-input">
    <label v-if="label" class="domain-list-label">
      {{ label }}
      <span v-if="required" class="required-mark">*</span>
    </label>

    <div v-if="help" class="domain-list-help">{{ help }}</div>

    <!-- 域名列表显示 -->
    <div v-if="domains.length > 0" class="domain-tags">
      <div v-for="(domain, index) in domains" :key="index" class="domain-tag">
        <span class="domain-text">{{ domain }}</span>
        <button type="button" class="domain-remove" @click="removeDomain(index)" :disabled="disabled">
          <svg width="12" height="12" viewBox="0 0 12 12" fill="none" xmlns="http://www.w3.org/2000/svg">
            <path d="M9 3L3 9M3 3L9 9" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" />
          </svg>
        </button>
      </div>
    </div>

    <!-- 输入框和添加按钮 -->
    <div class="domain-input-group">
      <input v-model="inputValue" type="text" class="domain-input" :placeholder="placeholder" :disabled="disabled"
        @keydown.enter.prevent="addDomain" @blur="handleBlur" />
      <button type="button" class="domain-add-btn" @click="addDomain" :disabled="disabled || !canAdd">
        <svg width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg">
          <path d="M8 3V13M3 8H13" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" />
        </svg>
      </button>
    </div>

    <div v-if="error" class="domain-error">{{ error }}</div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch } from 'vue'

interface Props {
  modelValue: string[]
  label?: string
  placeholder?: string
  help?: string
  error?: string
  required?: boolean
  disabled?: boolean
}

const props = withDefaults(defineProps<Props>(), {
  placeholder: '输入域名后按回车或点击加号添加',
  required: false,
  disabled: false
})

const emit = defineEmits<{
  'update:modelValue': [value: string[]]
}>()

const domains = ref<string[]>([...props.modelValue])
const inputValue = ref('')

// 是否可以添加
const canAdd = computed(() => {
  const trimmed = inputValue.value.trim()
  if (!trimmed) return false

  // 验证域名格式（简单验证）
  const domainRegex = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/
  if (!domainRegex.test(trimmed)) return false

  // 检查是否已存在
  return !domains.value.includes(trimmed.toLowerCase())
})

// 添加域名
const addDomain = () => {
  const trimmed = inputValue.value.trim().toLowerCase()
  if (!trimmed) return

  // 验证域名格式
  const domainRegex = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/
  if (!domainRegex.test(trimmed)) {
    return
  }

  // 检查是否已存在
  if (domains.value.includes(trimmed)) {
    inputValue.value = ''
    return
  }

  // 添加域名
  domains.value.push(trimmed)
  inputValue.value = ''
  emit('update:modelValue', [...domains.value])
}

// 删除域名
const removeDomain = (index: number) => {
  domains.value.splice(index, 1)
  emit('update:modelValue', [...domains.value])
}

// 处理失焦事件（如果输入框有值，自动添加）
const handleBlur = () => {
  if (inputValue.value.trim() && canAdd.value) {
    addDomain()
  }
}

// 监听外部值变化
watch(() => props.modelValue, (newValue) => {
  if (JSON.stringify(newValue) !== JSON.stringify(domains.value)) {
    domains.value = [...newValue]
  }
}, { deep: true })
</script>

<style scoped>
.domain-list-input {
  margin-bottom: 16px;
}

.domain-list-label {
  display: block;
  font-size: 14px;
  font-weight: 500;
  color: #333;
  margin-bottom: 8px;
}

.required-mark {
  color: #f56c6c;
  margin-left: 4px;
}

.domain-list-help {
  font-size: 12px;
  color: #909399;
  margin-bottom: 8px;
  line-height: 1.5;
}

.domain-tags {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-bottom: 8px;
  min-height: 32px;
}

.domain-tag {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 4px 8px;
  background: #f0f2f5;
  border: 1px solid #dcdfe6;
  border-radius: 4px;
  font-size: 13px;
  color: #606266;
  transition: all 0.2s;
}

.domain-tag:hover {
  background: #e4e7ed;
  border-color: #c0c4cc;
}

.domain-text {
  user-select: none;
}

.domain-remove {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 16px;
  height: 16px;
  padding: 0;
  border: none;
  background: transparent;
  color: #909399;
  cursor: pointer;
  border-radius: 2px;
  transition: all 0.2s;
  flex-shrink: 0;
}

.domain-remove:hover:not(:disabled) {
  color: #f56c6c;
  background: rgba(245, 108, 108, 0.1);
}

.domain-remove:disabled {
  cursor: not-allowed;
  opacity: 0.5;
}

.domain-input-group {
  display: flex;
  gap: 8px;
  align-items: center;
}

.domain-input {
  flex: 1;
  height: 32px;
  padding: 0 12px;
  border: 1px solid #dcdfe6;
  border-radius: 4px;
  font-size: 14px;
  color: #606266;
  transition: border-color 0.2s;
  outline: none;
}

.domain-input:focus {
  border-color: #409eff;
}

.domain-input:disabled {
  background: #f5f7fa;
  cursor: not-allowed;
  color: #c0c4cc;
}

.domain-add-btn {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 32px;
  height: 32px;
  padding: 0;
  border: 1px solid #dcdfe6;
  background: #fff;
  color: #606266;
  border-radius: 4px;
  cursor: pointer;
  transition: all 0.2s;
  flex-shrink: 0;
}

.domain-add-btn:hover:not(:disabled) {
  border-color: #409eff;
  color: #409eff;
  background: #ecf5ff;
}

.domain-add-btn:disabled {
  cursor: not-allowed;
  opacity: 0.5;
  background: #f5f7fa;
}

.domain-error {
  margin-top: 4px;
  font-size: 12px;
  color: #f56c6c;
  line-height: 1.5;
}
</style>
