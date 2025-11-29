<template>
  <div class="tag-list-input">
    <label v-if="label" class="tag-list-label">
      {{ label }}
      <span v-if="required" class="required-mark">*</span>
    </label>

    <div v-if="help" class="tag-list-help">{{ help }}</div>

    <!-- 标签列表显示 -->
    <div v-if="tags.length > 0" class="tag-list">
      <div v-for="(tag, index) in tags" :key="index" class="tag-item">
        <span class="tag-text">{{ tag }}</span>
        <button type="button" class="tag-remove" @click="removeTag(index)" :disabled="disabled">
          <svg width="12" height="12" viewBox="0 0 12 12" fill="none" xmlns="http://www.w3.org/2000/svg">
            <path d="M9 3L3 9M3 3L9 9" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" />
          </svg>
        </button>
      </div>
    </div>

    <!-- 输入框和添加按钮 -->
    <div class="tag-input-group">
      <input v-model="inputValue" type="text" class="tag-input" :placeholder="placeholder" :disabled="disabled"
        @keydown.enter.prevent="addTag" @keydown.comma.prevent="addTag" @blur="handleBlur" />
      <button type="button" class="tag-add-btn" @click="addTag" :disabled="disabled || !canAdd">
        <svg width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg">
          <path d="M8 3V13M3 8H13" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" />
        </svg>
      </button>
    </div>

    <div v-if="error" class="tag-error">{{ error }}</div>
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
  allowDuplicate?: boolean // 是否允许重复标签
  validateFn?: (value: string) => boolean | string // 自定义验证函数，返回 true 或错误信息
}

const props = withDefaults(defineProps<Props>(), {
  placeholder: '输入后按回车或逗号添加',
  required: false,
  disabled: false,
  allowDuplicate: false
})

const emit = defineEmits<{
  'update:modelValue': [value: string[]]
}>()

const tags = ref<string[]>([...props.modelValue])
const inputValue = ref('')

// 是否可以添加
const canAdd = computed(() => {
  const trimmed = inputValue.value.trim()
  if (!trimmed) return false

  // 如果有自定义验证函数，使用它
  if (props.validateFn) {
    const result = props.validateFn(trimmed)
    if (result !== true) return false
  }

  // 检查是否已存在（如果不允许重复）
  if (!props.allowDuplicate && tags.value.includes(trimmed)) {
    return false
  }

  return true
})

// 添加标签
const addTag = () => {
  const trimmed = inputValue.value.trim()
  if (!trimmed) return

  // 如果有自定义验证函数，使用它
  if (props.validateFn) {
    const result = props.validateFn(trimmed)
    if (result !== true) {
      // 如果是错误信息，可以显示给用户（这里简化处理，只返回 false）
      return
    }
  }

  // 检查是否已存在（如果不允许重复）
  if (!props.allowDuplicate && tags.value.includes(trimmed)) {
    inputValue.value = ''
    return
  }

  // 添加标签
  tags.value.push(trimmed)
  inputValue.value = ''
  emit('update:modelValue', [...tags.value])
}

// 删除标签
const removeTag = (index: number) => {
  tags.value.splice(index, 1)
  emit('update:modelValue', [...tags.value])
}

// 处理失焦事件（如果输入框有值，自动添加）
const handleBlur = () => {
  if (inputValue.value.trim() && canAdd.value) {
    addTag()
  }
}

// 监听外部值变化
watch(() => props.modelValue, (newValue) => {
  if (JSON.stringify(newValue) !== JSON.stringify(tags.value)) {
    tags.value = [...newValue]
  }
}, { deep: true })
</script>

<style scoped>
.tag-list-input {
  margin-bottom: 16px;
}

.tag-list-label {
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

.tag-list-help {
  font-size: 12px;
  color: #909399;
  margin-bottom: 8px;
  line-height: 1.5;
}

.tag-list {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  margin-bottom: 8px;
  min-height: 28px;
  padding: 4px;
  background: #fafafa;
  border: 1px solid #e4e7ed;
  border-radius: 4px;
}

.tag-item {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 2px 6px;
  background: #ffffff;
  border: 1px solid #c0c4cc;
  border-radius: 3px;
  font-size: 12px;
  color: #606266;
  transition: all 0.2s;
  line-height: 1.5;
}

.tag-item:hover {
  background: #f5f7fa;
  border-color: #909399;
}

.tag-text {
  user-select: none;
  white-space: nowrap;
}

.tag-remove {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 14px;
  height: 14px;
  padding: 0;
  border: none;
  background: transparent;
  color: #909399;
  cursor: pointer;
  border-radius: 2px;
  transition: all 0.2s;
  flex-shrink: 0;
}

.tag-remove:hover:not(:disabled) {
  color: #f56c6c;
  background: rgba(245, 108, 108, 0.1);
}

.tag-remove:disabled {
  cursor: not-allowed;
  opacity: 0.5;
}

.tag-input-group {
  display: flex;
  gap: 6px;
  align-items: center;
}

.tag-input {
  flex: 1;
  height: 28px;
  padding: 0 8px;
  border: 1px solid #dcdfe6;
  border-radius: 3px;
  font-size: 13px;
  color: #606266;
  transition: border-color 0.2s;
  outline: none;
  background: #ffffff;
}

.tag-input:focus {
  border-color: #409eff;
  box-shadow: 0 0 0 1px rgba(64, 158, 255, 0.2);
}

.tag-input:disabled {
  background: #f5f7fa;
  cursor: not-allowed;
  color: #c0c4cc;
}

.tag-add-btn {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 28px;
  height: 28px;
  padding: 0;
  border: 1px solid #dcdfe6;
  background: #ffffff;
  color: #606266;
  border-radius: 3px;
  cursor: pointer;
  transition: all 0.2s;
  flex-shrink: 0;
}

.tag-add-btn:hover:not(:disabled) {
  border-color: #409eff;
  color: #409eff;
  background: #ecf5ff;
}

.tag-add-btn:disabled {
  cursor: not-allowed;
  opacity: 0.5;
  background: #f5f7fa;
}

.tag-error {
  margin-top: 4px;
  font-size: 12px;
  color: #f56c6c;
  line-height: 1.5;
}
</style>
