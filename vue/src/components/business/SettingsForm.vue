<template>
  <div class="settings-container">
    <form @submit.prevent="$emit('submit', formData)">
      <div v-for="section in sections" :key="section.title" class="settings-section">
        <h3>{{ section.title }}</h3>
        <div v-for="field in section.fields" :key="field.key">
          <FormField v-if="field.type !== 'checkbox'" v-model="formData[field.key]" :label="field.label"
            :type="field.type" :placeholder="field.placeholder" :required="field.required" :disabled="field.disabled"
            :min="field.min" :max="field.max" :step="field.step" :rows="field.rows" :error="field.error"
            :help="field.help" />
          <CheckboxField v-else v-model="formData[field.key]" :label="field.label" :disabled="field.disabled"
            :error="field.error" :help="field.help" />
        </div>
      </div>

      <div class="form-actions">
        <Button variant="secondary" @click="$emit('reset')">重置</Button>
        <Button type="submit" variant="primary" :disabled="saving">
          {{ saving ? '保存中...' : '保存设置' }}
        </Button>
      </div>
    </form>
  </div>
</template>

<script setup lang="ts">
import { ref, watch } from 'vue'
import { FormField, CheckboxField, Button } from '@/components/common'

interface FormFieldConfig {
  key: string
  label: string
  type: 'text' | 'email' | 'password' | 'number' | 'textarea' | 'checkbox'
  placeholder?: string
  required?: boolean
  disabled?: boolean
  min?: number
  max?: number
  step?: number
  rows?: number
  error?: string
  help?: string
}

interface SettingsSection {
  title: string
  fields: FormFieldConfig[]
}

interface Props {
  sections: SettingsSection[]
  initialData?: Record<string, any>
  saving?: boolean
}

const props = withDefaults(defineProps<Props>(), {
  saving: false
})

defineEmits<{
  submit: [data: Record<string, any>]
  reset: []
}>()

const formData = ref<Record<string, any>>({})

// 初始化表单数据
watch(() => props.initialData, (newData) => {
  if (newData) {
    formData.value = { ...newData }
  }
}, { immediate: true })

// 监听sections变化，初始化表单字段
watch(() => props.sections, (newSections) => {
  const data: Record<string, any> = {}
  newSections.forEach(section => {
    section.fields.forEach(field => {
      if (field.type === 'checkbox') {
        data[field.key] = false
      } else if (field.type === 'number') {
        data[field.key] = 0
      } else {
        data[field.key] = ''
      }
    })
  })
  formData.value = { ...data, ...props.initialData }
}, { immediate: true })
</script>

<style scoped>
.settings-container {
  background: white;
  border-radius: 8px;
  padding: 20px;
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
}

.settings-section {
  margin-bottom: 30px;
  padding-bottom: 20px;
  border-bottom: 1px solid #e0e0e0;
}

.settings-section:last-child {
  border-bottom: none;
  margin-bottom: 0;
}

.settings-section h3 {
  margin: 0 0 15px 0;
  color: #333;
  font-size: 18px;
}

.form-actions {
  display: flex;
  gap: 10px;
  justify-content: flex-end;
  margin-top: 20px;
  padding-top: 20px;
  border-top: 1px solid #e0e0e0;
}
</style>
