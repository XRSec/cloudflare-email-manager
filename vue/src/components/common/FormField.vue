<template>
  <div class="form-group">
    <label v-if="label" :for="fieldId">{{ label }}</label>
    <input v-if="type !== 'textarea'" :id="fieldId" :type="type" :value="modelValue" :placeholder="placeholder"
      :required="required" :disabled="disabled" :min="min" :max="max" :step="step" class="form-control"
      @input="$emit('update:modelValue', ($event.target as HTMLInputElement).value)" />
    <textarea v-else :id="fieldId" :value="modelValue" :placeholder="placeholder" :required="required"
      :disabled="disabled" :rows="rows" class="form-control"
      @input="$emit('update:modelValue', ($event.target as HTMLTextAreaElement).value)"></textarea>
    <div v-if="error" class="form-error">{{ error }}</div>
    <div v-if="help" class="form-help">{{ help }}</div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'

interface Props {
  modelValue: string | number
  label?: string
  type?: 'text' | 'email' | 'password' | 'number' | 'textarea' | 'tel' | 'url'
  placeholder?: string
  required?: boolean
  disabled?: boolean
  error?: string
  help?: string
  min?: number
  max?: number
  step?: number
  rows?: number
}

withDefaults(defineProps<Props>(), {
  type: 'text',
  required: false,
  disabled: false,
  rows: 3
})

defineEmits<{
  'update:modelValue': [value: string | number]
}>()

const fieldId = computed(() => `field-${Math.random().toString(36).substr(2, 9)}`)
</script>

<style scoped>
.form-group {
  margin-bottom: 15px;
}

.form-group label {
  display: block;
  margin-bottom: 5px;
  font-weight: bold;
  color: #555;
}

.form-control {
  width: 100%;
  padding: 10px;
  border: 1px solid #ddd;
  border-radius: 4px;
  font-size: 14px;
  transition: border-color 0.2s;
  box-sizing: border-box;
}

.form-control:focus {
  outline: none;
  border-color: #007bff;
  box-shadow: 0 0 0 2px rgba(0, 123, 255, 0.25);
}

.form-control:disabled {
  background-color: #f8f9fa;
  opacity: 0.6;
  cursor: not-allowed;
}

.form-control::placeholder {
  color: #6c757d;
}

.form-error {
  color: #dc3545;
  font-size: 12px;
  margin-top: 5px;
}

.form-help {
  color: #6c757d;
  font-size: 12px;
  margin-top: 5px;
}
</style>
