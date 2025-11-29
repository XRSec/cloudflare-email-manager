<template>
  <div class="form-group">
    <label class="checkbox-label" :for="fieldId">
      <input :id="fieldId" type="checkbox" :checked="modelValue" :disabled="disabled" class="checkbox-input"
        @change="$emit('update:modelValue', ($event.target as HTMLInputElement).checked)" />
      <span class="checkbox-text">{{ label }}</span>
    </label>
    <div v-if="error" class="form-error">{{ error }}</div>
    <div v-if="help" class="form-help">{{ help }}</div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'

interface Props {
  modelValue: boolean
  label: string
  disabled?: boolean
  error?: string
  help?: string
}

withDefaults(defineProps<Props>(), {
  disabled: false
})

defineEmits<{
  'update:modelValue': [value: boolean]
}>()

const fieldId = computed(() => `checkbox-${Math.random().toString(36).substr(2, 9)}`)
</script>

<style scoped>
.form-group {
  margin-bottom: 15px;
}

.checkbox-label {
  display: flex;
  align-items: center;
  gap: 8px;
  cursor: pointer;
  font-weight: normal;
}

.checkbox-input {
  width: auto;
  margin: 0;
  cursor: pointer;
}

.checkbox-text {
  color: #555;
}

.checkbox-label:disabled {
  opacity: 0.6;
  cursor: not-allowed;
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
