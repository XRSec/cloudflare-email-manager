<template>
  <div class="page-header">
    <h1>{{ title }}</h1>
    <div class="header-actions">
      <slot name="actions">
        <button v-if="showRefresh" class="btn btn-secondary btn-sm" @click="$emit('refresh')" :disabled="loading">
          {{ loading ? '🔄 刷新中...' : '🔄 刷新' }}
        </button>
      </slot>
    </div>
  </div>
</template>

<script setup lang="ts">
interface Props {
  title: string
  showRefresh?: boolean
  loading?: boolean
}

defineProps<Props>()
defineEmits<{
  refresh: []
}>()
</script>

<style scoped>
.page-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 20px;
  padding-bottom: 15px;
  border-bottom: 1px solid #e0e0e0;
}

.page-header h1 {
  margin: 0;
  color: #333;
}

.header-actions {
  display: flex;
  gap: 10px;
}
</style>
