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
  gap: 18px;
  margin-bottom: 24px;
  padding: 0 0 16px;
  border-bottom: 1px solid rgba(15, 23, 42, 0.08);
}

.page-header h1 {
  margin: 0;
  color: #17324a;
  font-size: clamp(24px, 3vw, 30px);
  line-height: 1.08;
  letter-spacing: -0.03em;
}

.header-actions {
  display: flex;
  gap: 10px;
  flex-wrap: wrap;
}

@media (max-width: 640px) {
  .page-header {
    flex-direction: column;
    align-items: flex-start;
    gap: 14px;
    margin-bottom: 18px;
    padding-bottom: 14px;
  }

  .page-header h1 {
    font-size: 24px;
  }

  .header-actions {
    width: 100%;
  }
}
</style>
