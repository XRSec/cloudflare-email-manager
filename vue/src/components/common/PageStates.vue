<template>
  <!-- 加载状态 -->
  <div v-if="loading" class="loading-overlay">
    <div class="loading-spinner"></div>
    <p>{{ loadingText }}</p>
  </div>

  <!-- 错误状态 -->
  <div v-else-if="error" class="error-overlay">
    <div class="error-icon">❌</div>
    <h3>加载失败</h3>
    <p>{{ error }}</p>
    <button class="btn btn-primary" @click="$emit('retry')">重试</button>
  </div>

  <!-- 空状态 -->
  <div v-else-if="isEmpty" class="empty-state">
    <div class="empty-icon">{{ emptyIcon }}</div>
    <h3>{{ emptyTitle }}</h3>
    <p>{{ emptyDescription }}</p>
    <slot name="empty-actions"></slot>
  </div>
</template>

<script setup lang="ts">
interface Props {
  loading: boolean
  error?: string | null
  isEmpty?: boolean
  loadingText?: string
  emptyIcon?: string
  emptyTitle?: string
  emptyDescription?: string
}

withDefaults(defineProps<Props>(), {
  loadingText: '正在加载数据...',
  emptyIcon: '📄',
  emptyTitle: '暂无数据',
  emptyDescription: '当前没有数据'
})

defineEmits<{
  retry: []
}>()
</script>

<style scoped>
.loading-overlay,
.error-overlay,
.empty-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 40px;
  text-align: center;
}

.loading-spinner {
  width: 32px;
  height: 32px;
  border: 3px solid #f3f3f3;
  border-top: 3px solid #007bff;
  border-radius: 50%;
  animation: spin 1s linear infinite;
  margin-bottom: 15px;
}

@keyframes spin {
  0% {
    transform: rotate(0deg);
  }

  100% {
    transform: rotate(360deg);
  }
}

.error-icon,
.empty-icon {
  font-size: 48px;
  margin-bottom: 15px;
}
</style>
