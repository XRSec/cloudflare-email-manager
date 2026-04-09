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
  padding: 42px 24px;
  text-align: center;
  border-radius: 24px;
  border: 1px dashed rgba(47, 94, 138, 0.18);
  background: linear-gradient(180deg, rgba(255, 255, 255, 0.92), rgba(243, 247, 252, 0.96));
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

.error-overlay h3,
.empty-state h3 {
  margin: 0 0 10px;
  color: #17324a;
  font-size: 22px;
}

.loading-overlay p,
.error-overlay p,
.empty-state p {
  margin: 0;
  color: #5a6978;
  line-height: 1.6;
}

@media (max-width: 640px) {
  .loading-overlay,
  .error-overlay,
  .empty-state {
    padding: 32px 18px;
    border-radius: 20px;
  }

  .error-icon,
  .empty-icon {
    font-size: 40px;
  }
}
</style>
