<template>
  <div v-if="isDebugMode" class="debug-info">
    <h3>🔍 调试信息</h3>
    <div class="debug-item">
      <strong>路由信息:</strong> {{ routeInfo?.description || '未知' }}
    </div>
    <div class="debug-item">
      <strong>是否支持统一管理:</strong> {{ isSupported ? '是' : '否' }}
    </div>
    <div class="debug-item">
      <strong>是否有权限:</strong> {{ hasAccess ? '是' : '否' }}
    </div>
    <div class="debug-item">
      <strong>API方法:</strong> {{ routeInfo?.apiMethod || '未知' }}
    </div>
    <div class="debug-item">
      <strong>缓存策略:</strong> {{ routeInfo?.cacheStrategy?.keyPrefix || '未知' }}
    </div>
    <div class="debug-item">
      <strong>最后更新:</strong> {{ lastUpdated ? new Date(lastUpdated).toLocaleString() : '从未' }}
    </div>
  </div>
</template>

<script setup lang="ts">
interface Props {
  isDebugMode: boolean
  routeInfo?: any
  isSupported?: boolean
  hasAccess?: boolean
  lastUpdated?: string | number | null | undefined
}

defineProps<Props>()
</script>

<style scoped>
.debug-info {
  background: #f8f9fa;
  border: 1px solid #dee2e6;
  border-radius: 8px;
  padding: 15px;
  margin-bottom: 20px;
}

.debug-info h3 {
  margin: 0 0 10px 0;
  color: #495057;
}

.debug-item {
  margin-bottom: 5px;
  font-size: 14px;
}
</style>
