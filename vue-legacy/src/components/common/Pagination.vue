<template>
  <div v-if="pagination" class="pagination-container">
    <div class="pagination-info">
      显示 {{ (pagination.page - 1) * pagination.limit + 1 }} - {{ Math.min(pagination.page * pagination.limit,
        pagination.total) }} 条，共 {{ pagination.total }} 条
    </div>
    <div class="pagination">
      <button class="btn btn-sm" :disabled="pagination.page <= 1" @click="$emit('changePage', pagination.page - 1)">
        上一页
      </button>
      <span class="pagination-current">{{ pagination.page }} / {{ pagination.totalPages }}</span>
      <button class="btn btn-sm" :disabled="pagination.page >= pagination.totalPages"
        @click="$emit('changePage', pagination.page + 1)">
        下一页
      </button>
    </div>
  </div>
</template>

<script setup lang="ts">
interface Pagination {
  page: number
  limit: number
  total: number
  totalPages: number
}

interface Props {
  pagination?: Pagination
}

defineProps<Props>()
defineEmits<{
  changePage: [page: number]
}>()
</script>

<style scoped>
.pagination-container {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-top: 20px;
  padding-top: 15px;
  border-top: 1px solid #e0e0e0;
}

.pagination-info {
  color: #666;
  font-size: 14px;
}

.pagination {
  display: flex;
  align-items: center;
  gap: 10px;
}

.pagination-current {
  padding: 0 10px;
  font-weight: bold;
}
</style>
