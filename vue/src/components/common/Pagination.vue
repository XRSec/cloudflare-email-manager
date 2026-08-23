<template>
  <div v-if="pagination" class="pagination-container">
    <div class="pagination-info">
      显示 {{ (pagination.page - 1) * pagination.limit + 1 }} - {{ Math.min(pagination.page * pagination.limit,
        pagination.total) }} 条，共 {{ pagination.total }} 条
    </div>
    <div class="pagination">
      <label class="page-size-label">
        每页
        <select v-model.number="pageSize" class="page-size-selector" @change="handlePageSizeChange">
          <option v-for="size in pageSizeOptions" :key="size" :value="size">{{ size }} 条</option>
        </select>
      </label>
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
import { computed, ref, watch } from 'vue'

interface Pagination {
  page: number
  limit: number
  total: number
  totalPages: number
}

interface Props {
  pagination?: Pagination
  pageSizeOptions?: number[]
}

const props = withDefaults(defineProps<Props>(), {
  pageSizeOptions: () => [10, 20, 50, 100]
})

const emit = defineEmits<{
  changePage: [page: number]
  changePageSize: [pageSize: number]
}>()

const pageSize = ref(props.pagination?.limit || props.pageSizeOptions[0])
const pageSizeOptions = computed(() => props.pageSizeOptions)

watch(() => props.pagination?.limit, (limit) => {
  if (limit) pageSize.value = limit
})

const handlePageSizeChange = () => {
  emit('changePageSize', pageSize.value)
}
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

.page-size-label {
  display: flex;
  align-items: center;
  gap: 4px;
  white-space: nowrap;
}

.page-size-selector {
  padding: 3px 6px;
  border: 1px solid #ddd;
  border-radius: 4px;
  background: white;
}
</style>
