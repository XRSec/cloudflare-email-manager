<template>
  <div class="data-table-container">
    <!-- 表格工具栏 -->
    <div class="table-toolbar" v-if="showToolbar">
      <div class="toolbar-left">
        <!-- 批量选择 -->
        <div class="batch-selection" v-if="selectable && selectedRows.length > 0">
          <span class="selection-info">已选择 {{ selectedRows.length }} 项</span>
          <button class="btn btn-sm btn-secondary" @click="clearSelection">
            清空选择
          </button>
          <slot name="batch-actions" :selectedRows="selectedRows" />
        </div>

        <!-- 左侧工具栏 -->
        <slot name="toolbar-left" />
      </div>

      <div class="toolbar-right">
        <!-- 搜索框 -->
        <div class="search-box" v-if="searchable">
          <input v-model="searchQuery" type="text" class="form-control form-control-sm" :placeholder="searchPlaceholder"
            @input="handleSearch" />
          <span class="search-icon">🔍</span>
        </div>

        <!-- 刷新按钮 -->
        <button v-if="refreshable" class="btn btn-sm btn-secondary" @click="handleRefresh" :disabled="loading">
          {{ loading ? '🔄 刷新中...' : '🔄 刷新' }}
        </button>

        <!-- 右侧工具栏 -->
        <slot name="toolbar-right" />
      </div>
    </div>

    <!-- 表格容器 -->
    <div class="table-wrapper" :class="{ loading: loading }">
      <!-- 加载覆盖层 -->
      <div class="table-loading-overlay" v-if="loading">
        <div class="loading-spinner"></div>
        <p>{{ loadingText }}</p>
      </div>

      <!-- 数据表格 -->
      <table class="data-table" :class="tableClass">
        <!-- 表头 -->
        <thead>
          <tr>
            <!-- 选择列 -->
            <th v-if="selectable" class="select-column">
              <input type="checkbox" :checked="isAllSelected" :indeterminate="isIndeterminate"
                @change="handleSelectAll" />
            </th>

            <!-- 数据列 -->
            <th v-for="column in columns" :key="column.key" :class="getColumnClass(column)"
              :style="getColumnStyle(column)" @click="handleSort(column)">
              <div class="table-header-content">
                <span>{{ column.title }}</span>
                <span v-if="column.sortable" class="sort-indicator">
                  <span class="sort-arrow sort-asc"
                    :class="{ active: sortField === column.key && sortOrder === 'asc' }">▲</span>
                  <span class="sort-arrow sort-desc"
                    :class="{ active: sortField === column.key && sortOrder === 'desc' }">▼</span>
                </span>
              </div>
            </th>

            <!-- 操作列 -->
            <th v-if="$slots.actions" class="actions-column">操作</th>
          </tr>
        </thead>

        <!-- 表体 -->
        <tbody>
          <!-- 空状态 -->
          <tr v-if="!loading && displayData.length === 0" class="empty-row">
            <td :colspan="totalColumns" class="empty-cell">
              <div class="empty-state">
                <div class="empty-icon">📝</div>
                <div class="empty-title">{{ emptyText }}</div>
                <div class="empty-description" v-if="emptyDescription">
                  {{ emptyDescription }}
                </div>
                <slot name="empty" />
              </div>
            </td>
          </tr>

          <!-- 数据行 -->
          <tr v-for="(row, index) in displayData" :key="getRowKey(row, index)" class="data-row"
            :class="getRowClass(row, index)" @click="handleRowClick(row, index)">
            <!-- 选择列 -->
            <td v-if="selectable" class="select-cell">
              <input type="checkbox" :checked="isRowSelected(row)" @change="handleRowSelect(row, $event)" @click.stop />
            </td>

            <!-- 数据列 -->
            <td v-for="column in columns" :key="column.key" :class="getCellClass(column, row)"
              :style="getColumnStyle(column)">
              <slot :name="`column-${column.key}`" :row="row" :column="column" :index="index"
                :value="getColumnValue(row, column)">
                {{ formatColumnValue(row, column) }}
              </slot>
            </td>

            <!-- 操作列 -->
            <td v-if="$slots.actions" class="actions-cell">
              <div class="actions-wrapper">
                <slot name="actions" :row="row" :index="index" />
              </div>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <!-- 分页器 -->
    <div class="table-pagination" v-if="pagination && !loading">
      <div class="pagination-info">
        <span>共 {{ total }} 条记录</span>
        <select v-model="currentPageSize" class="page-size-selector" @change="handlePageSizeChange">
          <option v-for="size in pageSizeOptions" :key="size" :value="size">
            {{ size }} 条/页
          </option>
        </select>
      </div>

      <div class="pagination-controls">
        <button class="btn btn-sm btn-secondary" :disabled="currentPage <= 1" @click="goToPage(1)">
          首页
        </button>
        <button class="btn btn-sm btn-secondary" :disabled="currentPage <= 1" @click="goToPage(currentPage - 1)">
          上一页
        </button>

        <span class="page-info">
          第 {{ currentPage }} / {{ totalPages }} 页
        </span>

        <button class="btn btn-sm btn-secondary" :disabled="currentPage >= totalPages"
          @click="goToPage(currentPage + 1)">
          下一页
        </button>
        <button class="btn btn-sm btn-secondary" :disabled="currentPage >= totalPages" @click="goToPage(totalPages)">
          末页
        </button>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch } from 'vue'

// 列定义接口
export interface TableColumn {
  key: string
  title: string
  width?: string | number
  minWidth?: string | number
  align?: 'left' | 'center' | 'right'
  sortable?: boolean
  formatter?: (value: any, row: any, column: TableColumn) => string
  className?: string | ((row: any) => string)
}

interface Props {
  // 数据
  data: any[]
  columns: TableColumn[]

  // 表格配置
  rowKey?: string | ((row: any) => string | number)
  loading?: boolean
  loadingText?: string
  tableClass?: string

  // 选择
  selectable?: boolean
  selectedRows?: any[]

  // 排序
  sortField?: string
  sortOrder?: 'asc' | 'desc'

  // 分页
  pagination?: boolean
  currentPage?: number
  pageSize?: number
  total?: number
  pageSizeOptions?: number[]

  // 搜索
  searchable?: boolean
  searchPlaceholder?: string
  searchFields?: string[]

  // 工具栏
  showToolbar?: boolean
  refreshable?: boolean

  // 空状态
  emptyText?: string
  emptyDescription?: string

  // 行配置
  rowClassName?: string | ((row: any, index: number) => string)
  clickableRow?: boolean
}

const props = withDefaults(defineProps<Props>(), {
  rowKey: 'id',
  loading: false,
  loadingText: '加载中...',
  selectable: false,
  selectedRows: () => [],
  pagination: true,
  currentPage: 1,
  pageSize: 20,
  total: 0,
  pageSizeOptions: () => [10, 20, 50, 100],
  searchable: true,
  searchPlaceholder: '搜索...',
  searchFields: () => [],
  showToolbar: true,
  refreshable: true,
  emptyText: '暂无数据',
  emptyDescription: '',
  clickableRow: false
})

const emit = defineEmits<{
  'update:selectedRows': [rows: any[]]
  'update:currentPage': [page: number]
  'update:pageSize': [size: number]
  'update:sortField': [field: string]
  'update:sortOrder': [order: 'asc' | 'desc']
  'search': [query: string]
  'refresh': []
  'row-click': [row: any, index: number]
  'selection-change': [selectedRows: any[]]
  'sort-change': [field: string, order: 'asc' | 'desc']
  'page-change': [page: number, pageSize: number]
}>()

// 响应式状态
const searchQuery = ref('')
const currentPageSize = ref(props.pageSize)
const internalSelectedRows = ref<any[]>(props.selectedRows)

// 计算属性
const totalColumns = computed(() => {
  let count = props.columns.length
  if (props.selectable) count++
  if (!!document.querySelector('.data-table-container .actions-column')) count++
  return count
})

const totalPages = computed(() => {
  return Math.ceil(props.total / currentPageSize.value)
})

// 搜索过滤数据
const filteredData = computed(() => {
  if (!searchQuery.value) return props.data

  const query = searchQuery.value.toLowerCase()
  const searchFields = props.searchFields.length > 0
    ? props.searchFields
    : props.columns.map(col => col.key)

  return props.data.filter(row => {
    return searchFields.some(field => {
      const value = getColumnValue(row, { key: field } as TableColumn)
      return String(value).toLowerCase().includes(query)
    })
  })
})

// 分页显示数据
const displayData = computed(() => {
  if (!props.pagination) return filteredData.value

  const start = (props.currentPage - 1) * currentPageSize.value
  const end = start + currentPageSize.value
  return filteredData.value.slice(start, end)
})

// 选择状态
const isAllSelected = computed(() => {
  return displayData.value.length > 0 &&
    displayData.value.every(row => isRowSelected(row))
})

const isIndeterminate = computed(() => {
  const selectedCount = displayData.value.filter(row => isRowSelected(row)).length
  return selectedCount > 0 && selectedCount < displayData.value.length
})

// 方法
const getRowKey = (row: any, index: number): string | number => {
  if (typeof props.rowKey === 'function') {
    return props.rowKey(row)
  }
  return row[props.rowKey] || index
}

const getColumnValue = (row: any, column: TableColumn): any => {
  const keys = column.key.split('.')
  let value = row
  for (const key of keys) {
    value = value?.[key]
  }
  return value
}

const formatColumnValue = (row: any, column: TableColumn): string => {
  const value = getColumnValue(row, column)

  if (column.formatter) {
    return column.formatter(value, row, column)
  }

  if (value === null || value === undefined) {
    return '-'
  }

  return String(value)
}

const getColumnClass = (column: TableColumn): string => {
  const classes = [`column-${column.key}`]

  if (column.align) {
    classes.push(`text-${column.align}`)
  }

  if (column.sortable) {
    classes.push('sortable')
  }

  return classes.join(' ')
}

const getColumnStyle = (column: TableColumn): Record<string, string> => {
  const style: Record<string, string> = {}

  if (column.width) {
    style.width = typeof column.width === 'number' ? `${column.width}px` : column.width
  }

  if (column.minWidth) {
    style.minWidth = typeof column.minWidth === 'number' ? `${column.minWidth}px` : column.minWidth
  }

  return style
}

const getCellClass = (column: TableColumn, row: any): string => {
  const classes = [`cell-${column.key}`]

  if (column.align) {
    classes.push(`text-${column.align}`)
  }

  if (column.className) {
    if (typeof column.className === 'function') {
      classes.push(column.className(row))
    } else {
      classes.push(column.className)
    }
  }

  return classes.join(' ')
}

const getRowClass = (row: any, index: number): string => {
  const classes = []

  if (props.clickableRow) {
    classes.push('clickable')
  }

  if (isRowSelected(row)) {
    classes.push('selected')
  }

  if (props.rowClassName) {
    if (typeof props.rowClassName === 'function') {
      classes.push(props.rowClassName(row, index))
    } else {
      classes.push(props.rowClassName)
    }
  }

  return classes.join(' ')
}

const isRowSelected = (row: any): boolean => {
  const rowKey = getRowKey(row, -1)
  return internalSelectedRows.value.some(selectedRow =>
    getRowKey(selectedRow, -1) === rowKey
  )
}

// 事件处理
const handleSearch = () => {
  emit('search', searchQuery.value)
}

const handleRefresh = () => {
  emit('refresh')
}

const handleSort = (column: TableColumn) => {
  if (!column.sortable) return

  let newOrder: 'asc' | 'desc' = 'asc'

  if (props.sortField === column.key) {
    newOrder = props.sortOrder === 'asc' ? 'desc' : 'asc'
  }

  emit('update:sortField', column.key)
  emit('update:sortOrder', newOrder)
  emit('sort-change', column.key, newOrder)
}

const handleRowClick = (row: any, index: number) => {
  if (props.clickableRow) {
    emit('row-click', row, index)
  }
}

const handleSelectAll = (event: Event) => {
  const target = event.target as HTMLInputElement
  if (target.checked) {
    // 选择当前页所有行
    const newSelected = [...internalSelectedRows.value]
    displayData.value.forEach(row => {
      if (!isRowSelected(row)) {
        newSelected.push(row)
      }
    })
    internalSelectedRows.value = newSelected
  } else {
    // 取消选择当前页所有行
    const currentPageKeys = displayData.value.map(row => getRowKey(row, -1))
    internalSelectedRows.value = internalSelectedRows.value.filter(row =>
      !currentPageKeys.includes(getRowKey(row, -1))
    )
  }

  emit('update:selectedRows', internalSelectedRows.value)
  emit('selection-change', internalSelectedRows.value)
}

const handleRowSelect = (row: any, event: Event) => {
  const target = event.target as HTMLInputElement
  const rowKey = getRowKey(row, -1)

  if (target.checked) {
    if (!isRowSelected(row)) {
      internalSelectedRows.value.push(row)
    }
  } else {
    internalSelectedRows.value = internalSelectedRows.value.filter(selectedRow =>
      getRowKey(selectedRow, -1) !== rowKey
    )
  }

  emit('update:selectedRows', internalSelectedRows.value)
  emit('selection-change', internalSelectedRows.value)
}

const clearSelection = () => {
  internalSelectedRows.value = []
  emit('update:selectedRows', [])
  emit('selection-change', [])
}

const handlePageSizeChange = () => {
  emit('update:pageSize', currentPageSize.value)
  emit('page-change', 1, currentPageSize.value)
}

const goToPage = (page: number) => {
  if (page >= 1 && page <= totalPages.value && page !== props.currentPage) {
    emit('update:currentPage', page)
    emit('page-change', page, currentPageSize.value)
  }
}

// 监听选中行变化
watch(() => props.selectedRows, (newValue) => {
  internalSelectedRows.value = newValue
}, { deep: true })

// 监听页面大小变化
watch(() => props.pageSize, (newValue) => {
  currentPageSize.value = newValue
})
</script>

<style scoped>
.data-table-container {
  background: white;
  border-radius: 10px;
  box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
  overflow: hidden;
}

/* 工具栏样式 */
.table-toolbar {
  padding: 16px 20px;
  border-bottom: 1px solid #e0e0e0;
  display: flex;
  justify-content: space-between;
  align-items: center;
  background: #f8f9fa;
}

.toolbar-left,
.toolbar-right {
  display: flex;
  align-items: center;
  gap: 12px;
}

.batch-selection {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 8px 16px;
  background: #e3f2fd;
  border-radius: 6px;
  border: 1px solid #2196f3;
}

.selection-info {
  font-size: 14px;
  color: #1976d2;
  font-weight: 500;
}

.search-box {
  position: relative;
}

.search-box input {
  padding-right: 35px;
  width: 250px;
}

.search-icon {
  position: absolute;
  right: 10px;
  top: 50%;
  transform: translateY(-50%);
  color: #6c757d;
  pointer-events: none;
}

/* 表格样式 */
.table-wrapper {
  position: relative;
  overflow-x: auto;
}

.table-wrapper.loading {
  pointer-events: none;
}

.table-loading-overlay {
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(255, 255, 255, 0.9);
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  z-index: 10;
}

.loading-spinner {
  width: 40px;
  height: 40px;
  border: 3px solid #f3f3f3;
  border-top: 3px solid #007bff;
  border-radius: 50%;
  animation: spin 1s linear infinite;
  margin-bottom: 16px;
}

.data-table {
  width: 100%;
  border-collapse: collapse;
}

.data-table th,
.data-table td {
  padding: 12px 16px;
  text-align: left;
  border-bottom: 1px solid #e0e0e0;
  vertical-align: middle;
}

.data-table th {
  background: #f8f9fa;
  font-weight: 600;
  color: #2c3e50;
  position: sticky;
  top: 0;
  z-index: 5;
}

.data-table .sortable {
  cursor: pointer;
  user-select: none;
}

.data-table .sortable:hover {
  background: #e9ecef;
}

.table-header-content {
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.sort-indicator {
  display: flex;
  flex-direction: column;
  margin-left: 8px;
}

.sort-arrow {
  font-size: 10px;
  line-height: 1;
  color: #dee2e6;
  transition: color 0.2s;
}

.sort-arrow.active {
  color: #007bff;
}

.data-row:hover {
  background: #f8f9fa;
}

.data-row.selected {
  background: #e3f2fd;
}

.data-row.clickable {
  cursor: pointer;
}

.select-column,
.select-cell {
  width: 50px;
  text-align: center;
}

.actions-column,
.actions-cell {
  width: 120px;
  text-align: center;
}

.actions-wrapper {
  display: flex;
  gap: 8px;
  justify-content: center;
}

/* 文本对齐 */
.text-left {
  text-align: left;
}

.text-center {
  text-align: center;
}

.text-right {
  text-align: right;
}

/* 空状态 */
.empty-cell {
  text-align: center;
  padding: 60px 20px;
}

.empty-state {
  color: #6c757d;
}

.empty-icon {
  font-size: 48px;
  margin-bottom: 16px;
}

.empty-title {
  font-size: 18px;
  font-weight: 500;
  margin-bottom: 8px;
  color: #2c3e50;
}

.empty-description {
  font-size: 14px;
}

/* 分页器 */
.table-pagination {
  padding: 16px 20px;
  border-top: 1px solid #e0e0e0;
  display: flex;
  justify-content: space-between;
  align-items: center;
  background: #f8f9fa;
}

.pagination-info {
  display: flex;
  align-items: center;
  gap: 16px;
  font-size: 14px;
  color: #6c757d;
}

.page-size-selector {
  padding: 4px 8px;
  border: 1px solid #ddd;
  border-radius: 4px;
  font-size: 14px;
}

.pagination-controls {
  display: flex;
  align-items: center;
  gap: 8px;
}

.page-info {
  margin: 0 16px;
  font-size: 14px;
  color: #2c3e50;
  font-weight: 500;
}

/* 响应式设计 */
@media (max-width: 768px) {
  .table-toolbar {
    flex-direction: column;
    gap: 12px;
    align-items: stretch;
  }

  .toolbar-left,
  .toolbar-right {
    justify-content: center;
  }

  .search-box input {
    width: 100%;
  }

  .table-pagination {
    flex-direction: column;
    gap: 12px;
    align-items: stretch;
  }

  .pagination-controls {
    justify-content: center;
  }

  .data-table th,
  .data-table td {
    padding: 8px 12px;
    font-size: 14px;
  }
}

@keyframes spin {
  0% {
    transform: rotate(0deg);
  }

  100% {
    transform: rotate(360deg);
  }
}
</style>
