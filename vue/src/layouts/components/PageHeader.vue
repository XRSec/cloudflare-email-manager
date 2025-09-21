<template>
  <div class="page-header">
    <!-- 左侧：标题和搜索框 -->
    <div class="header-left">
      <h1>{{ title }}</h1>

      <!-- 搜索框 - 可选 -->
      <SearchBox v-if="showSearch" v-model="searchQuery" :placeholder="searchPlaceholder" :loading="searchLoading"
        :search-results="searchResults" @search="$emit('search', $event)" @clear="$emit('clear-search')"
        class="header-search" />
    </div>

    <!-- 右侧：操作按钮 -->
    <div class="header-actions">
      <!-- 标签页 - 可选 -->
      <div v-if="tabs && tabs.length > 0" class="view-tabs">
        <button v-for="tab in tabs" :key="tab.key" class="tab-btn" :class="{ active: tab.key === activeTab }"
          @click="$emit('tab-change', tab.key)">
          {{ tab.icon }} {{ tab.title }}
          <span v-if="tab.badge" class="badge" :class="tab.badgeClass">
            {{ tab.badge }}
          </span>
        </button>
      </div>

      <!-- 自定义操作按钮 -->
      <slot name="actions" />

      <!-- 默认刷新按钮 -->
      <button v-if="showRefresh" class="btn btn-secondary" @click="handleRefresh" :disabled="refreshing">
        {{ refreshing ? '🔄 刷新中...' : '🔄 刷新' }}
      </button>
    </div>
  </div>
</template>

<script setup lang="ts">
import SearchBox from './SearchBox.vue'

interface Tab {
  key: string
  title: string
  icon: string
  badge?: string | number
  badgeClass?: string
}

interface Props {
  // 页面标题
  title: string

  // 搜索相关
  showSearch?: boolean
  searchPlaceholder?: string
  searchLoading?: boolean
  searchResults?: any

  // 标签页
  tabs?: Tab[]
  activeTab?: string

  // 刷新按钮
  showRefresh?: boolean
  refreshing?: boolean
}

withDefaults(defineProps<Props>(), {
  showSearch: false,
  searchPlaceholder: '搜索...',
  searchLoading: false,
  searchResults: null,
  tabs: () => [],
  activeTab: '',
  showRefresh: true,
  refreshing: false
})

const emit = defineEmits<{
  'search': [query: string]
  'clear-search': []
  'tab-change': [tabKey: string]
  'refresh': []
  'update:search-query': [value: string]
}>()

// v-model 支持
const searchQuery = defineModel<string>('searchQuery', { default: '' })

// 调试工具函数
const debugLog = (...args: any[]) => {
  const isDebugMode = import.meta.env.DEV || import.meta.env.VITE_DEBUG === 'true'
  if (isDebugMode) {
    console.log(...args)
  }
}

// 处理刷新按钮点击
const handleRefresh = () => {
  debugLog('📡 PageHeader：刷新按钮被点击，触发 refresh 事件')
  emit('refresh')
}
</script>

<style scoped>
.page-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 20px;
  margin-bottom: 20px;
  flex-wrap: wrap;
}

.header-left {
  display: flex;
  align-items: center;
  gap: 20px;
  flex: 1;
  min-width: 0;
}

.header-left h1 {
  margin: 0;
  color: #2c3e50;
  font-size: 24px;
  font-weight: 600;
  white-space: nowrap;
}

.header-search {
  flex: 1;
  max-width: 400px;
  min-width: 250px;
}

.header-actions {
  display: flex;
  align-items: center;
  gap: 16px;
  flex-shrink: 0;
  flex-wrap: wrap;
}

.view-tabs {
  display: flex;
  background: #f8f9fa;
  border-radius: 8px;
  padding: 4px;
  gap: 4px;
}

.tab-btn {
  padding: 8px 16px;
  border: none;
  background: transparent;
  border-radius: 6px;
  cursor: pointer;
  font-size: 14px;
  font-weight: 500;
  color: #6c757d;
  transition: all 0.3s ease;
  display: flex;
  align-items: center;
  gap: 8px;
  white-space: nowrap;
}

.tab-btn:hover {
  background: #e9ecef;
  color: #495057;
}

.tab-btn.active {
  background: #007bff;
  color: white;
  box-shadow: 0 2px 4px rgba(0, 123, 255, 0.25);
}

.badge {
  padding: 2px 6px;
  border-radius: 10px;
  font-size: 11px;
  font-weight: 500;
  margin-left: 4px;
}

.badge-success {
  background: #28a745;
  color: white;
}

.badge-warning {
  background: #ffc107;
  color: #212529;
}

.badge-danger {
  background: #dc3545;
  color: white;
}

.badge-info {
  background: #17a2b8;
  color: white;
}

/* 响应式布局 */
@media (max-width: 1200px) {
  .header-left {
    flex-direction: column;
    align-items: flex-start;
    gap: 12px;
  }

  .header-search {
    width: 100%;
    max-width: none;
  }
}

@media (max-width: 768px) {
  .page-header {
    flex-direction: column;
    align-items: stretch;
  }

  .header-left {
    flex-direction: column;
    align-items: stretch;
  }

  .header-actions {
    justify-content: center;
    flex-wrap: wrap;
  }

  .view-tabs {
    justify-content: center;
    order: -1;
    margin-bottom: 12px;
  }

  .header-search {
    min-width: auto;
  }
}

@media (max-width: 480px) {
  .header-left h1 {
    font-size: 20px;
  }

  .tab-btn {
    padding: 6px 12px;
    font-size: 13px;
  }

  .view-tabs {
    width: 100%;
  }

  .header-actions {
    width: 100%;
  }
}
</style>
