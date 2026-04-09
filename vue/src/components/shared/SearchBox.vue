<template>
  <div class="search-container">
    <div class="search-input-wrapper">
      <input v-model="searchQuery" type="text" class="search-input" :placeholder="placeholder"
        @keyup.enter="handleSearch" @input="handleInput" />
      <button class="search-btn" @click="handleSearch" :disabled="loading">
        <span v-if="!loading">🔍</span>
        <span v-else class="loading-spinner-sm">⟳</span>
      </button>
      <button v-if="searchQuery && showClear" class="clear-btn" @click="clearSearch" title="清除搜索">
        ✕
      </button>
    </div>

    <!-- 搜索结果统计 -->
    <div class="search-stats" v-if="searchQuery && showStats && searchResults">
      找到 {{ searchResults.total || 0 }} 条结果
      <span v-if="searchResults.time" class="search-time">
        ({{ searchResults.time }}ms)
      </span>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch } from 'vue'

interface Props {
  // 基础配置
  placeholder?: string
  loading?: boolean
  showClear?: boolean
  showStats?: boolean

  // 防抖配置
  debounceTime?: number
  minLength?: number

  // 初始值
  modelValue?: string

  // 搜索结果
  searchResults?: {
    total?: number
    time?: number
    items?: any[]
  } | null
}

const props = withDefaults(defineProps<Props>(), {
  placeholder: '搜索...',
  loading: false,
  showClear: true,
  showStats: true,
  debounceTime: 300,
  minLength: 0,
  modelValue: '',
  searchResults: null
})

const emit = defineEmits<{
  'update:modelValue': [value: string]
  'search': [query: string]
  'clear': []
  'input': [value: string]
}>()

// 响应式数据
const searchQuery = ref(props.modelValue)
let debounceTimer: ReturnType<typeof setTimeout> | null = null

// 计算属性
const shouldSearch = computed(() => {
  return searchQuery.value.length >= props.minLength
})

// 监听外部值变化
watch(() => props.modelValue, (newValue) => {
  searchQuery.value = newValue
})

// 监听内部值变化
watch(searchQuery, (newValue) => {
  emit('update:modelValue', newValue)
})

// 方法
const handleSearch = () => {
  if (shouldSearch.value || searchQuery.value === '') {
    emit('search', searchQuery.value)
  }
}

const handleInput = () => {
  emit('input', searchQuery.value)

  // 防抖搜索
  if (debounceTimer) {
    clearTimeout(debounceTimer)
  }

  debounceTimer = setTimeout(() => {
    if (shouldSearch.value) {
      handleSearch()
    }
  }, props.debounceTime)
}

const clearSearch = () => {
  searchQuery.value = ''
  emit('clear')
  emit('search', '')
}
</script>

<style scoped>
/* 使用后台页面中的通用样式类 */
</style>
