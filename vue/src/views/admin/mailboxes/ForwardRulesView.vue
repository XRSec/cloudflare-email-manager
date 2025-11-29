<template>
  <div class="page-content">
    <!-- 统一页面头部 -->
    <PageHeader :title="`${pageIcon} ${pageTitle}`" :show-search="true" search-placeholder="搜索规则名称或描述..."
      :search-loading="loading" :search-results="searchResults" :show-refresh="false"
      v-model:search-query="searchKeyword" @search="handleSearch" @clear-search="handleClearSearch">
      <template #actions>
        <button class="btn btn-primary" @click="createRule">
          ➕ 新建规则
        </button>
      </template>
    </PageHeader>

    <!-- 加载状态 -->
    <LoadingOverlay v-if="loading" :show="true" text="加载转发规则..." type="local" />

    <!-- 错误状态 -->
    <div v-else-if="error" class="error-state">
      <div class="error-icon">❌</div>
      <p>{{ error }}</p>
      <button class="btn btn-primary" @click="refreshData">重试</button>
    </div>

    <!-- 空状态 -->
    <div v-else-if="!hasRules" class="empty-state">
      <div class="empty-icon">🔄</div>
      <p>{{ searchKeyword ? '没有找到匹配的规则' : '暂无转发规则' }}</p>
      <button v-if="searchKeyword" class="btn btn-secondary" @click="handleClearSearch">
        清除搜索
      </button>
      <button v-else class="btn btn-primary" @click="createRule">
        创建第一个规则
      </button>
    </div>

    <!-- 规则列表 -->
    <div v-else class="rules-list">
      <div v-for="rule in rules" :key="rule.id" class="rule-item">
        <div class="rule-info">
          <div class="rule-name">{{ rule.rule_name }}</div>
          <div class="rule-description">{{ rule.description || rule.webhook_url }}</div>
          <div class="rule-details">
            <span class="rule-status" :class="rule.enabled ? 'status-enabled' : 'status-disabled'">
              {{ rule.enabled ? '已启用' : '已禁用' }}
            </span>
          </div>
        </div>
        <div class="rule-actions">
          <button class="btn btn-sm btn-secondary" @click="editRule(rule)">编辑</button>
          <button class="btn btn-sm" :class="rule.enabled ? 'btn-warning' : 'btn-success'" @click="toggleRule(rule)">
            {{ rule.enabled ? '禁用' : '启用' }}
          </button>
          <button class="btn btn-sm btn-danger" @click="deleteRule(rule)">删除</button>
        </div>
      </div>

      <!-- 分页组件 -->
      <Pagination v-if="pagination" :pagination="pagination" @change-page="changePage" />
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { usePaginatedPageData } from '@/composables/useUnifiedPageData'
import { useSystemStore } from '@/composables/system'
import { usePageRefreshRegistry, useGlobalRefreshEventListener } from '@/composables/globalRefreshManager'
import { apiService } from '@/composables/api'
import LoadingOverlay from '@/views/shared/components/AppLoadingSpinner.vue'
import { PageHeader, Pagination } from '@/components'

const systemStore = useSystemStore()

// 使用统一页面数据管理（带缓存）
const {
  data,
  loading,
  error,
  lastUpdated,
  routeInfo,
  isSupported,
  hasAccess,
  pagination,
  refreshData,
  changePage
} = usePaginatedPageData()

// 页面信息
const pageTitle = computed(() => '转发管理')
const pageIcon = computed(() => '🔄')

// 搜索相关
const searchKeyword = ref('')
const searchResults = ref<any>(null)

// 提取数据
const rules = computed(() => {
  const items = data.value?.data?.items || []
  if (searchKeyword.value) {
    const keyword = searchKeyword.value.toLowerCase()
    return items.filter((rule: any) => {
      const name = (rule.rule_name || '').toLowerCase()
      const description = (rule.description || '').toLowerCase()
      return name.includes(keyword) || description.includes(keyword)
    })
  }
  return items
})
const total = computed(() => {
  if (searchKeyword.value) {
    return rules.value.length
  }
  return data.value?.data?.total || 0
})
const hasRules = computed(() => rules.value.length > 0)

// 搜索处理
const handleSearch = () => {
  const startTime = Date.now()
  // 搜索时强制刷新数据
  refreshData().then(() => {
    searchResults.value = {
      total: total.value,
      time: Date.now() - startTime
    }
  })
}

const handleClearSearch = () => {
  searchKeyword.value = ''
  searchResults.value = null
  // 清除搜索后刷新数据
  refreshData()
}

// 注册刷新方法到全局刷新管理器
const { registerPageRefresh, unregisterPageRefresh } = usePageRefreshRegistry()
const { addGlobalRefreshListener, removeGlobalRefreshListener } = useGlobalRefreshEventListener()

// 全局刷新事件处理
const handleGlobalRefresh = () => {
  console.log('🌍 转发管理页面收到全局刷新事件')
  refreshData()
}

// 页面级刷新方法
const pageRefresh = async () => {
  console.log('🔄 转发管理页面级刷新触发')
  await refreshData()
}

// 规则操作
const createRule = async () => {
  const name = window.prompt('请输入规则名称')
  if (!name?.trim()) {
    return
  }

  const url = window.prompt('请输入 Webhook URL')
  if (!url?.trim()) {
    return
  }

  const recipient = window.prompt('可选：收件人过滤（按邮件地址关键字匹配）') || ''

  try {
    await apiService.createForwardRule({
      rule_name: name.trim(),
      webhook_url: url.trim(),
      recipient_filter: recipient.trim() || undefined,
      enabled: 1
    })
    await refreshData()
  } catch (error) {
    console.error('创建规则失败:', error)
    alert('创建规则失败，请检查输入')
  }
}

const editRule = async (rule: any) => {
  const name = window.prompt('规则名称', rule.rule_name)
  if (!name?.trim()) {
    return
  }

  const url = window.prompt('Webhook URL', rule.webhook_url)
  if (!url?.trim()) {
    return
  }

  const recipient = window.prompt('收件人过滤（可选）', rule.recipient_filter || '') || ''

  try {
    await apiService.updateForwardRule(rule.id, {
      rule_name: name.trim(),
      webhook_url: url.trim(),
      recipient_filter: recipient.trim() || undefined
    })
    await refreshData()
  } catch (error) {
    console.error('更新规则失败:', error)
    alert('更新规则失败，请稍后重试')
  }
}

const toggleRule = async (rule: any) => {
  const nextState = rule.enabled ? 0 : 1
  try {
    await apiService.updateForwardRule(rule.id, { enabled: nextState })
    await refreshData()
  } catch (error) {
    console.error('切换规则状态失败:', error)
    alert('切换规则状态失败')
  }
}

const deleteRule = async (rule: any) => {
  if (!confirm(`确定要删除规则 "${rule.rule_name}" 吗？`)) {
    return
  }

  try {
    await apiService.deleteForwardRule(rule.id)
    await refreshData()
  } catch (error) {
    console.error('删除规则失败:', error)
    alert('删除规则失败')
  }
}

// 页面初始化
onMounted(() => {
  console.log('🔄 转发管理页面初始化')

  // 注册页面级刷新方法
  registerPageRefresh(pageRefresh)

  // 监听全局刷新事件
  addGlobalRefreshListener(handleGlobalRefresh)
})

// 页面卸载
onUnmounted(() => {
  // 注销页面级刷新方法
  unregisterPageRefresh()

  // 移除全局刷新事件监听
  removeGlobalRefreshListener(handleGlobalRefresh)
})
</script>

<style scoped>
/* 规则列表样式 */
.rules-list {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.rule-item {
  background: white;
  border-radius: 8px;
  padding: 20px;
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
  display: flex;
  justify-content: space-between;
  align-items: center;
  transition: box-shadow 0.3s ease;
}

.rule-item:hover {
  box-shadow: 0 4px 8px rgba(0, 0, 0, 0.15);
}

.rule-info {
  flex: 1;
}

.rule-name {
  font-size: 18px;
  font-weight: 600;
  color: #2c3e50;
  margin-bottom: 8px;
}

.rule-description {
  color: #6c757d;
  margin-bottom: 8px;
}

.rule-details {
  display: flex;
  gap: 12px;
  align-items: center;
}

.rule-status {
  padding: 4px 8px;
  border-radius: 12px;
  font-size: 12px;
  font-weight: 500;
}

.status-enabled {
  background: #d4edda;
  color: #155724;
}

.status-disabled {
  background: #f8d7da;
  color: #721c24;
}

.rule-actions {
  display: flex;
  gap: 8px;
}

/* 状态样式 */
.error-state,
.empty-state {
  text-align: center;
  padding: 60px 20px;
  background: white;
  border-radius: 8px;
}

.error-icon,
.empty-icon {
  font-size: 48px;
  margin-bottom: 16px;
}

.error-state p,
.empty-state p {
  color: #6c757d;
  margin-bottom: 20px;
  font-size: 16px;
}

@media (max-width: 768px) {
  .rule-item {
    flex-direction: column;
    align-items: stretch;
    gap: 16px;
  }

  .rule-actions {
    justify-content: center;
  }
}
</style>