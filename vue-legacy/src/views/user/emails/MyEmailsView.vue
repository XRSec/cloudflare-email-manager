<template>
  <div class="my-emails-view">
    <PageHeader title="📧 我的邮件" />

    <DebugInfo :is-debug-mode="isDebugMode" :route-info="routeInfo" :is-supported="isSupported" :has-access="hasAccess"
      :last-updated="lastUpdated ? lastUpdated.toString() : undefined" />

    <PageStates :loading="loading" :error="error" :is-empty="!data || !emails.length" loading-text="正在加载邮件数据..."
      empty-icon="📧" empty-title="暂无邮件" empty-description="当前没有邮件数据" @retry="refreshData" />

    <div v-if="data && emails.length" class="data-container">
      <EmailList :emails="emails" :show-owner="false" :show-actions="true" @delete="deleteEmail" />

      <Pagination :pagination="pagination || undefined" @change-page="changePage" />
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { useSystemStore } from '@/composables/system'
import { apiService } from '@/composables/api'
import { usePageRefreshRegistry, useGlobalRefreshEventListener } from '@/composables/globalRefreshManager'
import { PageHeader, DebugInfo, PageStates, EmailList, Pagination } from '@/components'

const systemStore = useSystemStore()

// 本地页面状态
const data = ref<any | null>(null)
const loading = ref(false)
const error = ref<string | null>(null)
const lastUpdated = ref<Date | null>(null)

const currentPage = ref(1)
const pageSize = ref(20)

const pagination = computed(() => {
  const responseData = data.value?.data
  const total = responseData?.total || 0

  return {
    total,
    page: currentPage.value,
    limit: pageSize.value,
    totalPages: Math.ceil(total / pageSize.value)
  }
})

// 简单的调试信息
const routeInfo = computed(() => ({
  routeName: 'my-emails',
  description: '我的邮件'
}))
const isSupported = computed(() => true)
const hasAccess = computed(() => true)

// 加载当前用户邮件列表
const loadData = async (page = currentPage.value) => {
  if (loading.value) return

  loading.value = true
  error.value = null

  try {
    const response = await apiService.getEmails({
      page,
      limit: pageSize.value
    })

    data.value = response
    lastUpdated.value = new Date()
  } catch (err: any) {
    console.error('加载我的邮件失败:', err)
    error.value = err?.message || '加载失败'
  } finally {
    loading.value = false
  }
}

// 刷新当前页
const refreshData = async () => {
  await loadData(currentPage.value)
}

// 分页切换
const changePage = async (page: number) => {
  currentPage.value = page
  await loadData(page)
}

// 调试模式
const isDebugMode = computed(() => systemStore.systemConfig?.debug_mode === 1)

// 邮件列表
const emails = computed(() => {
  return data.value?.data?.items || []
})

// 删除邮件
const deleteEmail = async (id: number) => {
  if (!confirm('确定要删除这封邮件吗？')) return

  try {
    // TODO: 实现删除邮件API
    console.log('删除邮件:', id)
    await refreshData()
  } catch (error) {
    console.error('删除邮件失败:', error)
    alert('删除失败')
  }
}

// 注册刷新方法到全局刷新管理器
const { registerPageRefresh, unregisterPageRefresh } = usePageRefreshRegistry()
const { addGlobalRefreshListener, removeGlobalRefreshListener } = useGlobalRefreshEventListener()

// 全局刷新事件处理
const handleGlobalRefresh = () => {
  console.log('🌍 我的邮件页面收到全局刷新事件')
  refreshData()
}

// 页面级刷新方法
const pageRefresh = async () => {
  console.log('🔄 我的邮件页面级刷新触发')
  await refreshData()
}

// 页面初始化
onMounted(() => {
  console.log('📧 我的邮件页面初始化')

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
.my-emails-view {
  padding: 20px;
  max-width: 1200px;
  margin: 0 auto;
}

.data-container {
  background: white;
  border-radius: 8px;
  padding: 20px;
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
}
</style>
