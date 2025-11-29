<template>
  <div class="all-emails-view">
    <PageHeader title="🌍 全部邮件" />

    <DebugInfo :is-debug-mode="isDebugMode" :route-info="routeInfo" :is-supported="isSupported" :has-access="hasAccess"
      :last-updated="lastUpdated ? lastUpdated.toString() : undefined" />

    <PageStates :loading="loading" :error="error" :is-empty="!data || !emails.length" loading-text="正在加载全部邮件数据..."
      empty-icon="📨" empty-title="暂无邮件" empty-description="系统中没有邮件数据" @retry="refreshData" />

    <div v-if="data && emails.length" class="data-container">
      <EmailList :emails="emails" :show-owner="true" :show-actions="true" @delete="deleteEmail" />

      <Pagination :pagination="pagination || undefined" @change-page="changePage" />
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useSystemStore } from '@/composables/system'
import { apiService } from '@/composables/api'
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
  routeName: 'all-emails',
  description: '全部邮件（管理员）'
}))
const isSupported = computed(() => true)
const hasAccess = computed(() => true)

// 加载全部邮件（管理员）
const loadData = async (page = currentPage.value) => {
  if (loading.value) return

  loading.value = true
  error.value = null

  try {
    const response = await apiService.getAdminEmails({
      page,
      limit: pageSize.value,
      scope: 'all'
    })

    data.value = response
    lastUpdated.value = new Date()
  } catch (err: any) {
    console.error('加载全部邮件失败:', err)
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

// 页面初始化
onMounted(() => {
  console.log('🌍 全部邮件页面初始化')
})
</script>

<style scoped>
.all-emails-view {
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
