<template>
  <div class="admin-page">
    <div class="page-header">
      <h1>{{ pageIcon }} {{ pageTitle }}</h1>
    </div>

    <div class="page-content">
      <!-- 临时调试信息 -->
      <div v-if="isDebugMode"
        style="background: #f0f0f0; padding: 10px; margin: 10px 0; font-family: monospace; font-size: 12px;">
        <div>调试信息：</div>
        <div>loading: {{ loading }}</div>
        <div>emails数组长度: {{ emails.length }}</div>
        <div>emails类型: {{ typeof emails }}</div>
        <div>total: {{ total }}</div>
        <div>原始emails: {{ emails }}</div>
      </div>

      <LoadingOverlay v-if="loading" text="加载邮件列表..." />
      <div v-if="!loading && emails.length === 0" class="empty-state">
        <div class="empty-icon">{{ pageIcon }}</div>
        <p>暂无邮件</p>
      </div>
      <div v-if="emails.length > 0" class="list-container">
        <div v-for="email in emails" :key="email.id" class="list-item clickable" @click="viewEmail(email.id)">
          <div class="list-item-info">
            <div class="list-item-title">{{ email.subject }}</div>
            <div class="list-item-meta">
              <span class="list-item-meta-left">
                {{ isAdminPage ? `${email.sender_email} → ${email.recipient_email}` : email.sender_email }}
              </span>
              <span class="list-item-meta-right">{{ formatTime(email.received_at) }}</span>
            </div>
          </div>
        </div>
      </div>

      <!-- 分页 -->
      <div v-if="total > pageSize" class="pagination-container">
        <div class="pagination-info">
          显示 {{ (currentPage - 1) * pageSize + 1 }} - {{ Math.min(currentPage * pageSize, total) }} 条，共 {{ total }} 条
        </div>
        <div class="pagination">
          <button class="btn btn-sm" :disabled="currentPage <= 1" @click="handlePageChange(currentPage - 1)">
            上一页
          </button>
          <span class="pagination-current">{{ currentPage }} / {{ Math.ceil(total / pageSize) }}</span>
          <button class="btn btn-sm" :disabled="currentPage >= Math.ceil(total / pageSize)"
            @click="handlePageChange(currentPage + 1)">
            下一页
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { adminApiService } from '@/composables/api'
import LoadingOverlay from '@/layouts/AppLoadingSpinner.vue'
import { useSystemStore } from '@/composables/system'
const systemStore = useSystemStore()

const router = useRouter()
const route = useRoute()

// 根据路由名称判断页面类型
const routeName = computed(() => route.name as string)
const isAdminPage = computed(() => routeName.value === 'admin-emails')

// 简单的响应式数据
const emailsResponse = ref(null)
const loading = ref(false)

// 页面信息
const pageTitle = computed(() => isAdminPage.value ? '全部邮件' : '我的邮件')
const pageIcon = computed(() => isAdminPage.value ? '📨' : '📧')

// 从响应数据中提取邮件数组和分页信息
const emails = computed(() => emailsResponse?.value?.data?.items || [])
const total = computed(() => emailsResponse?.value?.data?.total || 0)
const isDebugMode = computed(() => systemStore.isDebugMode)
const currentPage = ref(1)
const pageSize = ref(20)

// 加载数据
const loadData = async () => {
  if (loading.value) return

  loading.value = true
  try {
    const params = {
      page: currentPage.value,
      pageSize: pageSize.value,
      scope: 'all'
    }

    const response = await adminApiService.getEmails(params)
    emailsResponse.value = response
    if (!response.success) console.error('加载邮件失败:', response) // TODO fix
  } catch (error) {
    console.error('加载邮件失败:', error)
  } finally {
    loading.value = false
  }
}

// 暴露刷新方法给全局刷新按钮使用
const refreshData = () => {
  loadData()
}

// 注册到全局，让MainLayoutView的刷新按钮能调用
window.refreshCurrentPage = refreshData

// 分页处理
const handlePageChange = (page: number) => {
  currentPage.value = page
  loadData()
}

// 初始化
onMounted(() => {
  loadData()
})

const formatTime = (dateString: string) => {
  const date = new Date(dateString)
  const now = new Date()
  const diff = now.getTime() - date.getTime()

  if (diff < 60000) {
    return '刚刚'
  } else if (diff < 3600000) {
    return `${Math.floor(diff / 60000)}分钟前`
  } else if (diff < 86400000) {
    return `${Math.floor(diff / 3600000)}小时前`
  } else {
    return date.toLocaleDateString('zh-CN')
  }
}

const viewEmail = (emailId: string) => {
  router.push({ name: 'email-detail', params: { id: emailId } })
}

// 页面刷新逻辑已由 usePageData 处理
</script>

<style scoped>
/* 使用全局样式，这里只保留页面特定的样式 */
</style>