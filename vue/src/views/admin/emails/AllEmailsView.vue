<template>
  <div class="all-emails-view">
    <PageHeader title="🌍 全部邮件" />

    <DebugInfo :is-debug-mode="isDebugMode" :route-info="routeInfo" :is-supported="isSupported" :has-access="hasAccess"
      :last-updated="lastUpdated ? lastUpdated.toString() : undefined" />

    <PageStates :loading="loading" :error="error" :is-empty="!data || !emails.length" loading-text="正在加载全部邮件数据..."
      empty-icon="📨" empty-title="暂无邮件" empty-description="系统中没有邮件数据" @retry="refreshData" />

    <div v-if="data && emails.length" class="data-container">
      <!-- 操作工具栏（参考 R2 文件管理样式） -->
      <div class="emails-actions">
        <div class="emails-actions-left">
          <label class="select-all-checkbox">
            <input type="checkbox" :checked="isAllSelected" @change="handleSelectAll" />
            <span>全选</span>
          </label>
          <div v-if="selectedEmailIds.length > 0" class="selection-info">
            <span class="selection-count">已选择 <strong>{{ selectedEmailIds.length }}</strong> 封邮件</span>
          </div>
        </div>
        <div class="emails-actions-right">
          <Button variant="primary" size="sm" @click="batchMarkAsRead" :disabled="selectedEmailIds.length === 0"
            title="标记选中邮件为已读">
            ✅ 标记已读
          </Button>
          <Button variant="primary" size="sm" @click="batchMarkAsUnread" :disabled="selectedEmailIds.length === 0"
            title="标记选中邮件为未读">
            📧 标记未读
          </Button>
          <Button variant="danger" size="sm" @click="batchDelete" :disabled="selectedEmailIds.length === 0"
            title="删除选中邮件">
            {{ selectedEmailIds.length > 0 ? `🗑️ 删除选中 (${selectedEmailIds.length})` : '🗑️ 删除选中' }}
          </Button>
        </div>
      </div>

      <EmailList :emails="emails" :show-owner="true" :show-actions="true" :enable-selection="true"
        :selected-ids="selectedEmailIds" @delete="deleteEmail" @view="viewEmailDetail"
        @selection-change="handleSelectionChange" />

      <Pagination :pagination="pagination || undefined" @change-page="changePage" />
    </div>

    <!-- 邮件详情模态窗口 -->
    <EmailDetailModal :show="showDetailModal" :email-id="selectedEmailId" @close="closeDetailModal" />
  </div>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { useSystemStore } from '@/composables/system'
import { apiService } from '@/composables/api'
import { usePaginatedPageData } from '@/composables/useUnifiedPageData'
import { cacheService } from '@/composables/cache'
import { PageHeader, DebugInfo, PageStates, EmailList, Pagination, Button } from '@/components'
import EmailDetailModal from '@/components/business/EmailDetailModal.vue'

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
} = usePaginatedPageData(1, 20)

// 调试模式
const isDebugMode = computed(() => systemStore.systemConfig?.debug_mode === 1)

// 邮件列表
const emails = computed(() => {
  return data.value?.data?.items || []
})

// 邮件详情模态窗口
const showDetailModal = ref(false)
const selectedEmailId = ref<string | null>(null)

const viewEmailDetail = (id: string) => {
  console.log('📧 [AllEmailsView] 查看邮件详情')
  console.log('📁 文件名: AllEmailsView.vue')
  console.log('📂 文件路径: vue/src/views/admin/emails/AllEmailsView.vue')
  console.log('🆔 邮件ID:', id)
  selectedEmailId.value = id
  showDetailModal.value = true
}

const closeDetailModal = () => {
  showDetailModal.value = false
  const emailId = selectedEmailId.value
  selectedEmailId.value = null

  // 局部更新：只更新对应邮件的状态，而不是重新加载整个列表
  // 后端在获取邮件详情时会自动标记为已读，这里直接更新前端状态
  if (emailId && data.value?.data?.items) {
    const emailIndex = data.value.data.items.findIndex((e: { id: string }) => e.id === emailId)
    if (emailIndex !== -1) {
      const email = data.value.data.items[emailIndex]
      if (email.status === 'unread') {
        // 只有当邮件是未读状态时才需要更新
        email.status = 'read'
        email.is_read = 1
        console.log('📧 [AllEmailsView] 局部更新邮件状态为已读:', emailId)
      }
    }
  }
}

// 多选功能
const selectedEmailIds = ref<string[]>([])

const handleSelectionChange = (ids: string[]) => {
  selectedEmailIds.value = ids
}

const isAllSelected = computed(() => {
  return emails.value.length > 0 && selectedEmailIds.value.length === emails.value.length
})

const handleSelectAll = (event: Event) => {
  const checked = (event.target as HTMLInputElement).checked
  if (checked) {
    selectedEmailIds.value = emails.value.map((email: { id: string }) => email.id)
  } else {
    selectedEmailIds.value = []
  }
}

const clearSelection = () => {
  selectedEmailIds.value = []
}

// 删除邮件
const deleteEmail = async (id: string) => {
  if (!confirm('确定要删除这封邮件吗？')) return

  try {
    await apiService.deleteEmail(id)

    // 清除该邮件的详情缓存
    cacheService.delete(`email_detail_${id}`)

    await refreshData()
    // 如果删除的是选中的邮件，从选中列表中移除
    const index = selectedEmailIds.value.indexOf(id)
    if (index > -1) {
      selectedEmailIds.value.splice(index, 1)
    }
    ElMessage.success('邮件删除成功')
  } catch (error) {
    console.error('删除邮件失败:', error)
    ElMessage.error('删除失败，请稍后重试')
  }
}

// 批量删除
const batchDelete = async () => {
  if (selectedEmailIds.value.length === 0) return
  if (!confirm(`确定要删除选中的 ${selectedEmailIds.value.length} 封邮件吗？`)) return

  try {
    await apiService.batchDeleteEmails(selectedEmailIds.value)
    const count = selectedEmailIds.value.length

    // 清除所有选中邮件的详情缓存
    selectedEmailIds.value.forEach(id => {
      cacheService.delete(`email_detail_${id}`)
    })

    selectedEmailIds.value = []
    await refreshData()
    ElMessage.success(`成功删除 ${count} 封邮件`)
  } catch (error) {
    console.error('批量删除失败:', error)
    ElMessage.error('批量删除失败，请稍后重试')
  }
}

// 批量标记为已读
const batchMarkAsRead = async () => {
  if (selectedEmailIds.value.length === 0) return

  try {
    const count = selectedEmailIds.value.length
    await apiService.batchUpdateEmailReadStatus(selectedEmailIds.value, true)

    // 更新缓存中的邮件状态
    selectedEmailIds.value.forEach(id => {
      const cacheKey = `email_detail_${id}`
      const cached = cacheService.get<any>(cacheKey)
      if (cached) {
        cached.is_read = 1
        cacheService.set(cacheKey, cached, 24 * 60 * 60 * 1000)
      }
    })

    selectedEmailIds.value = []
    await refreshData()
    ElMessage.success(`成功标记 ${count} 封邮件为已读`)
  } catch (error) {
    console.error('批量标记为已读失败:', error)
    ElMessage.error('批量标记失败，请稍后重试')
  }
}

// 批量标记为未读
const batchMarkAsUnread = async () => {
  if (selectedEmailIds.value.length === 0) return

  try {
    const count = selectedEmailIds.value.length
    await apiService.batchUpdateEmailReadStatus(selectedEmailIds.value, false)

    // 更新缓存中的邮件状态
    selectedEmailIds.value.forEach(id => {
      const cacheKey = `email_detail_${id}`
      const cached = cacheService.get<any>(cacheKey)
      if (cached) {
        cached.is_read = 0
        cacheService.set(cacheKey, cached, 24 * 60 * 60 * 1000)
      }
    })

    selectedEmailIds.value = []
    await refreshData()
    ElMessage.success(`成功标记 ${count} 封邮件为未读`)
  } catch (error) {
    console.error('批量标记为未读失败:', error)
    ElMessage.error('批量标记失败，请稍后重试')
  }
}
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

/* 邮件操作工具栏（参考 R2 文件管理样式） */
.emails-actions {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 10px;
  margin-bottom: 20px;
  padding: 12px 15px;
  background: #f8f9fa;
  border: 1px solid #e9ecef;
  border-radius: 6px;
  flex-wrap: wrap;
}

.emails-actions-left {
  display: flex;
  align-items: center;
  gap: 15px;
  flex: 1;
}

.emails-actions-right {
  display: flex;
  gap: 10px;
  align-items: center;
  flex-wrap: wrap;
}

.select-all-checkbox {
  display: flex;
  align-items: center;
  gap: 8px;
  cursor: pointer;
  font-size: 14px;
  font-weight: 500;
  color: #495057;
  user-select: none;
  padding: 4px 8px;
  border-radius: 4px;
  transition: background-color 0.2s ease;
}

.select-all-checkbox:hover {
  background: #e9ecef;
  color: #333;
}

.select-all-checkbox input[type="checkbox"] {
  width: 18px;
  height: 18px;
  cursor: pointer;
  margin: 0;
}

.selection-info {
  display: flex;
  align-items: center;
  padding: 4px 12px;
  background: #e3f2fd;
  border: 1px solid #90caf9;
  border-radius: 4px;
}

.selection-count {
  font-size: 13px;
  color: #1976d2;
}

.selection-count strong {
  font-weight: 600;
  color: #0d47a1;
}

/* 响应式布局 */
@media (max-width: 768px) {
  .emails-actions {
    flex-direction: column;
    align-items: stretch;
  }

  .emails-actions-left,
  .emails-actions-right {
    width: 100%;
    justify-content: space-between;
  }

  .emails-actions-right {
    flex-direction: column;
  }
}
</style>
