<template>
  <div class="my-mailboxes-view">
    <PageHeader title="📮 我的邮箱" :show-refresh="true" :loading="loading" @refresh="refreshData">
      <template #actions>
        <Button variant="primary" size="sm" @click="showCreateForm = true">
          ➕ 申请邮箱
        </Button>
        <Button variant="secondary" size="sm" @click="refreshData" :disabled="loading">
          {{ loading ? '🔄 刷新中...' : '🔄 刷新' }}
        </Button>
      </template>
    </PageHeader>

    <DebugInfo :is-debug-mode="isDebugMode" :route-info="routeInfo" :is-supported="isSupported" :has-access="hasAccess"
      :last-updated="lastUpdated ? lastUpdated.toString() : undefined" />

    <PageStates :loading="loading" :error="error" :is-empty="!data || !mailboxes.length" loading-text="正在加载邮箱数据..."
      empty-icon="📮" empty-title="暂无邮箱" empty-description="您还没有申请任何邮箱" @retry="refreshData">
      <template #empty-actions>
        <Button variant="primary" @click="showCreateForm = true">申请邮箱</Button>
      </template>
    </PageStates>

    <div v-if="data && mailboxes.length" class="data-container">
      <MailboxList :mailboxes="mailboxes" :show-owner="false" :show-actions="true" :can-toggle-status="false"
        @delete="deleteMailbox" />

      <Pagination :pagination="pagination || undefined" @change-page="changePage" />
    </div>

    <!-- 申请邮箱表单 -->
    <Modal :show="showCreateForm" title="申请新邮箱" @close="showCreateForm = false">
      <form @submit.prevent="submitApplication">
        <FormField v-model="formData.address" label="邮箱地址" type="email" placeholder="请输入邮箱地址" :required="true" />
        <FormField v-model="formData.reason" label="申请理由" type="textarea" placeholder="请输入申请理由" :rows="3" />
      </form>

      <template #footer>
        <Button variant="secondary" @click="showCreateForm = false">取消</Button>
        <Button variant="primary" @click="submitApplication" :disabled="submitting">
          {{ submitting ? '提交中...' : '提交申请' }}
        </Button>
      </template>
    </Modal>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { usePaginatedPageData } from '@/composables/useUnifiedPageData'
import { useSystemStore } from '@/composables/system'
// import { userApiService } from '@/composables/api'
import {
  PageHeader,
  DebugInfo,
  PageStates,
  MailboxList,
  Pagination,
  Modal,
  FormField,
  Button
} from '@/components'

const systemStore = useSystemStore()

// 使用统一页面数据管理
const {
  data,
  loading,
  error,
  lastUpdated,
  routeInfo,
  isSupported,
  hasAccess,
  pagination,
  // loadData,
  refreshData,
  changePage
} = usePaginatedPageData()

// 调试模式
const isDebugMode = computed(() => systemStore.systemConfig?.debug_mode === 1)

// 邮箱列表
const mailboxes = computed(() => {
  return data.value?.data?.items || []
})

// 申请表单
const showCreateForm = ref(false)
const submitting = ref(false)
const formData = ref({
  address: '',
  reason: ''
})

// 删除邮箱
const deleteMailbox = async (id: number) => {
  if (!confirm('确定要删除这个邮箱吗？')) return

  try {
    // TODO: 实现删除邮箱API
    console.log('删除邮箱:', id)
    await refreshData()
  } catch (error) {
    console.error('删除邮箱失败:', error)
    alert('删除失败')
  }
}

// 提交申请
const submitApplication = async () => {
  submitting.value = true
  try {
    // TODO: 实现申请邮箱API
    console.log('申请邮箱:', formData.value)
    showCreateForm.value = false
    formData.value = { address: '', reason: '' }
    await refreshData()
  } catch (error) {
    console.error('提交申请失败:', error)
    alert('提交失败')
  } finally {
    submitting.value = false
  }
}

// 页面初始化
onMounted(() => {
  console.log('📮 我的邮箱页面初始化')
})
</script>

<style scoped>
.my-mailboxes-view {
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
