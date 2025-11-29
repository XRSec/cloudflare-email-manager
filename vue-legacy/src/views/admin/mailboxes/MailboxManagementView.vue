<template>
  <div class="mailbox-management-view">
    <PageHeader title="📮 邮箱管理">
      <template #actions>
        <Button variant="primary" size="sm" @click="showCreateForm = true">
          ➕ 创建邮箱
        </Button>
        <!-- <Button variant="secondary" size="sm" @click="refreshData" :disabled="loading">
          {{ loading ? '🔄 刷新中...' : '🔄 刷新' }}
        </Button> -->
      </template>
    </PageHeader>

    <DebugInfo :is-debug-mode="isDebugMode" :route-info="routeInfo" :is-supported="isSupported" :has-access="hasAccess"
      :last-updated="lastUpdated ? lastUpdated.toString() : undefined" />

    <PageStates :loading="loading" :error="error" :is-empty="!data || !mailboxes.length" loading-text="正在加载邮箱管理数据..."
      empty-icon="📮" empty-title="暂无邮箱" empty-description="系统中没有邮箱数据" @retry="refreshData" />

    <div v-if="data && mailboxes.length" class="data-container">
      <MailboxList :mailboxes="mailboxes" :show-owner="true" :show-actions="true" :can-toggle-status="true"
        @delete="deleteMailbox" @toggle-status="toggleMailboxStatus" />

      <Pagination :pagination="pagination || undefined" @change-page="changePage" />
    </div>

    <!-- 创建邮箱表单 -->
    <Modal :show="showCreateForm" title="创建新邮箱" @close="showCreateForm = false">
      <form @submit.prevent="submitCreate">
        <FormField v-model="formData.address" label="邮箱地址" type="email" placeholder="请输入邮箱地址" :required="true" />
        <FormField v-model="formData.owner_id" label="所有者ID" type="number" placeholder="请输入用户ID" :required="true" />
      </form>

      <template #footer>
        <Button variant="secondary" @click="showCreateForm = false">取消</Button>
        <Button variant="primary" @click="submitCreate" :disabled="submitting">
          {{ submitting ? '创建中...' : '创建邮箱' }}
        </Button>
      </template>
    </Modal>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { usePaginatedPageData } from '@/composables/useUnifiedPageData'
import { useSystemStore } from '@/composables/system'
import { mailboxApiService } from '@/composables/api'
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

// 创建表单
const showCreateForm = ref(false)
const submitting = ref(false)
const formData = ref({
  address: '',
  owner_id: 0
})

// 切换邮箱状态
const toggleMailboxStatus = async (id: number, currentStatus: number) => {
  const newStatus = currentStatus === 1 ? 2 : 1
  const action = newStatus === 1 ? '启用' : '停用'

  if (!confirm(`确定要${action}这个邮箱吗？`)) return

  try {
    // 这里需要调用相应的API
    console.log(`切换邮箱状态: ${id} -> ${newStatus}`)
    await refreshData()
  } catch (error) {
    console.error('切换邮箱状态失败:', error)
    alert('操作失败')
  }
}

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

// 提交创建
const submitCreate = async () => {
  // 表单验证
  if (!formData.value.address) {
    alert('请输入邮箱地址')
    return
  }
  if (!formData.value.owner_id || formData.value.owner_id <= 0) {
    alert('请输入有效的用户ID')
    return
  }

  submitting.value = true
  try {
    const response = await mailboxApiService.createMailbox({
      address: formData.value.address,
      owner_id: formData.value.owner_id
    })

    if (response.success) {
      alert(response.message || '邮箱创建成功')
      showCreateForm.value = false
      formData.value = { address: '', owner_id: 0 }
      await refreshData()
    } else {
      alert(response.message || '创建失败')
    }
  } catch (error: any) {
    console.error('创建邮箱失败:', error)
    const errorMessage = error.response?.data?.message || error.message || '创建失败'
    alert(errorMessage)
  } finally {
    submitting.value = false
  }
}

// 页面初始化
onMounted(() => {
  console.log('📮 邮箱管理页面初始化')
})
</script>

<style scoped>
.mailbox-management-view {
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
