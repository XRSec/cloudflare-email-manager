<template>
  <div class="page-content">
    <!-- 统一页面头部 -->
    <PageHeader :title="pageTitle" :show-search="true" :search-placeholder="getSearchPlaceholder()"
      :search-loading="loading" :search-results="searchResults" :tabs="headerTabs" :active-tab="currentTab"
      :show-refresh="false" v-model:search-query="searchQuery" @search="handleSearch" @clear-search="handleClearSearch"
      @tab-change="switchTab">
      <template #actions>
        <!-- 管理员才能看到创建邮箱按钮 -->
        <button v-if="isAdminScope && currentTab === 'mailboxes'" class="btn btn-primary"
          @click="showCreateModal = true">
          ➕ 创建邮箱
        </button>

        <!-- 普通用户看到申请邮箱按钮 -->
        <button v-if="!isAdminScope && currentTab === 'mailboxes'" class="btn btn-primary"
          @click="showCreateModal = true">
          ➕ 申请邮箱
        </button>
      </template>
    </PageHeader>

    <!-- 批量操作栏 -->
    <div v-if="batchMode && selectedItems.length > 0" class="batch-actions">
      <span class="selected-count">已选择 {{ selectedItems.length }} 项</span>

      <!-- 管理员批量操作 -->
      <template v-if="isAdminScope">
        <button v-if="currentTab === 'mailboxes'" class="btn btn-sm btn-warning" @click="batchSuspend">
          ⏸️ 批量停用
        </button>
        <button v-if="currentTab === 'applications'" class="btn btn-sm btn-success" @click="batchApprove">
          ✅ 批量通过
        </button>
        <button v-if="currentTab === 'applications'" class="btn btn-sm btn-danger" @click="batchReject">
          ❌ 批量拒绝
        </button>
      </template>

      <!-- 通用批量操作 -->
      <button class="btn btn-sm btn-danger" @click="batchDelete">
        🗑️ 批量删除
      </button>
    </div>

    <!-- 邮箱列表 -->
    <DataTable v-if="currentTab === 'mailboxes'" :data="mailboxes" :columns="mailboxColumns" :loading="loading"
      :pagination="true" :current-page="currentPage" :page-size="pageSize" :total="total" :searchable="false"
      :refreshable="false" :selectable="batchMode" :selected-rows="selectedItems"
      :empty-text="getEmptyText('mailboxes')" :empty-description="getEmptyDescription('mailboxes')"
      @page-change="handlePageChange" @selection-change="handleSelectionChange" @row-click="viewItem">
      <!-- 状态列 -->
      <template #column-status="{ value }">
        <span class="badge" :class="getStatusClass(value)">
          {{ getStatusText(value) }}
        </span>
      </template>

      <!-- 用户信息列 -->
      <template #column-user_info="{ row }">
        <div v-if="isAdminScope" class="user-info">
          <div class="user-name">{{ row.username || '-' }}</div>
          <div class="user-type">{{ getUserTypeText(row.user_type) }}</div>
        </div>
        <span v-else>-</span>
      </template>

      <!-- 时间列 -->
      <template #column-created_at="{ value }">
        {{ formatDate(value) }}
      </template>

      <!-- 过期时间列 -->
      <template #column-expires_at="{ value }">
        <span v-if="value" :class="getExpiryClass(value)">
          {{ formatDate(value) }}
        </span>
        <span v-else class="text-success">永久</span>
      </template>

      <!-- 操作列 -->
      <template #actions="{ row }">
        <div class="action-buttons">
          <button class="btn btn-sm btn-secondary" @click="viewItem(row)" title="查看详情">
            👁️
          </button>

          <!-- 管理员操作 -->
          <template v-if="isAdminScope">
            <button v-if="row.status === 'active'" class="btn btn-sm btn-warning" @click="suspendMailbox(row)"
              title="停用邮箱">
              ⏸️
            </button>
            <button v-if="row.status === 'suspended'" class="btn btn-sm btn-success" @click="activateMailbox(row)"
              title="激活邮箱">
              ▶️
            </button>
          </template>

          <!-- 通用操作 -->
          <button class="btn btn-sm btn-info" @click="manageForwarding(row)" title="转发设置">
            🔄
          </button>
          <button v-if="canDelete(row)" class="btn btn-sm btn-danger" @click="deleteItem(row)" title="删除邮箱">
            🗑️
          </button>
        </div>
      </template>
    </DataTable>

    <!-- 申请记录列表 -->
    <DataTable v-if="currentTab === 'applications'" :data="applications" :columns="applicationColumns"
      :loading="loading" :pagination="true" :current-page="currentPage" :page-size="pageSize" :total="applicationTotal"
      :searchable="false" :refreshable="false" :selectable="batchMode" :selected-rows="selectedItems"
      :empty-text="getEmptyText('applications')" :empty-description="getEmptyDescription('applications')"
      @page-change="handlePageChange" @selection-change="handleSelectionChange" @row-click="viewItem">
      <!-- 申请状态列 -->
      <template #column-status="{ value }">
        <span class="badge" :class="getApplicationStatusClass(value)">
          {{ getApplicationStatusText(value) }}
        </span>
      </template>

      <!-- 申请理由列 -->
      <template #column-reason="{ value }">
        <div class="reason-cell" :title="value">
          {{ value ? (value.length > 50 ? value.substring(0, 50) + '...' : value) : '-' }}
        </div>
      </template>

      <!-- 申请操作列 -->
      <template #actions="{ row }">
        <div class="action-buttons">
          <button class="btn btn-sm btn-secondary" @click="viewItem(row)" title="查看详情">
            👁️
          </button>

          <!-- 管理员审核操作 -->
          <template v-if="isAdminScope && row.status === 'pending'">
            <button class="btn btn-sm btn-success" @click="approveApplication(row)" title="通过申请">
              ✅
            </button>
            <button class="btn btn-sm btn-danger" @click="rejectApplication(row)" title="拒绝申请">
              ❌
            </button>
          </template>

          <!-- 用户取消申请 -->
          <button v-if="!isAdminScope && row.status === 'pending'" class="btn btn-sm btn-warning"
            @click="cancelApplication(row)" title="取消申请">
            ❌
          </button>
        </div>
      </template>
    </DataTable>

    <!-- 详情模态框 -->
    <Modal v-model:visible="showDetailModal" :title="modalTitle" size="large">
      <div v-if="selectedItem" class="detail-content">
        <!-- 邮箱详情 -->
        <div v-if="currentTab === 'mailboxes'" class="detail-grid">
          <div class="detail-item">
            <label>邮箱地址</label>
            <span>{{ selectedItem.address }}</span>
          </div>
          <div v-if="isAdminScope" class="detail-item">
            <label>所属用户</label>
            <span>{{ selectedItem.username || '-' }} ({{ getUserTypeText(selectedItem.user_type) }})</span>
          </div>
          <div class="detail-item">
            <label>状态</label>
            <span class="badge" :class="getStatusClass(selectedItem.status)">
              {{ getStatusText(selectedItem.status) }}
            </span>
          </div>
          <div class="detail-item">
            <label>创建时间</label>
            <span>{{ formatFullDate(selectedItem.created_at) }}</span>
          </div>
          <div class="detail-item">
            <label>过期时间</label>
            <span v-if="selectedItem.expires_at">{{ formatFullDate(selectedItem.expires_at) }}</span>
            <span v-else class="text-success">永久有效</span>
          </div>
          <div class="detail-item">
            <label>邮件数量</label>
            <span>{{ selectedItem.email_count || 0 }} 封</span>
          </div>
        </div>

        <!-- 申请详情 -->
        <div v-if="currentTab === 'applications'" class="detail-grid">
          <div class="detail-item">
            <label>申请邮箱</label>
            <span>{{ selectedItem.email }}</span>
          </div>
          <div class="detail-item">
            <label>申请用户</label>
            <span>{{ selectedItem.username }}</span>
          </div>
          <div class="detail-item">
            <label>申请状态</label>
            <span class="badge" :class="getApplicationStatusClass(selectedItem.status)">
              {{ getApplicationStatusText(selectedItem.status) }}
            </span>
          </div>
          <div class="detail-item full-width">
            <label>申请理由</label>
            <p class="reason-text">{{ selectedItem.reason || '无' }}</p>
          </div>
          <div class="detail-item">
            <label>申请时间</label>
            <span>{{ formatFullDate(selectedItem.created_at) }}</span>
          </div>
        </div>
      </div>
    </Modal>

    <!-- 创建/申请邮箱模态框 -->
    <Modal v-model:visible="showCreateModal" :title="isAdminScope ? '创建邮箱' : '申请邮箱'" size="medium" :loading="creating"
      show-cancel show-confirm @confirm="submitForm" @cancel="resetForm">
      <form class="create-form">
        <div class="form-group">
          <label class="form-label">邮箱地址 *</label>
          <div class="input-group">
            <input v-model="form.prefix" type="text" class="form-control" placeholder="邮箱前缀"
              :class="{ 'is-invalid': errors.prefix }" />
            <span class="input-group-text">@</span>
            <select v-model="form.domain" class="form-control">
              <option v-for="domain in availableDomains" :key="domain" :value="domain">
                {{ domain }}
              </option>
            </select>
          </div>
          <div v-if="errors.prefix" class="form-error">{{ errors.prefix }}</div>
        </div>

        <!-- 管理员创建邮箱的额外字段 -->
        <template v-if="isAdminScope">
          <div class="form-group">
            <label class="form-label">分配给用户</label>
            <select v-model="form.userId" class="form-control">
              <option value="">管理员创建（无关联用户）</option>
              <option v-for="user in availableUsers" :key="user.id" :value="user.id">
                {{ user.username }} ({{ getUserTypeText(user.user_type) }})
              </option>
            </select>
          </div>
        </template>

        <!-- 用户申请邮箱的理由字段 -->
        <template v-else>
          <div class="form-group">
            <label class="form-label">申请理由 *</label>
            <textarea v-model="form.reason" class="form-control" rows="3" placeholder="请简要说明申请理由（最少20字）"
              :class="{ 'is-invalid': errors.reason }"></textarea>
            <div v-if="errors.reason" class="form-error">{{ errors.reason }}</div>
            <div class="form-help">已输入 {{ form.reason.length }} 字</div>
          </div>
        </template>

        <div class="form-group">
          <label class="form-label">有效期</label>
          <select v-model="form.duration" class="form-control">
            <option v-if="isAdminScope" value="0">永久</option>
            <option value="30">30天</option>
            <option value="90">90天</option>
            <option value="180">180天</option>
            <option value="365">1年</option>
          </select>
        </div>

        <div class="form-group">
          <label class="form-label">{{ isAdminScope ? '备注' : '补充说明' }}</label>
          <textarea v-model="form.note" class="form-control" rows="2"
            :placeholder="isAdminScope ? '创建备注（可选）' : '补充说明（可选）'"></textarea>
        </div>
      </form>
    </Modal>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useRoute } from 'vue-router'
import { useAuthStore } from '@/composables/stores'
import DataTable, { type TableColumn } from '@/layouts/components/DataTable.vue'
import Modal from '@/layouts/components/Modal.vue'
import PageHeader from '@/layouts/components/PageHeader.vue'

// 状态管理
const authStore = useAuthStore()
const route = useRoute()

// 根据路由判断页面类型 - 关键逻辑
const routeName = computed(() => route.name as string)
const isAdminScope = computed(() => routeName.value.startsWith('admin-'))

// 响应式数据
const mailboxes = ref<any[]>([])
const applications = ref<any[]>([])
const loading = ref(false)
const currentPage = ref(1)
const pageSize = ref(20)
const total = ref(0)
const applicationTotal = ref(0)
const searchQuery = ref('')
const searchResults = ref<any>(null)
const currentTab = ref('mailboxes')

// 批量操作
const batchMode = ref(false)
const selectedItems = ref<any[]>([])

// 模态框
const showDetailModal = ref(false)
const showCreateModal = ref(false)
const selectedItem = ref<any>(null)
const creating = ref(false)

// 表单数据
const form = ref({
  prefix: '',
  domain: '',
  userId: '',
  reason: '',
  duration: 365,
  note: ''
})
const errors = ref<Record<string, string>>({})

// 模拟数据
const availableDomains = ref(['temp.mail', 'example.com', 'test.email'])
const availableUsers = ref([
  { id: '1', username: 'user1', user_type: 'user' },
  { id: '2', username: 'user2', user_type: 'user' }
])

// 计算属性
const pageTitle = computed(() => {
  if (isAdminScope.value) {
    return '邮箱管理'
  } else {
    return '我的邮箱'
  }
})

const modalTitle = computed(() => {
  if (currentTab.value === 'mailboxes') {
    return isAdminScope.value ? '邮箱详情' : '我的邮箱详情'
  } else {
    return isAdminScope.value ? '申请详情' : '我的申请记录'
  }
})

// 标签页配置 - 根据权限动态调整
const headerTabs = computed(() => {
  const tabs = [
    {
      key: 'mailboxes',
      title: isAdminScope.value ? '邮箱管理' : '我的邮箱',
      icon: '📮'
    }
  ]

  // 申请记录标签
  if (isAdminScope.value) {
    const pendingCount = applications.value.filter(app => app.status === 'pending').length
    tabs.push({
      key: 'applications',
      title: '申请审核',
      icon: '📋',
      ...(pendingCount > 0 ? { badge: pendingCount, badgeClass: 'badge-warning' } : {})
    })
  } else {
    tabs.push({
      key: 'applications',
      title: '申请记录',
      icon: '📋'
    })
  }

  return tabs
})

// 表格列配置 - 根据权限动态调整
const mailboxColumns = computed((): TableColumn[] => {
  const baseColumns: TableColumn[] = [
    { key: 'address', title: '邮箱地址', width: 200, sortable: true },
    { key: 'status', title: '状态', width: 100, align: 'center' },
    { key: 'created_at', title: '创建时间', width: 130, sortable: true },
    { key: 'expires_at', title: '过期时间', width: 130, sortable: true },
    { key: 'email_count', title: '邮件数', width: 80, align: 'center' }
  ]

  // 管理员可以看到用户信息
  if (isAdminScope.value) {
    baseColumns.splice(1, 0, { key: 'user_info', title: '用户信息', width: 120 })
  }

  return baseColumns
})

const applicationColumns = computed((): TableColumn[] => {
  const baseColumns: TableColumn[] = [
    { key: 'email', title: '申请邮箱', width: 200, sortable: true },
    { key: 'status', title: '状态', width: 100, align: 'center' },
    { key: 'reason', title: '申请理由', width: 200 },
    { key: 'created_at', title: '申请时间', width: 130, sortable: true }
  ]

  // 管理员可以看到申请用户
  if (isAdminScope.value) {
    baseColumns.splice(1, 0, { key: 'username', title: '申请用户', width: 120 })
  }

  return baseColumns
})

// 数据加载 - 根据权限使用不同的scope
const loadMailboxes = async () => {
  loading.value = true
  try {

    // 模拟API调用 - 这里需要根据实际API调整
    await new Promise(resolve => setTimeout(resolve, 500))

    const mockData = Array.from({ length: 15 }, (_, i) => ({
      id: `mailbox_${i + 1}`,
      address: `${isAdminScope.value ? 'user' : 'my'}${i + 1}@temp.mail`,
      username: isAdminScope.value ? `user${i + 1}` : authStore.user?.username,
      user_type: isAdminScope.value ? (i < 3 ? 'admin' : 'user') : authStore.user?.user_type,
      status: ['active', 'suspended', 'expired'][Math.floor(Math.random() * 3)],
      email_count: Math.floor(Math.random() * 50),
      created_at: new Date(Date.now() - Math.random() * 86400000 * 30).toISOString(),
      expires_at: Math.random() > 0.3 ? new Date(Date.now() + Math.random() * 86400000 * 365).toISOString() : null
    }))

    mailboxes.value = mockData
    total.value = isAdminScope.value ? 47 : 8 // 管理员看到更多
  } catch (error) {
    console.error('加载邮箱失败:', error)
  } finally {
    loading.value = false
  }
}

const loadApplications = async () => {
  loading.value = true
  try {

    await new Promise(resolve => setTimeout(resolve, 500))

    const mockData = Array.from({ length: 8 }, (_, i) => ({
      id: `app_${i + 1}`,
      email: `${isAdminScope.value ? 'user' : 'my'}${i + 1}@temp.mail`,
      username: isAdminScope.value ? `user${i + 1}` : authStore.user?.username,
      status: ['pending', 'approved', 'rejected'][Math.floor(Math.random() * 3)],
      reason: `我需要这个邮箱用于项目${i + 1}的测试和开发工作`,
      created_at: new Date(Date.now() - Math.random() * 86400000 * 7).toISOString()
    }))

    applications.value = mockData
    applicationTotal.value = isAdminScope.value ? 23 : 5
  } catch (error) {
    console.error('加载申请失败:', error)
  } finally {
    loading.value = false
  }
}

// 搜索和UI方法
const getSearchPlaceholder = () => {
  const prefix = isAdminScope.value ? '搜索所有' : '搜索我的'
  return currentTab.value === 'mailboxes'
    ? `${prefix}邮箱地址...`
    : `${prefix}申请记录...`
}

const getEmptyText = (type: string) => {
  if (type === 'mailboxes') {
    return isAdminScope.value ? '系统中暂无邮箱' : '您还没有邮箱'
  } else {
    return isAdminScope.value ? '暂无申请记录' : '您还没有申请记录'
  }
}

const getEmptyDescription = (type: string) => {
  if (type === 'mailboxes') {
    return isAdminScope.value ? '系统中还没有任何邮箱记录' : '点击右上角按钮申请新邮箱'
  } else {
    return isAdminScope.value ? '当前没有用户申请邮箱' : '您还没有申请过邮箱'
  }
}

// 权限检查方法
const canDelete = (item: any) => {
  if (isAdminScope.value) {
    return true // 管理员可以删除任何邮箱
  } else {
    return item.username === authStore.user?.username // 用户只能删除自己的邮箱
  }
}

// 事件处理方法
const switchTab = (tab: string) => {
  currentTab.value = tab
  currentPage.value = 1
  searchQuery.value = ''
  searchResults.value = null
  selectedItems.value = []
  batchMode.value = false

  if (tab === 'mailboxes') {
    loadMailboxes()
  } else {
    loadApplications()
  }
}

const refreshData = () => {
  if (currentTab.value === 'mailboxes') {
    loadMailboxes()
  } else {
    loadApplications()
  }
}

const handleSearch = () => {
  const startTime = Date.now()

  if (currentTab.value === 'mailboxes') {
    loadMailboxes().then(() => updateSearchResults(startTime))
  } else {
    loadApplications().then(() => updateSearchResults(startTime))
  }
}

const handleClearSearch = () => {
  searchQuery.value = ''
  searchResults.value = null
  refreshData()
}

const updateSearchResults = (startTime: number) => {
  const currentTotal = currentTab.value === 'mailboxes' ? total.value : applicationTotal.value
  searchResults.value = {
    total: currentTotal,
    time: Date.now() - startTime
  }
}

const handlePageChange = (page: number, size: number) => {
  currentPage.value = page
  pageSize.value = size
  refreshData()
}

const handleSelectionChange = (selection: any[]) => {
  selectedItems.value = selection
  batchMode.value = selection.length > 0
}

// 批量操作方法
const batchApprove = () => {
  console.log('批量通过:', selectedItems.value)
  window.showMessage?.(`已批量通过 ${selectedItems.value.length} 个申请`, 'success')
  selectedItems.value = []
  batchMode.value = false
  refreshData()
}

const batchReject = () => {
  console.log('批量拒绝:', selectedItems.value)
  window.showMessage?.(`已批量拒绝 ${selectedItems.value.length} 个申请`, 'warning')
  selectedItems.value = []
  batchMode.value = false
  refreshData()
}

const batchSuspend = () => {
  console.log('批量停用:', selectedItems.value)
  window.showMessage?.(`已批量停用 ${selectedItems.value.length} 个邮箱`, 'warning')
  selectedItems.value = []
  batchMode.value = false
  refreshData()
}

const batchDelete = () => {
  if (!confirm(`确定要删除选中的 ${selectedItems.value.length} 项吗？`)) return

  console.log('批量删除:', selectedItems.value)
  window.showMessage?.(`已删除 ${selectedItems.value.length} 项`, 'success')
  selectedItems.value = []
  batchMode.value = false
  refreshData()
}

// 单项操作方法
const viewItem = (item: any) => {
  selectedItem.value = item
  showDetailModal.value = true
}

const approveApplication = (application: any) => {
  console.log('通过申请:', application)
  window.showMessage?.(`已通过申请: ${application.email}`, 'success')
  refreshData()
}

const rejectApplication = (application: any) => {
  console.log('拒绝申请:', application)
  window.showMessage?.(`已拒绝申请: ${application.email}`, 'warning')
  refreshData()
}

const cancelApplication = (application: any) => {
  if (!confirm('确定要取消这个申请吗？')) return
  console.log('取消申请:', application)
  window.showMessage?.(`申请已取消: ${application.email}`, 'info')
  refreshData()
}

const suspendMailbox = (mailbox: any) => {
  console.log('停用邮箱:', mailbox)
  window.showMessage?.(`已停用邮箱: ${mailbox.address}`, 'warning')
  refreshData()
}

const activateMailbox = (mailbox: any) => {
  console.log('激活邮箱:', mailbox)
  window.showMessage?.(`已激活邮箱: ${mailbox.address}`, 'success')
  refreshData()
}

const deleteItem = (item: any) => {
  const itemType = currentTab.value === 'mailboxes' ? '邮箱' : '申请'
  const itemName = currentTab.value === 'mailboxes' ? item.address : item.email

  if (!confirm(`确定要删除${itemType} ${itemName} 吗？`)) return

  console.log(`删除${itemType}:`, item)
  window.showMessage?.(`已删除${itemType}: ${itemName}`, 'success')
  refreshData()
}

const manageForwarding = (mailbox: any) => {
  window.router?.push({
    name: 'forward-rules',
    query: { mailbox: mailbox.address }
  })
}

// 表单处理
const submitForm = async () => {
  errors.value = {}

  if (!form.value.prefix.trim()) {
    errors.value.prefix = '邮箱前缀不能为空'
    return
  }

  if (!isAdminScope.value && form.value.reason.length < 20) {
    errors.value.reason = '申请理由至少需要20个字符'
    return
  }

  creating.value = true
  try {
    await new Promise(resolve => setTimeout(resolve, 1000))

    const fullAddress = `${form.value.prefix}@${form.value.domain}`
    const action = isAdminScope.value ? '创建' : '申请'

    console.log(`${action}邮箱:`, { ...form.value, address: fullAddress })

    window.showMessage?.(`邮箱${action}成功: ${fullAddress}`, 'success')
    showCreateModal.value = false
    resetForm()
    refreshData()
  } catch (error: any) {
    window.showMessage?.(error.message || `${isAdminScope.value ? '创建' : '申请'}失败`, 'error')
  } finally {
    creating.value = false
  }
}

const resetForm = () => {
  form.value = {
    prefix: '',
    domain: availableDomains.value[0] || '',
    userId: '',
    reason: '',
    duration: 365,
    note: ''
  }
  errors.value = {}
}

// 工具函数
const getStatusClass = (status: string) => {
  const classes = {
    active: 'badge-success',
    suspended: 'badge-warning',
    expired: 'badge-secondary'
  }
  return classes[status as keyof typeof classes] || 'badge-secondary'
}

const getStatusText = (status: string) => {
  const texts = {
    active: '正常',
    suspended: '已停用',
    expired: '已过期'
  }
  return texts[status as keyof typeof texts] || status
}

const getApplicationStatusClass = (status: string) => {
  const classes = {
    pending: 'badge-warning',
    approved: 'badge-success',
    rejected: 'badge-danger'
  }
  return classes[status as keyof typeof classes] || 'badge-secondary'
}

const getApplicationStatusText = (status: string) => {
  const texts = {
    pending: '待审核',
    approved: '已通过',
    rejected: '已拒绝'
  }
  return texts[status as keyof typeof texts] || status
}

const getUserTypeText = (type: string) => {
  return type === 'admin' ? '管理员' : '普通用户'
}

const getExpiryClass = (expiry: string) => {
  const now = new Date()
  const expiryDate = new Date(expiry)
  const daysLeft = Math.ceil((expiryDate.getTime() - now.getTime()) / (1000 * 3600 * 24))

  if (daysLeft < 7) return 'text-danger'
  if (daysLeft < 30) return 'text-warning'
  return 'text-success'
}

const formatDate = (dateString: string) => {
  return new Date(dateString).toLocaleDateString('zh-CN')
}

const formatFullDate = (dateString: string) => {
  return new Date(dateString).toLocaleString('zh-CN')
}

// 避免刷新冲突 - 使用不同的函数名
const refreshCurrentPage = () => {
  console.log('📱 页面级刷新触发')
  refreshData()
}

// 页面加载
onMounted(() => {
  loadMailboxes()

  // 初始化表单
  if (availableDomains.value.length > 0) {
    form.value.domain = availableDomains.value[0]
  }
})

// 注册全局刷新方法 - 使用页面特定的刷新方法
window.refreshCurrentPage = refreshCurrentPage
</script>

<style scoped>
/* 复用通用样式，只添加页面特定样式 */
.user-info {
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.user-name {
  font-weight: 500;
  color: #2c3e50;
}

.user-type {
  font-size: 12px;
  color: #6c757d;
}

.reason-cell {
  max-width: 200px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.detail-content {
  padding: 20px 0;
}

.detail-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 16px;
  margin-bottom: 20px;
}

.detail-item {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.detail-item.full-width {
  grid-column: 1 / -1;
}

.detail-item label {
  font-weight: 600;
  color: #495057;
  font-size: 14px;
}

.detail-item span,
.detail-item p {
  color: #2c3e50;
}

.reason-text {
  background: #f8f9fa;
  padding: 12px;
  border-radius: 6px;
  border-left: 4px solid #007bff;
  margin: 0;
  line-height: 1.5;
}

.create-form {
  display: flex;
  flex-direction: column;
  gap: 20px;
}

.form-group {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.form-label {
  font-weight: 500;
  color: #2c3e50;
}

.form-control {
  padding: 10px 12px;
  border: 1px solid #ddd;
  border-radius: 6px;
  font-size: 14px;
  transition: border-color 0.3s ease;
}

.form-control:focus {
  outline: none;
  border-color: #007bff;
  box-shadow: 0 0 0 2px rgba(0, 123, 255, 0.25);
}

.form-control.is-invalid {
  border-color: #dc3545;
}

.form-error {
  color: #dc3545;
  font-size: 12px;
}

.form-help {
  color: #6c757d;
  font-size: 12px;
}

.input-group {
  display: flex;
  align-items: center;
}

.input-group .form-control:first-child {
  border-radius: 6px 0 0 6px;
}

.input-group .form-control:last-child {
  border-radius: 0 6px 6px 0;
}

.input-group-text {
  padding: 10px 12px;
  background: #f8f9fa;
  border: 1px solid #ddd;
  border-left: none;
  border-right: none;
  color: #6c757d;
}

/* 状态徽章样式 */
.badge {
  padding: 4px 8px;
  border-radius: 12px;
  font-size: 12px;
  font-weight: 500;
}

.badge-success {
  background: #d4edda;
  color: #155724;
}

.badge-warning {
  background: #fff3cd;
  color: #856404;
}

.badge-danger {
  background: #f8d7da;
  color: #721c24;
}

.badge-secondary {
  background: #e2e3e5;
  color: #6c757d;
}

.text-success {
  color: #28a745;
}

.text-warning {
  color: #ffc107;
}

.text-danger {
  color: #dc3545;
}

@media (max-width: 768px) {
  .detail-grid {
    grid-template-columns: 1fr;
  }
}
</style>
