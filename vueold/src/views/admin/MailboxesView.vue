<template>
  <div class="mailboxes-container">
    <n-card title="邮箱管理">
      <template #header-extra>
        <div class="header-actions">
          <n-input
            v-model:value="searchKeyword"
            placeholder="搜索邮箱..."
            style="width: 200px; margin-right: 12px;"
            @keyup.enter="handleSearch"
          >
            <template #prefix>
              <n-icon>
                <Search />
              </n-icon>
            </template>
          </n-input>
          
          <n-button @click="handleSearch" :loading="loading">
            搜索
          </n-button>
          
          <n-button @click="handleSync" :loading="loading">
            <template #icon>
              <n-icon>
                <Sync />
              </n-icon>
            </template>
            刷新
          </n-button>
        </div>
      </template>

      <n-data-table
        :columns="columns"
        :data="systemStore.allMailboxes"
        :loading="loading"
        :pagination="pagination"
        :bordered="false"
        striped
        @update:page="handlePageChange"
        @update:page-size="handlePageSizeChange"
      />
    </n-card>

    <!-- 邮箱历史记录弹窗 -->
    <n-modal v-model:show="showHistoryModal" preset="card" title="邮箱历史记录" size="large" style="width: 800px;">
      <template #header-extra>
        <n-tag type="info">{{ currentMailboxAddress }}</n-tag>
      </template>
      
      <n-data-table
        :columns="historyColumns"
        :data="mailboxHistory"
        :loading="historyLoading"
        :pagination="historyPagination"
        :bordered="false"
        striped
        @update:page="handleHistoryPageChange"
        @update:page-size="handleHistoryPageSizeChange"
      />
    </n-modal>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, computed, h } from 'vue'
import { useMessage } // 移除 naive-ui 导入
import { Search, Sync, Clock } from '@vicons/fa'
import { useSystemStore } from '@/stores/system'
import { apiService } from '@/api'
import type { DataTableColumns } // 移除 naive-ui 导入
import type { Mailbox, MailboxHistory } from '@/api'

const message = useMessage()
const systemStore = useSystemStore()

const loading = ref(false)
const searchKeyword = ref('')

// 历史记录相关状态
const showHistoryModal = ref(false)
const historyLoading = ref(false)
const mailboxHistory = ref<MailboxHistory[]>([])
const currentMailboxId = ref<number | null>(null)
const currentMailboxAddress = ref('')
const historyPage = ref(1)
const historyPageSize = ref(10)
const historyTotal = ref(0)

const pagination = computed(() => ({
  page: systemStore.currentPage,
  pageSize: systemStore.pageSize,
  itemCount: systemStore.total,
  showSizePicker: true,
  pageSizes: [10, 20, 50],
  showQuickJumper: true
}))

const historyPagination = computed(() => ({
  page: historyPage.value,
  pageSize: historyPageSize.value,
  itemCount: historyTotal.value,
  showSizePicker: true,
  pageSizes: [10, 20, 50],
  showQuickJumper: true
}))

const columns: DataTableColumns<Mailbox> = [
  {
    title: 'ID',
    key: 'id',
    width: 80
  },
  {
    title: '用户ID',
    key: 'owner_id',
    width: 100
  },
  {
    title: '用户名',
    key: 'owner_username',
    width: 120
  },
  {
    title: '邮箱地址',
    key: 'address',
    render: (row) => {
      return h('span', { style: 'font-family: monospace' }, row.address)
    }
  },
  {
    title: '状态',
    key: 'status',
    width: 100,
    render: (row) => {
      const statusMap = {
        active: { type: 'success', text: '正常' },
        disabled: { type: 'error', text: '停用' },
        deleted: { type: 'warning', text: '已删除' }
      }
      const status = statusMap[row.status]
      return h('n-tag', { type: status.type }, { default: () => status.text })
    }
  },
  {
    title: '创建时间',
    key: 'created_at',
    width: 180,
    render: (row) => {
      return new Date(row.created_at).toLocaleString()
    }
  },
  {
    title: '更新时间',
    key: 'updated_at',
    width: 180,
    render: (row) => {
      return row.updated_at ? new Date(row.updated_at).toLocaleString() : '-'
    }
  },
  {
    title: '操作',
    key: 'actions',
    width: 200,
    render: (row) => {
      return h('div', { style: 'display: flex; gap: 8px;' }, [
        h('n-button', {
          size: 'small',
          type: 'info',
          onClick: () => showMailboxHistory(row.id, row.address)
        }, {
          default: () => '历史记录'
        }),
        h('n-button', {
          size: 'small',
          type: row.status === 'active' ? 'warning' : 'success',
          onClick: () => toggleMailboxStatus(row.id, row.status === 'active' ? 'disabled' : 'active')
        }, {
          default: () => row.status === 'active' ? '停用' : '启用'
        })
      ])
    }
  }
]

// 历史记录列定义
const historyColumns: DataTableColumns<MailboxHistory> = [
  {
    title: 'ID',
    key: 'id',
    width: 80
  },
  {
    title: '操作人',
    key: 'user_username',
    width: 120,
    render: (row) => {
      return h('div', { style: 'display: flex; align-items: center; gap: 8px;' }, [
        h('n-icon', { size: 16 }, { default: () => h(Clock) }),
        h('span', row.user_username || '未知用户')
      ])
    }
  },
  {
    title: '邮箱所有者',
    key: 'owner_username',
    width: 120
  },
  {
    title: '操作类型',
    key: 'action_type',
    width: 100,
    render: (row) => {
      const actionMap = {
        created: { type: 'success', text: '创建' },
        deleted: { type: 'error', text: '删除' },
        disabled: { type: 'warning', text: '停用' }
      }
      const action = actionMap[row.action_type]
      return h('n-tag', { type: action.type }, { default: () => action.text })
    }
  },
  {
    title: '操作时间',
    key: 'created_at',
    width: 180,
    render: (row) => {
      return new Date(row.created_at).toLocaleString()
    }
  }
]

const handleSearch = async () => {
  await loadMailboxes(1, systemStore.pageSize, searchKeyword.value)
}

const handleSync = async () => {
  await loadMailboxes()
}

// 显示邮箱历史记录
const showMailboxHistory = async (mailboxId: number, mailboxAddress: string) => {
  currentMailboxId.value = mailboxId
  currentMailboxAddress.value = mailboxAddress
  showHistoryModal.value = true
  historyPage.value = 1
  await loadMailboxHistory()
}

// 加载邮箱历史记录
const loadMailboxHistory = async () => {
  if (!currentMailboxId.value) return
  
  historyLoading.value = true
  try {
    const response = await apiService.api.get(`/mailbox-history/${currentMailboxId.value}`, {
      params: {
        page: historyPage.value,
        limit: historyPageSize.value
      }
    })
    
    if (response.data.success) {
      mailboxHistory.value = response.data.data.history
      historyTotal.value = response.data.data.total
    } else {
      message.error('加载历史记录失败')
    }
  } catch (error) {
    console.error('加载历史记录失败:', error)
    message.error('加载历史记录失败')
  } finally {
    historyLoading.value = false
  }
}

// 历史记录分页处理
const handleHistoryPageChange = (page: number) => {
  historyPage.value = page
  loadMailboxHistory()
}

const handleHistoryPageSizeChange = (pageSize: number) => {
  historyPageSize.value = pageSize
  historyPage.value = 1
  loadMailboxHistory()
}

const handlePageChange = async (page: number) => {
  await loadMailboxes(page, systemStore.pageSize, searchKeyword.value)
}

const handlePageSizeChange = async (pageSize: number) => {
  await loadMailboxes(1, pageSize, searchKeyword.value)
}

const loadMailboxes = async (page = 1, limit = 20, search = '') => {
  loading.value = true
  // 管理员邮箱管理页面显示所有邮箱
  await systemStore.fetchAllMailboxes(page, limit, search, 'all')
  loading.value = false
}

const toggleMailboxStatus = async (mailboxId: number, status: 'active' | 'disabled') => {
  const action = status === 'active' ? '启用' : '停用'
  if (!confirm(`确定要${action}这个邮箱吗？`)) {
    return
  }
  
  try {
    const response = await apiService.toggleMailboxStatus(mailboxId, status)
    if (response.success) {
      message.success(`邮箱${action}成功`)
      await loadMailboxes()
    } else {
      message.error(response.message || `${action}失败`)
    }
  } catch (error) {
    console.error(`${action}邮箱失败:`, error)
    message.error(`${action}邮箱失败`)
  }
}

onMounted(async () => {
  await loadMailboxes()
})
</script>

<style scoped>
.mailboxes-container {
  height: 100%;
}

.header-actions {
  display: flex;
  align-items: center;
  gap: 12px;
}
</style>
