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
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, computed, h } from 'vue'
import { useMessage } from 'naive-ui'
import { Search, Sync } from '@vicons/fa'
import { useSystemStore } from '@/stores/system'
import type { DataTableColumns } from 'naive-ui'
import type { Mailbox } from '@/api'

const message = useMessage()
const systemStore = useSystemStore()

const loading = ref(false)
const searchKeyword = ref('')

const pagination = computed(() => ({
  page: systemStore.currentPage,
  pageSize: systemStore.pageSize,
  itemCount: systemStore.total,
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
    key: 'user_id',
    width: 100
  },
  {
    title: '邮箱地址',
    key: 'email',
    render: (row) => {
      return h('span', { style: 'font-family: monospace' }, row.email)
    }
  },
  {
    title: '域名',
    key: 'domain'
  },
  {
    title: '状态',
    key: 'status',
    width: 100,
    render: (row) => {
      const statusMap = {
        active: { type: 'success', text: '正常' },
        inactive: { type: 'error', text: '停用' },
        pending: { type: 'warning', text: '待审核' }
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
    title: '过期时间',
    key: 'expires_at',
    width: 180,
    render: (row) => {
      return row.expires_at ? new Date(row.expires_at).toLocaleString() : '永不过期'
    }
  }
]

const handleSearch = async () => {
  await loadMailboxes(1, systemStore.pageSize, searchKeyword.value)
}

const handleSync = async () => {
  await loadMailboxes()
}

const handlePageChange = async (page: number) => {
  await loadMailboxes(page, systemStore.pageSize, searchKeyword.value)
}

const handlePageSizeChange = async (pageSize: number) => {
  await loadMailboxes(1, pageSize, searchKeyword.value)
}

const loadMailboxes = async (page = 1, limit = 20, search = '') => {
  loading.value = true
  await systemStore.fetchAllMailboxes(page, limit, search)
  loading.value = false
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
