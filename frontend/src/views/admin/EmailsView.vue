<template>
  <div class="emails-container">
    <n-card title="邮件管理">
      <template #header-extra>
        <div class="header-actions">
          <n-input
            v-model:value="searchKeyword"
            placeholder="搜索邮件..."
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
        :data="systemStore.allEmails"
        :loading="loading"
        :pagination="pagination"
        :bordered="false"
        striped
        @update:page="handlePageChange"
        @update:page-size="handlePageSizeChange"
      />
    </n-card>

    <!-- 邮件详情模态框 -->
    <n-modal
      v-model:show="showEmailModal"
      preset="dialog"
      :title="selectedEmail?.subject || '邮件详情'"
      style="width: 80%; max-width: 1000px;"
    >
      <div v-if="selectedEmail" class="email-detail">
        <div class="email-header">
          <div class="email-meta">
            <p><strong>发件人:</strong> {{ selectedEmail.from }}</p>
            <p><strong>收件人:</strong> {{ selectedEmail.to }}</p>
            <p><strong>时间:</strong> {{ new Date(selectedEmail.received_at).toLocaleString() }}</p>
          </div>
        </div>
        
        <n-divider />
        
        <div class="email-content">
          <div v-if="selectedEmail.content_type === 'html'" v-html="selectedEmail.content"></div>
          <div v-else style="white-space: pre-wrap;">{{ selectedEmail.content }}</div>
        </div>
        
        <div v-if="selectedEmail.attachments && selectedEmail.attachments.length > 0" class="email-attachments">
          <n-divider />
          <h4>附件</h4>
          <n-list>
            <n-list-item v-for="attachment in selectedEmail.attachments" :key="attachment.id">
              <n-thing>
                <template #header>
                  {{ attachment.filename }}
                </template>
                <template #description>
                  {{ attachment.content_type }} - {{ formatFileSize(attachment.size) }}
                </template>
                <template #footer>
                  <n-button size="small" @click="downloadAttachment(attachment)">
                    下载
                  </n-button>
                </template>
              </n-thing>
            </n-list-item>
          </n-list>
        </div>
      </div>
    </n-modal>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, computed, h } from 'vue'
import { useMessage } from 'naive-ui'
import { Search, Sync, Eye } from '@vicons/fa'
import { useSystemStore } from '@/stores/system'
import { apiService } from '@/api'
import type { DataTableColumns } from 'naive-ui'
import type { Email } from '@/api'

const message = useMessage()
const systemStore = useSystemStore()

const loading = ref(false)
const showEmailModal = ref(false)
const selectedEmail = ref<Email | null>(null)
const searchKeyword = ref('')

const pagination = computed(() => ({
  page: systemStore.currentPage,
  pageSize: systemStore.pageSize,
  itemCount: systemStore.total,
  showSizePicker: true,
  pageSizes: [10, 20, 50],
  showQuickJumper: true
}))

const columns: DataTableColumns<Email> = [
  {
    title: 'ID',
    key: 'id',
    width: 80
  },
  {
    title: '邮箱ID',
    key: 'mailbox_id',
    width: 100
  },
  {
    title: '发件人',
    key: 'from',
    width: 200,
    ellipsis: true
  },
  {
    title: '收件人',
    key: 'to',
    width: 200,
    ellipsis: true
  },
  {
    title: '主题',
    key: 'subject',
    ellipsis: true,
    render: (row) => {
      return h('span', { 
        style: 'font-weight: 500; cursor: pointer;',
        onClick: () => handleViewEmail(row)
      }, row.subject || '(无主题)')
    }
  },
  {
    title: '类型',
    key: 'content_type',
    width: 80,
    render: (row) => {
      return h('n-tag', { 
        type: row.content_type === 'html' ? 'info' : 'default' 
      }, { default: () => row.content_type.toUpperCase() })
    }
  },
  {
    title: '接收时间',
    key: 'received_at',
    width: 180,
    render: (row) => {
      return new Date(row.received_at).toLocaleString()
    }
  },
  {
    title: '操作',
    key: 'actions',
    width: 120,
    render: (row) => {
      return h('div', { class: 'action-buttons' }, [
        h('n-button', {
          size: 'small',
          type: 'primary',
          onClick: () => handleViewEmail(row)
        }, {
          icon: () => h(Eye),
          default: () => '查看'
        })
      ])
    }
  }
]

const handleViewEmail = async (email: Email) => {
  selectedEmail.value = email
  showEmailModal.value = true
}

const handleSearch = async () => {
  await loadEmails(1, systemStore.pageSize, searchKeyword.value)
}

const handleSync = async () => {
  await loadEmails()
}

const handlePageChange = async (page: number) => {
  await loadEmails(page, systemStore.pageSize, searchKeyword.value)
}

const handlePageSizeChange = async (pageSize: number) => {
  await loadEmails(1, pageSize, searchKeyword.value)
}

const loadEmails = async (page = 1, limit = 20, search = '') => {
  loading.value = true
  await systemStore.fetchAllEmails(page, limit, search)
  loading.value = false
}

const downloadAttachment = async (attachment: any) => {
  try {
    const blob = await apiService.getAttachment(attachment.id)
    const url = window.URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = attachment.filename
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    window.URL.revokeObjectURL(url)
  } catch (error) {
    message.error('下载附件失败')
  }
}

const formatFileSize = (bytes: number) => {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
}

onMounted(async () => {
  await loadEmails()
})
</script>

<style scoped>
.emails-container {
  height: 100%;
}

.header-actions {
  display: flex;
  align-items: center;
  gap: 12px;
}

.action-buttons {
  display: flex;
  gap: 8px;
}

.email-detail {
  max-height: 70vh;
  overflow-y: auto;
}

.email-header {
  margin-bottom: 16px;
}

.email-meta p {
  margin: 4px 0;
  color: #666;
}

.email-content {
  margin: 16px 0;
  padding: 16px;
  background: #f5f5f5;
  border-radius: 6px;
  min-height: 100px;
}

.email-attachments {
  margin-top: 16px;
}
</style>
