<template>
  <div class="all-emails-view">
    <PageHeader title="🌍 全部邮件" />

    <section class="filters-panel" @keydown.enter="handleFilterKeydown">
      <div class="filters-header">
        <div class="filters-heading">
          <span class="filters-eyebrow">Search</span>
          <h2 class="filters-title">搜索与过滤</h2>
          <p class="filters-description">支持关键词、状态、附件、发件人、主题、日期区间和排序组合筛选。</p>
        </div>
        <div class="filters-stats">
          <span class="filters-stat">{{ pagination?.total ?? 0 }} 封匹配邮件</span>
          <span v-if="activeFilterCount > 0" class="filters-stat filters-stat-active">已启用 {{ activeFilterCount }} 个条件</span>
        </div>
      </div>

      <div class="filters-search-row">
        <div class="filters-search-box">
          <SearchBox
            v-model="filters.search"
            :loading="loading"
            :show-stats="false"
            placeholder="搜索主题、发件人、收件人或正文"
            @search="applyFilters"
          />
        </div>
        <button type="button" class="filter-action filter-action-primary" :disabled="loading" @click="applyFilters">
          应用筛选
        </button>
        <button type="button" class="filter-action" :disabled="!hasActiveFilters" @click="resetFilters">
          清空
        </button>
      </div>

      <div class="filters-chip-row">
        <div class="chip-group">
          <span class="chip-group-label">状态</span>
          <button
            type="button"
            class="filter-chip"
            :class="{ active: filters.status === '' }"
            @click="setStatusFilter('')"
          >
            全部
          </button>
          <button
            type="button"
            class="filter-chip"
            :class="{ active: filters.status === 'unread' }"
            @click="setStatusFilter('unread')"
          >
            未读
          </button>
          <button
            type="button"
            class="filter-chip"
            :class="{ active: filters.status === 'read' }"
            @click="setStatusFilter('read')"
          >
            已读
          </button>
        </div>

        <div class="chip-group">
          <span class="chip-group-label">附件</span>
          <button
            type="button"
            class="filter-chip"
            :class="{ active: filters.hasAttachments === '' }"
            @click="setAttachmentFilter('')"
          >
            全部
          </button>
          <button
            type="button"
            class="filter-chip"
            :class="{ active: filters.hasAttachments === 'true' }"
            @click="setAttachmentFilter('true')"
          >
            有附件
          </button>
          <button
            type="button"
            class="filter-chip"
            :class="{ active: filters.hasAttachments === 'false' }"
            @click="setAttachmentFilter('false')"
          >
            无附件
          </button>
        </div>
      </div>

      <div class="filters-grid">
        <label class="filter-field">
          <span class="filter-label">发件人</span>
          <input v-model="filters.sender" type="text" class="filter-input" placeholder="sender@example.com" />
        </label>

        <label class="filter-field">
          <span class="filter-label">主题</span>
          <input v-model="filters.subject" type="text" class="filter-input" placeholder="按主题精确缩小范围" />
        </label>

        <label class="filter-field">
          <span class="filter-label">开始日期</span>
          <input v-model="filters.startDate" type="date" class="filter-input" />
        </label>

        <label class="filter-field">
          <span class="filter-label">结束日期</span>
          <input v-model="filters.endDate" type="date" class="filter-input" />
        </label>

        <label class="filter-field">
          <span class="filter-label">排序字段</span>
          <select v-model="filters.sort" class="filter-input">
            <option v-for="option in SORT_OPTIONS" :key="option.value" :value="option.value">
              {{ option.label }}
            </option>
          </select>
        </label>

        <label class="filter-field">
          <span class="filter-label">排序方向</span>
          <select v-model="filters.order" class="filter-input">
            <option value="desc">降序</option>
            <option value="asc">升序</option>
          </select>
        </label>
      </div>

      <div v-if="activeFilterTags.length > 0" class="active-filters">
        <span v-for="tag in activeFilterTags" :key="tag" class="active-filter-tag">{{ tag }}</span>
      </div>
    </section>

    <PageStates
      :loading="loading"
      :error="error"
      :is-empty="isEmpty"
      loading-text="正在加载全部邮件数据..."
      :empty-icon="hasActiveFilters ? '🔎' : '📨'"
      :empty-title="hasActiveFilters ? '没有匹配邮件' : '暂无邮件'"
      :empty-description="hasActiveFilters ? '当前过滤条件没有匹配结果，请调整后重试。' : '系统中没有邮件数据'"
      @retry="refreshData"
    >
      <template v-if="hasActiveFilters" #empty-actions>
        <Button variant="secondary" size="sm" @click="resetFilters">清空筛选</Button>
      </template>
    </PageStates>

    <div v-if="data && emails.length" class="data-container">
      <div class="emails-actions" :class="{ 'has-selection': selectedEmailIds.length > 0 }">
        <div class="emails-actions-left">
          <label class="select-all-checkbox">
            <input type="checkbox" :checked="isAllSelected" @change="handleSelectAll" />
            <span>全选</span>
          </label>
          <div v-if="selectedEmailIds.length > 0" class="selection-info">
            <span class="selection-count"><strong>{{ selectedEmailIds.length }}</strong></span>
          </div>
        </div>
        <div class="emails-actions-right">
          <Button
            variant="primary"
            size="sm"
            @click="batchMarkAsRead"
            :disabled="selectedEmailIds.length === 0"
            title="标记选中邮件为已读"
          >
            已读
          </Button>
          <Button
            variant="primary"
            size="sm"
            @click="batchMarkAsUnread"
            :disabled="selectedEmailIds.length === 0"
            title="标记选中邮件为未读"
          >
            未读
          </Button>
          <Button
            variant="info"
            size="sm"
            @click="openForwardModalForSelected"
            :disabled="selectedEmailIds.length === 0"
            title="转发选中邮件"
          >
            转发
          </Button>
          <Button
            variant="danger"
            size="sm"
            @click="batchDelete"
            :disabled="selectedEmailIds.length === 0"
            title="删除选中邮件"
          >
            删除
          </Button>
        </div>
      </div>

      <EmailList
        :emails="emails"
        :show-actions="true"
        :enable-selection="true"
        :selected-ids="selectedEmailIds"
        @delete="deleteEmail"
        @view="viewEmailDetail"
        @forward="openForwardModal"
        @selection-change="handleSelectionChange"
      />

      <Pagination :pagination="pagination || undefined" @change-page="changePage" />
    </div>

    <EmailDetailModal :show="showDetailModal" :email-id="selectedEmailId" @close="closeDetailModal" />

    <Modal :show="forwardModalVisible" title="转发邮件" size="medium" @close="closeForwardModal">
      <form class="forward-form" @submit.prevent="submitForward">
        <div class="forward-target-summary">
          <strong>{{ forwardEmailIds.length }}</strong>
          <span>封邮件将被转发</span>
        </div>

        <div class="forward-mode-toggle">
          <button type="button" class="forward-mode-button" :class="{ active: forwardForm.mode === 'webhook' }" @click="forwardForm.mode = 'webhook'">
            Webhook
          </button>
          <button type="button" class="forward-mode-button" :class="{ active: forwardForm.mode === 'recipient' }" @click="forwardForm.mode = 'recipient'">
            收件转发
          </button>
        </div>

        <label v-if="forwardForm.mode === 'webhook'" class="forward-field">
          <span>Webhook 通道</span>
          <select v-model.number="forwardForm.channelId" class="forward-input" :disabled="forwardOptionsLoading">
            <option :value="0">请选择 routing 中的通道</option>
            <option v-for="channel in webhookChannels" :key="channel.id" :value="channel.id">
              {{ channel.name }} / {{ channel.type }}
            </option>
          </select>
        </label>

        <label v-else class="forward-field">
          <span>收件人</span>
          <input v-model.trim="forwardForm.targetEmail" class="forward-input" type="email" placeholder="name@example.com" />
        </label>

        <label v-if="forwardForm.mode === 'recipient'" class="forward-field">
          <span>转发方式</span>
          <select v-model="forwardForm.targetForwardType" class="forward-input">
            <option value="internal">站内转发</option>
            <option value="smtp">SMTP 转发</option>
            <option value="cf">CF 转发</option>
          </select>
        </label>

        <label v-if="forwardForm.mode === 'recipient' && forwardForm.targetForwardType === 'cf'" class="forward-field">
          <span>发件人</span>
          <input v-model.trim="forwardForm.from" class="forward-input" type="email" placeholder="forward@example.com" />
        </label>

        <p v-if="forwardOptionsError" class="forward-error">{{ forwardOptionsError }}</p>
      </form>

      <template #footer>
        <Button variant="secondary" @click="closeForwardModal">取消</Button>
        <Button variant="primary" :disabled="forwardSubmitting || forwardOptionsLoading" @click="submitForward">
          {{ forwardSubmitting ? '转发中...' : '确认转发' }}
        </Button>
      </template>
    </Modal>
  </div>
</template>

<script setup lang="ts">
import { computed, defineAsyncComponent, onMounted, onUnmounted, reactive, ref, watch } from 'vue'
import { useRoute, useRouter, type LocationQuery, type LocationQueryValue } from 'vue-router'
import { emailApiService } from '@/composables/api-email'
import { api } from '@/composables/api-client'
import { usePaginatedPageData } from '@/composables/useUnifiedPageData'
import { cacheService } from '@/composables/cache'
import { PageHeader, PageStates, EmailList, Pagination, Button, SearchBox, Modal } from '@/components'
import { toast } from '@/utils/toast'

type EmailStatusFilter = '' | 'read' | 'unread'
type AttachmentFilter = '' | 'true' | 'false'
type SortField = 'received_at' | 'subject' | 'from_address' | 'to_address' | 'attachment_count' | 'size_bytes'
type SortOrder = 'asc' | 'desc'
type ForwardType = 'internal' | 'smtp' | 'cf'

interface EmailFiltersForm {
  search: string
  status: EmailStatusFilter
  sender: string
  subject: string
  startDate: string
  endDate: string
  hasAttachments: AttachmentFilter
  sort: SortField
  order: SortOrder
}

interface WebhookChannelOption {
  id: number
  name: string
  type: string
  enabled: boolean
}

const FILTER_QUERY_KEYS = ['search', 'status', 'sender', 'subject', 'start_date', 'end_date', 'has_attachments', 'sort', 'order'] as const

const DEFAULT_FILTERS: EmailFiltersForm = {
  search: '',
  status: '',
  sender: '',
  subject: '',
  startDate: '',
  endDate: '',
  hasAttachments: '',
  sort: 'received_at',
  order: 'desc'
}

const SORT_OPTIONS: Array<{ value: SortField; label: string }> = [
  { value: 'received_at', label: '接收时间' },
  { value: 'subject', label: '主题' },
  { value: 'from_address', label: '发件人' },
  { value: 'to_address', label: '收件人' },
  { value: 'attachment_count', label: '附件数量' },
  { value: 'size_bytes', label: '邮件大小' }
]

const SORT_LABELS: Record<SortField, string> = {
  received_at: '接收时间',
  subject: '主题',
  from_address: '发件人',
  to_address: '收件人',
  attachment_count: '附件数量',
  size_bytes: '邮件大小'
}

const route = useRoute()
const router = useRouter()
const EmailDetailModal = defineAsyncComponent(() => import('@/components/business/EmailDetailModal.vue'))

const getQueryValue = (value: LocationQueryValue | LocationQueryValue[] | undefined) => {
  if (Array.isArray(value)) {
    return value[0] || ''
  }

  return value || ''
}

const createDefaultFilters = (): EmailFiltersForm => ({
  ...DEFAULT_FILTERS
})

const normalizeFilters = (source: EmailFiltersForm): EmailFiltersForm => ({
  search: source.search.trim(),
  status: source.status,
  sender: source.sender.trim(),
  subject: source.subject.trim(),
  startDate: source.startDate,
  endDate: source.endDate,
  hasAttachments: source.hasAttachments,
  sort: source.sort,
  order: source.order
})

const isStatusFilter = (value: string): value is EmailStatusFilter => {
  return value === '' || value === 'read' || value === 'unread'
}

const isAttachmentFilter = (value: string): value is AttachmentFilter => {
  return value === '' || value === 'true' || value === 'false'
}

const isSortField = (value: string): value is SortField => {
  return Object.keys(SORT_LABELS).includes(value)
}

const isSortOrder = (value: string): value is SortOrder => {
  return value === 'asc' || value === 'desc'
}

const parseFiltersFromRoute = (query: LocationQuery): EmailFiltersForm => {
  const nextFilters = createDefaultFilters()
  const status = getQueryValue(query.status)
  const hasAttachments = getQueryValue(query.has_attachments)
  const sort = getQueryValue(query.sort)
  const order = getQueryValue(query.order)

  nextFilters.search = getQueryValue(query.search)
  nextFilters.sender = getQueryValue(query.sender)
  nextFilters.subject = getQueryValue(query.subject)
  nextFilters.startDate = getQueryValue(query.start_date)
  nextFilters.endDate = getQueryValue(query.end_date)
  nextFilters.status = isStatusFilter(status) ? status : DEFAULT_FILTERS.status
  nextFilters.hasAttachments = isAttachmentFilter(hasAttachments) ? hasAttachments : DEFAULT_FILTERS.hasAttachments
  nextFilters.sort = isSortField(sort) ? sort : DEFAULT_FILTERS.sort
  nextFilters.order = isSortOrder(order) ? order : DEFAULT_FILTERS.order

  return nextFilters
}

const toLocalDateBoundary = (dateValue: string, boundary: 'start' | 'end') => {
  if (!dateValue) {
    return undefined
  }

  const timeValue = boundary === 'start' ? '00:00:00.000' : '23:59:59.999'
  const date = new Date(`${dateValue}T${timeValue}`)

  if (Number.isNaN(date.getTime())) {
    return undefined
  }

  return date.toISOString()
}

const buildApiParams = (rawFilters: EmailFiltersForm) => {
  const filters = normalizeFilters(rawFilters)
  const params: Record<string, any> = {
    sort: filters.sort,
    order: filters.order
  }

  if (filters.search) params.search = filters.search
  if (filters.status) params.status = filters.status
  if (filters.sender) params.sender = filters.sender
  if (filters.subject) params.subject = filters.subject
  if (filters.startDate) params.start_date = toLocalDateBoundary(filters.startDate, 'start')
  if (filters.endDate) params.end_date = toLocalDateBoundary(filters.endDate, 'end')
  if (filters.hasAttachments) params.has_attachments = filters.hasAttachments === 'true'

  return params
}

const buildRouteQueryFromFilters = (rawFilters: EmailFiltersForm, currentQuery: LocationQuery) => {
  const filters = normalizeFilters(rawFilters)
  const nextQuery = { ...currentQuery } as Record<string, any>

  FILTER_QUERY_KEYS.forEach((key) => {
    delete nextQuery[key]
  })

  if (filters.search) nextQuery.search = filters.search
  if (filters.status) nextQuery.status = filters.status
  if (filters.sender) nextQuery.sender = filters.sender
  if (filters.subject) nextQuery.subject = filters.subject
  if (filters.startDate) nextQuery.start_date = filters.startDate
  if (filters.endDate) nextQuery.end_date = filters.endDate
  if (filters.hasAttachments) nextQuery.has_attachments = filters.hasAttachments
  if (filters.sort !== DEFAULT_FILTERS.sort) nextQuery.sort = filters.sort
  if (filters.order !== DEFAULT_FILTERS.order) nextQuery.order = filters.order

  return nextQuery
}

const serializeParams = (params: Record<string, any>) => {
  const orderedParams = Object.keys(params)
    .sort()
    .reduce<Record<string, any>>((acc, key) => {
      acc[key] = params[key]
      return acc
    }, {})

  return JSON.stringify(orderedParams)
}

const initialFilters = parseFiltersFromRoute(route.query)
const filters = reactive<EmailFiltersForm>({ ...initialFilters })
const appliedFilters = ref<EmailFiltersForm>({ ...initialFilters })
const appliedFilterSignature = ref(serializeParams(buildApiParams(initialFilters)))

const {
  data,
  loading,
  error,
  pagination,
  refreshData,
  changePage,
  setQueryParams
} = usePaginatedPageData(1, 20, buildApiParams(initialFilters))

const refreshCurrentEmailPage = async () => {
  selectedEmailIds.value = []
  await refreshData()
}

const emails = computed(() => {
  return data.value?.data?.items || []
})

const isEmpty = computed(() => {
  return Boolean(data.value) && emails.value.length === 0
})

const activeFilterTags = computed(() => {
  const source = appliedFilters.value
  const tags: string[] = []

  if (source.search) tags.push(`搜索: ${source.search}`)
  if (source.status === 'unread') tags.push('状态: 未读')
  if (source.status === 'read') tags.push('状态: 已读')
  if (source.sender) tags.push(`发件人: ${source.sender}`)
  if (source.subject) tags.push(`主题: ${source.subject}`)
  if (source.hasAttachments === 'true') tags.push('附件: 有附件')
  if (source.hasAttachments === 'false') tags.push('附件: 无附件')
  if (source.startDate) tags.push(`开始: ${source.startDate}`)
  if (source.endDate) tags.push(`结束: ${source.endDate}`)

  if (source.sort !== DEFAULT_FILTERS.sort || source.order !== DEFAULT_FILTERS.order) {
    tags.push(`排序: ${SORT_LABELS[source.sort]} / ${source.order === 'desc' ? '降序' : '升序'}`)
  }

  return tags
})

const activeFilterCount = computed(() => activeFilterTags.value.length)
const hasActiveFilters = computed(() => activeFilterCount.value > 0)

const showDetailModal = ref(false)
const selectedEmailId = ref<string | null>(null)

const openEmailDetail = (id: string) => {
  console.log('📧 [EmailsPage] 查看邮件详情')
  console.log('📁 文件名: EmailsPage.vue')
  console.log('📂 文件路径: vue/src/pages/app/emails/EmailsPage.vue')
  console.log('🆔 邮件ID:', id)
  selectedEmailId.value = id
  showDetailModal.value = true
}

const viewEmailDetail = (id: string) => {
  openEmailDetail(id)
}

const closeDetailModal = () => {
  showDetailModal.value = false
  const emailId = selectedEmailId.value
  selectedEmailId.value = null

  if (emailId && data.value?.data?.items) {
    const emailIndex = data.value.data.items.findIndex((e: { id: string }) => e.id === emailId)
    if (emailIndex !== -1) {
      const email = data.value.data.items[emailIndex]
      if (email.status === 'unread') {
        email.status = 'read'
        email.is_read = 1
        console.log('📧 [EmailsPage] 局部更新邮件状态为已读:', emailId)
      }
    }
  }
}

watch(
  () => serializeParams(buildApiParams(parseFiltersFromRoute(route.query))),
  async (nextSignature) => {
    const nextFilters = parseFiltersFromRoute(route.query)
    Object.assign(filters, nextFilters)
    appliedFilters.value = { ...nextFilters }

    if (nextSignature === appliedFilterSignature.value) {
      return
    }

    appliedFilterSignature.value = nextSignature
    selectedEmailIds.value = []
    await setQueryParams(buildApiParams(nextFilters), { resetPage: true })
  }
)

watch(
  () => route.query.email,
  (emailId) => {
    if (typeof emailId === 'string' && emailId) {
      openEmailDetail(emailId)
    }
  },
  { immediate: true }
)

const selectedEmailIds = ref<string[]>([])
const forwardModalVisible = ref(false)
const forwardEmailIds = ref<string[]>([])
const forwardOptionsLoading = ref(false)
const forwardSubmitting = ref(false)
const forwardOptionsError = ref<string | null>(null)
const webhookChannels = ref<WebhookChannelOption[]>([])
const forwardForm = reactive({
  mode: 'webhook' as 'webhook' | 'recipient',
  channelId: 0,
  targetEmail: '',
  targetForwardType: 'internal' as ForwardType,
  from: ''
})

const loadForwardOptions = async () => {
  forwardOptionsLoading.value = true
  forwardOptionsError.value = null

  try {
    const routingResponse = await api.post('/routing', { action: 'list' })

    const routingData = routingResponse.data?.data || {}
    webhookChannels.value = Array.isArray(routingData.channels)
      ? routingData.channels
        .filter((channel: any) => channel && channel.enabled && channel.url)
        .map((channel: any) => ({
          id: Number(channel.id),
          name: String(channel.name || '未命名通道'),
          type: String(channel.type || 'webhook'),
          enabled: Boolean(channel.enabled)
        }))
        .filter((channel: WebhookChannelOption) => Number.isInteger(channel.id) && channel.id > 0)
      : []

    if (!forwardForm.channelId && webhookChannels.value.length > 0) {
      forwardForm.channelId = webhookChannels.value[0].id
    }
  } catch (error) {
    console.error('加载转发选项失败:', error)
    forwardOptionsError.value = '加载转发配置失败，请稍后重试'
  } finally {
    forwardOptionsLoading.value = false
  }
}

const openForwardModal = async (id: string) => {
  forwardEmailIds.value = [id]
  forwardModalVisible.value = true
  await loadForwardOptions()
}

const openForwardModalForSelected = async () => {
  if (selectedEmailIds.value.length === 0) return
  forwardEmailIds.value = [...selectedEmailIds.value]
  forwardModalVisible.value = true
  await loadForwardOptions()
}

const closeForwardModal = () => {
  if (forwardSubmitting.value) return
  forwardModalVisible.value = false
  forwardEmailIds.value = []
  forwardOptionsError.value = null
}

const buildForwardPayload = () => {
  if (forwardForm.mode === 'webhook') {
    if (!forwardForm.channelId) {
      toast.warning('请选择 Webhook 通道')
      return null
    }

    return {
      mode: 'webhook' as const,
      channelId: forwardForm.channelId
    }
  }

  const targetEmail = forwardForm.targetEmail.trim().toLowerCase()
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(targetEmail)) {
    toast.warning('请输入有效的收件邮箱')
    return null
  }

  const from = forwardForm.from.trim()
  if (forwardForm.targetForwardType === 'cf' && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(from)) {
    toast.warning('请输入有效的 CF 发件人邮箱')
    return null
  }

  return {
    mode: 'recipient' as const,
    targetEmail,
    targetForwardType: forwardForm.targetForwardType,
    from: forwardForm.targetForwardType === 'cf' ? from : undefined
  }
}

const getForwardErrorMessage = (error: unknown) => {
  const responseMessage = (error as any)?.response?.data?.message || (error as any)?.response?.data?.error
  if (typeof responseMessage === 'string' && responseMessage.trim()) {
    return responseMessage.trim()
  }

  const directMessage = (error as Error)?.message
  if (typeof directMessage === 'string' && directMessage.trim()) {
    return directMessage.trim()
  }

  return '转发失败'
}

const buildForwardSuccessMessage = (successCount: number, payload: ReturnType<typeof buildForwardPayload>, responses: any[]) => {
  if (payload?.mode === 'recipient' && successCount === 1) {
    const data = responses[0]?.data || {}
    const target = data.target || payload.targetEmail

    if (data.targetForwardType === 'cf') {
      return data.messageId
        ? `已提交 Cloudflare 投递到 ${target}，消息 ID：${data.messageId}`
        : `已提交 Cloudflare 投递到 ${target}`
    }

    if (data.local) {
      return `已转发到站内邮箱 ${target}`
    }

    return `已转发到 ${target}`
  }

  return `成功转发 ${successCount} 封邮件`
}

const submitForward = async () => {
  if (forwardEmailIds.value.length === 0 || forwardSubmitting.value) return

  const payload = buildForwardPayload()
  if (!payload) return

  forwardSubmitting.value = true
  try {
    let successCount = 0
    let failedCount = 0
    const failureMessages: string[] = []
    const successResponses: any[] = []

    for (const emailId of forwardEmailIds.value) {
      try {
        const response = await emailApiService.forwardEmail(emailId, payload)
        successCount++
        successResponses.push(response)
      } catch (error) {
        console.error('转发邮件失败:', emailId, error)
        failedCount++
        const message = getForwardErrorMessage(error)
        if (!failureMessages.includes(message)) {
          failureMessages.push(message)
        }
      }
    }

    forwardSubmitting.value = false
    const failureMessage = failureMessages[0] || '请查看转发日志'

    if (failedCount === 0) {
      toast.success(buildForwardSuccessMessage(successCount, payload, successResponses), '转发已提交')
      selectedEmailIds.value = []
      closeForwardModal()
    } else if (successCount > 0) {
      toast.warning(`转发完成：成功 ${successCount} 封，失败 ${failedCount} 封。失败原因：${failureMessage}`)
      closeForwardModal()
    } else {
      toast.error(`转发失败：${failureMessage}`)
    }
  } finally {
    forwardSubmitting.value = false
  }
}

watch(
  emails,
  (nextEmails) => {
    const visibleIds = new Set(nextEmails.map((email: { id: string }) => email.id))
    selectedEmailIds.value = selectedEmailIds.value.filter(id => visibleIds.has(id))
  },
  { deep: true }
)

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

const applyFilters = async () => {
  const nextFilters = normalizeFilters(filters)

  if (nextFilters.startDate && nextFilters.endDate && nextFilters.startDate > nextFilters.endDate) {
    toast.warning('开始日期不能晚于结束日期')
    return
  }

  Object.assign(filters, nextFilters)
  await router.replace({
    query: buildRouteQueryFromFilters(nextFilters, route.query)
  })
}

const resetFilters = async () => {
  const nextFilters = createDefaultFilters()
  Object.assign(filters, nextFilters)
  await router.replace({
    query: buildRouteQueryFromFilters(nextFilters, route.query)
  })
}

const setStatusFilter = async (status: EmailStatusFilter) => {
  filters.status = status
  await applyFilters()
}

const setAttachmentFilter = async (value: AttachmentFilter) => {
  filters.hasAttachments = value
  await applyFilters()
}

const handleFilterKeydown = (event: KeyboardEvent) => {
  const target = event.target as HTMLElement | null
  const isInteractiveInput = target instanceof HTMLInputElement || target instanceof HTMLSelectElement

  if (!target || !isInteractiveInput || target.classList.contains('search-input')) {
    return
  }

  event.preventDefault()
  void applyFilters()
}

const deleteEmail = async (id: string) => {
  if (!confirm('确定要删除这封邮件吗？')) return

  try {
    await emailApiService.deleteEmail(id)
    cacheService.delete(`email_detail_${id}`)

    await refreshData()
    const index = selectedEmailIds.value.indexOf(id)
    if (index > -1) {
      selectedEmailIds.value.splice(index, 1)
    }

    toast.success('邮件删除成功')
  } catch (error) {
    console.error('删除邮件失败:', error)
    toast.error('删除失败，请稍后重试')
  }
}

const batchDelete = async () => {
  if (selectedEmailIds.value.length === 0) return
  if (!confirm(`确定要删除选中的 ${selectedEmailIds.value.length} 封邮件吗？`)) return

  try {
    await emailApiService.batchDeleteEmails(selectedEmailIds.value)
    const count = selectedEmailIds.value.length

    selectedEmailIds.value.forEach(id => {
      cacheService.delete(`email_detail_${id}`)
    })

    selectedEmailIds.value = []
    await refreshData()
    toast.success(`成功删除 ${count} 封邮件`)
  } catch (error) {
    console.error('批量删除失败:', error)
    toast.error('批量删除失败，请稍后重试')
  }
}

const batchMarkAsRead = async () => {
  if (selectedEmailIds.value.length === 0) return

  try {
    const count = selectedEmailIds.value.length
    await emailApiService.batchUpdateEmailReadStatus(selectedEmailIds.value, true)

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
    toast.success(`成功标记 ${count} 封邮件为已读`)
  } catch (error) {
    console.error('批量标记为已读失败:', error)
    toast.error('批量标记失败，请稍后重试')
  }
}

const batchMarkAsUnread = async () => {
  if (selectedEmailIds.value.length === 0) return

  try {
    const count = selectedEmailIds.value.length
    await emailApiService.batchUpdateEmailReadStatus(selectedEmailIds.value, false)

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
    toast.success(`成功标记 ${count} 封邮件为未读`)
  } catch (error) {
    console.error('批量标记为未读失败:', error)
    toast.error('批量标记失败，请稍后重试')
  }
}

onMounted(() => {
  window.refreshCurrentPage = refreshCurrentEmailPage
})

onUnmounted(() => {
  if (window.refreshCurrentPage === refreshCurrentEmailPage) {
    delete window.refreshCurrentPage
  }
})
</script>

<style scoped>
.all-emails-view {
  max-width: 1280px;
  margin: 0 auto;
  display: flex;
  flex-direction: column;
  gap: 18px;
}

.filters-panel,
.data-container {
  background: rgba(255, 255, 255, 0.96);
  border-radius: 24px;
  padding: 22px;
  box-shadow: 0 24px 42px -38px rgba(15, 23, 42, 0.8);
  border: 1px solid rgba(15, 23, 42, 0.08);
}

.filters-panel {
  display: flex;
  flex-direction: column;
  gap: 18px;
  background:
    radial-gradient(circle at top left, rgba(48, 120, 196, 0.12), transparent 38%),
    linear-gradient(180deg, rgba(250, 252, 255, 0.98), rgba(244, 248, 252, 0.98));
}

.filters-header {
  display: flex;
  justify-content: space-between;
  gap: 18px;
  align-items: flex-start;
}

.filters-heading {
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.filters-eyebrow {
  display: inline-flex;
  width: fit-content;
  padding: 4px 10px;
  border-radius: 999px;
  background: rgba(34, 96, 170, 0.12);
  color: #24517f;
  font-size: 12px;
  font-weight: 700;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}

.filters-title {
  margin: 0;
  color: #17324a;
  font-size: 24px;
}

.filters-description {
  margin: 0;
  color: #5a6978;
  line-height: 1.6;
}

.filters-stats {
  display: flex;
  gap: 10px;
  flex-wrap: wrap;
  justify-content: flex-end;
}

.filters-stat {
  display: inline-flex;
  align-items: center;
  padding: 10px 14px;
  border-radius: 999px;
  background: rgba(255, 255, 255, 0.88);
  border: 1px solid rgba(21, 52, 82, 0.08);
  color: #2d4a65;
  font-size: 13px;
  font-weight: 600;
}

.filters-stat-active {
  background: rgba(43, 103, 246, 0.12);
  border-color: rgba(43, 103, 246, 0.2);
  color: #174ea6;
}

.filters-search-row {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto auto;
  gap: 12px;
  align-items: center;
}

.filters-search-box {
  min-width: 0;
}

.filters-search-box :deep(.search-container) {
  display: block;
}

.filters-search-box :deep(.search-input-wrapper) {
  position: relative;
  display: flex;
  align-items: center;
  gap: 10px;
}

.filters-search-box :deep(.search-input) {
  width: 100%;
  min-height: 48px;
  padding: 12px 88px 12px 16px;
  border-radius: 16px;
  border: 1px solid rgba(15, 23, 42, 0.08);
  background: rgba(255, 255, 255, 0.94);
  color: #17324a;
  font-size: 14px;
  transition: border-color 0.2s ease, box-shadow 0.2s ease, transform 0.2s ease;
}

.filters-search-box :deep(.search-input:focus) {
  outline: none;
  border-color: rgba(43, 103, 246, 0.48);
  box-shadow: 0 0 0 4px rgba(43, 103, 246, 0.12);
}

.filters-search-box :deep(.search-btn),
.filters-search-box :deep(.clear-btn) {
  position: absolute;
  top: 50%;
  transform: translateY(-50%);
  border: none;
  background: transparent;
  cursor: pointer;
  color: #36536f;
  display: inline-flex;
  align-items: center;
  justify-content: center;
}

.filters-search-box :deep(.search-btn) {
  right: 40px;
}

.filters-search-box :deep(.clear-btn) {
  right: 12px;
}

.filter-action {
  min-height: 46px;
  padding: 0 18px;
  border-radius: 14px;
  border: 1px solid rgba(15, 23, 42, 0.08);
  background: rgba(255, 255, 255, 0.9);
  color: #17324a;
  font-size: 14px;
  font-weight: 600;
  cursor: pointer;
  transition: transform 0.2s ease, box-shadow 0.2s ease, background 0.2s ease;
}

.filter-action:hover:not(:disabled) {
  transform: translateY(-1px);
  box-shadow: 0 18px 28px -26px rgba(15, 23, 42, 0.6);
}

.filter-action:disabled {
  opacity: 0.55;
  cursor: not-allowed;
}

.filter-action-primary {
  background: linear-gradient(135deg, #2b67f6, #1d4ed8);
  border-color: #1d4ed8;
  color: #fff;
}

.filters-chip-row {
  display: flex;
  flex-wrap: wrap;
  gap: 14px;
}

.chip-group {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}

.chip-group-label {
  font-size: 13px;
  font-weight: 700;
  color: #34506a;
}

.filter-chip {
  min-height: 36px;
  padding: 0 14px;
  border-radius: 999px;
  border: 1px solid rgba(21, 52, 82, 0.1);
  background: rgba(255, 255, 255, 0.88);
  color: #35506a;
  font-size: 13px;
  font-weight: 600;
  cursor: pointer;
  transition: border-color 0.2s ease, background 0.2s ease, color 0.2s ease;
}

.filter-chip.active {
  background: linear-gradient(135deg, rgba(43, 103, 246, 0.14), rgba(31, 78, 216, 0.12));
  border-color: rgba(43, 103, 246, 0.28);
  color: #174ea6;
}

.filters-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 14px;
}

.filter-field {
  display: flex;
  flex-direction: column;
  gap: 8px;
  min-width: 0;
}

.filter-label {
  font-size: 13px;
  font-weight: 700;
  color: #35506a;
}

.filter-input {
  min-height: 46px;
  padding: 0 14px;
  border-radius: 14px;
  border: 1px solid rgba(15, 23, 42, 0.08);
  background: rgba(255, 255, 255, 0.94);
  color: #17324a;
  font-size: 14px;
  transition: border-color 0.2s ease, box-shadow 0.2s ease;
}

.filter-input:focus {
  outline: none;
  border-color: rgba(43, 103, 246, 0.48);
  box-shadow: 0 0 0 4px rgba(43, 103, 246, 0.12);
}

.active-filters {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

.active-filter-tag {
  display: inline-flex;
  align-items: center;
  padding: 7px 12px;
  border-radius: 999px;
  background: rgba(23, 78, 166, 0.08);
  border: 1px solid rgba(23, 78, 166, 0.12);
  color: #174ea6;
  font-size: 12px;
  font-weight: 600;
}

.data-container {
  padding: 22px;
}

.emails-actions {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 12px 14px;
  margin-bottom: 20px;
  padding: 14px 18px;
  background: linear-gradient(180deg, rgba(247, 250, 252, 0.96), rgba(241, 246, 251, 0.96));
  border: 1px solid rgba(15, 23, 42, 0.08);
  border-radius: 18px;
  flex-wrap: wrap;
  position: sticky;
  top: 12px;
  z-index: 2;
  backdrop-filter: blur(10px);
  overflow-x: auto;
  scrollbar-width: none;
}

.emails-actions::-webkit-scrollbar {
  display: none;
}

.emails-actions-left {
  display: flex;
  align-items: center;
  gap: 12px;
  flex: 1 1 auto;
  min-width: 0;
  margin-right: auto;
  flex-wrap: wrap;
}

.emails-actions-right {
  display: flex;
  justify-content: flex-end;
  gap: 8px;
  align-items: center;
  min-width: 0;
  flex: 0 0 auto;
  flex-wrap: nowrap;
}

.emails-actions-right :deep(.btn) {
  width: auto;
  min-width: 58px;
  justify-content: center;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  flex: 0 0 auto;
}

.emails-actions-right :deep(.btn.btn-sm) {
  padding: 8px 12px;
  font-size: 12px;
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
  padding: 8px 10px;
  border-radius: 999px;
  border: 1px solid rgba(15, 23, 42, 0.08);
  background: rgba(255, 255, 255, 0.92);
  transition: background-color 0.2s ease;
}

.select-all-checkbox:hover {
  background: #e9ecef;
  color: #333;
}

.select-all-checkbox input[type='checkbox'] {
  width: 18px;
  height: 18px;
  cursor: pointer;
  margin: 0;
}

.selection-info {
  display: flex;
  align-items: center;
  padding: 6px 12px;
  background: rgba(43, 103, 246, 0.1);
  border: 1px solid rgba(43, 103, 246, 0.18);
  border-radius: 999px;
  min-width: 0;
  max-width: 100%;
  box-sizing: border-box;
  flex: 0 1 auto;
}

.forward-form {
  display: flex;
  flex-direction: column;
  gap: 18px;
}

.forward-target-summary {
  display: flex;
  align-items: baseline;
  gap: 8px;
  padding: 12px 14px;
  border: 1px solid rgba(15, 23, 42, 0.08);
  border-radius: 8px;
  background: #f7fafc;
  color: #2d4a65;
}

.forward-target-summary strong {
  color: #174ea6;
  font-size: 20px;
}

.forward-mode-toggle {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 8px;
}

.forward-mode-button {
  min-height: 40px;
  border: 1px solid rgba(15, 23, 42, 0.12);
  border-radius: 8px;
  background: #fff;
  color: #2d4a65;
  cursor: pointer;
  font-weight: 700;
}

.forward-mode-button.active {
  background: #174ea6;
  border-color: #174ea6;
  color: #fff;
}

.forward-field {
  display: flex;
  flex-direction: column;
  gap: 8px;
  color: #35506a;
  font-size: 13px;
  font-weight: 700;
}

.forward-input {
  min-height: 42px;
  padding: 0 12px;
  border: 1px solid rgba(15, 23, 42, 0.12);
  border-radius: 8px;
  background: #fff;
  color: #17324a;
  font-size: 14px;
}

.forward-error {
  margin: 0;
  color: #b42318;
  font-size: 13px;
}

.selection-count {
  font-size: 13px;
  color: #1976d2;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.selection-count strong {
  font-weight: 600;
  color: #0d47a1;
}

@media (max-width: 960px) {
  .filters-header,
  .filters-search-row {
    grid-template-columns: 1fr;
    display: grid;
  }

  .filters-header {
    display: flex;
    flex-direction: column;
  }

  .filters-stats {
    justify-content: flex-start;
  }

  .filters-grid {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
}

@media (max-width: 768px) {
  .all-emails-view {
    gap: 14px;
  }

  .filters-panel,
  .data-container {
    padding: 16px;
    border-radius: 20px;
  }

  .emails-actions {
    align-items: flex-start;
    position: static;
    gap: 10px 8px;
    flex-wrap: nowrap;
  }

  .emails-actions-left {
    width: auto;
    max-width: 100%;
    justify-content: flex-start;
    flex: 0 0 auto;
  }

  .selection-info {
    max-width: 100%;
  }

  .selection-count {
    white-space: nowrap;
  }

  .emails-actions-right {
    width: auto;
    max-width: 100%;
    gap: 8px;
    flex-wrap: nowrap;
    justify-content: flex-start;
  }

  .emails-actions-right :deep(.btn) {
    min-width: 50px;
  }
}

@media (max-width: 640px) {
  .filters-grid {
    grid-template-columns: 1fr;
  }

  .filters-search-row {
    gap: 10px;
  }

  .filters-stats {
    gap: 8px;
  }

  .emails-actions {
    padding: 12px;
    align-items: flex-start;
    flex-wrap: nowrap;
  }

  .emails-actions-left {
    gap: 8px;
    justify-content: flex-start;
    flex: 0 0 auto;
  }

  .emails-actions-right {
    gap: 6px;
    flex-wrap: nowrap;
  }

  .selection-info {
    width: auto;
    max-width: 100%;
  }

  .emails-actions-right :deep(.btn.btn-sm) {
    padding: 8px 6px;
    font-size: 11px;
  }
}
</style>
