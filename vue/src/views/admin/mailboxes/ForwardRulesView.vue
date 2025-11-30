<template>
  <div class="page-content">
    <!-- 统一页面头部 -->
    <PageHeader :title="`${pageIcon} ${pageTitle}`" :show-search="true" search-placeholder="搜索规则名称或描述..."
      :search-loading="loading" :search-results="searchResults" :show-refresh="false"
      v-model:search-query="searchKeyword" @search="handleSearch" @clear-search="handleClearSearch">
      <template #actions>
        <button class="btn btn-primary" @click="openCreateModal">
          ➕ 新建规则
        </button>
      </template>
    </PageHeader>

    <!-- 默认推送渠道信息 -->
    <div class="default-webhook-info">
      <div class="info-icon">📢</div>
      <div class="info-content">
        <div class="info-title">默认推送渠道</div>
        <div class="info-detail">{{ defaultWebhookInfo || '未配置' }}</div>
        <div class="info-hint">💡 提示：支持钉钉、飞书、Bark 和自定义类型，接收所有未被规则命中的邮件</div>
      </div>
      <button class="btn btn-sm btn-secondary" @click="openDefaultWebhookModal">
        {{ defaultWebhookInfo ? '修改' : '配置' }}
      </button>
    </div>

    <!-- 加载状态 -->
    <LoadingOverlay v-if="loading" :show="true" text="加载转发规则..." type="local" />

    <!-- 错误状态 -->
    <div v-else-if="error" class="error-state">
      <div class="error-icon">❌</div>
      <p>{{ error }}</p>
      <button class="btn btn-primary" @click="refreshData">重试</button>
    </div>

    <!-- 空状态 -->
    <div v-else-if="!hasRules" class="empty-state">
      <div class="empty-icon">🔄</div>
      <p>{{ searchKeyword ? '没有找到匹配的规则' : '暂无转发规则' }}</p>
      <button v-if="searchKeyword" class="btn btn-secondary" @click="handleClearSearch">
        清除搜索
      </button>
      <button v-else class="btn btn-primary" @click="openCreateModal">
        创建第一个规则
      </button>
    </div>

    <!-- 规则列表 -->
    <div v-else class="rules-list">
      <!-- 批量操作工具栏 -->
      <div class="rules-actions">
        <div class="rules-actions-left">
          <label class="select-all-checkbox">
            <input type="checkbox" :checked="isAllSelected" @change="handleSelectAll" />
            <span>全选</span>
          </label>
          <div v-if="selectedRuleIds.length > 0" class="selection-info">
            <span class="selection-count">已选择 <strong>{{ selectedRuleIds.length }}</strong> 个规则</span>
          </div>
        </div>
        <div class="rules-actions-right">
          <button class="btn btn-sm btn-success" @click="batchEnable" :disabled="selectedRuleIds.length === 0"
            title="批量启用选中规则">
            ✅ 批量启用
          </button>
          <button class="btn btn-sm btn-warning" @click="batchDisable" :disabled="selectedRuleIds.length === 0"
            title="批量禁用选中规则">
            ⏸️ 批量禁用
          </button>
          <button class="btn btn-sm btn-danger" @click="batchDelete" :disabled="selectedRuleIds.length === 0"
            title="批量删除选中规则">
            {{ selectedRuleIds.length > 0 ? `🗑️ 删除选中 (${selectedRuleIds.length})` : '🗑️ 删除选中' }}
          </button>
        </div>
      </div>

      <!-- 规则卡片 -->
      <div v-for="rule in rules" :key="rule.id" class="rule-item" :class="{ 'selected': isRuleSelected(rule.id) }">
        <div class="rule-checkbox">
          <input type="checkbox" :checked="isRuleSelected(rule.id)" @change="toggleRuleSelection(rule.id)" />
        </div>
        <div class="rule-info">
          <div class="rule-header">
            <div class="rule-name">{{ rule.rule_name }}</div>
            <span class="rule-status" :class="rule.enabled ? 'status-enabled' : 'status-disabled'">
              {{ rule.enabled ? '已启用' : '已禁用' }}
            </span>
          </div>
          <div class="rule-details-inline">
            <span v-if="rule.sender_filter" class="detail-tag">
              📧 发件人: {{ rule.sender_filter }}
            </span>
            <span v-if="rule.recipient_filter" class="detail-tag">
              📨 收件人: {{ rule.recipient_filter }}
            </span>
            <span v-if="rule.exact_match === 1" class="exact-match-badge">
              ✓ 精确匹配
            </span>
            <span v-if="rule.skip_default_webhook === 1" class="skip-default-badge">
              ⚠️ 不推送默认
            </span>
            <span v-if="rule.webhooks && rule.webhooks.length > 0" class="webhook-info">
              🔗 Webhooks ({{ rule.webhooks.length }}):
              <span v-for="(wh, idx) in rule.webhooks" :key="wh.id || idx" class="webhook-tag">
                {{ wh.webhook_type }}
              </span>
            </span>
            <span v-else-if="rule.webhook_url" class="legacy-webhook">
              🔗 旧版: {{ formatWebhookUrl(rule.webhook_url) }}
            </span>
          </div>
        </div>
        <div class="rule-actions">
          <button class="btn btn-sm btn-secondary" @click="editRule(rule)">编辑</button>
          <button class="btn btn-sm" :class="rule.enabled ? 'btn-warning' : 'btn-success'" @click="toggleRule(rule)">
            {{ rule.enabled ? '禁用' : '启用' }}
          </button>
          <button class="btn btn-sm btn-danger" @click="deleteRule(rule)">删除</button>
        </div>
      </div>

      <!-- 分页组件 -->
      <Pagination v-if="pagination" :pagination="pagination" @change-page="changePage" />
    </div>

    <!-- 创建/编辑规则模态窗口 -->
    <Modal :show="showCreateModal" :title="editingRule ? '编辑转发规则' : '创建转发规则'" size="large" @close="closeCreateModal">
      <form @submit.prevent="handleSubmitRule" class="rule-form">
        <!-- 规则名称 -->
        <FormField v-model="formData.rule_name" label="规则名称" placeholder="请输入规则名称" :required="true"
          :error="formErrors.rule_name" />

        <!-- 发件人过滤 -->
        <TagListInput v-model="formData.sender_filters" label="发件人过滤（可选）" placeholder="输入关键字后按回车或逗号添加，留空则匹配所有邮件"
          help="例如：example.com 将只匹配来自包含 example.com 的邮件地址。可以添加多个过滤条件，满足任一条件即可匹配。" />

        <!-- 收件人过滤 -->
        <TagListInput v-model="formData.recipient_filters" label="收件人过滤（可选）" placeholder="输入关键字后按回车或逗号添加，留空则匹配所有邮件"
          help="例如：example.com 将只匹配发送到包含 example.com 的邮件地址。可以添加多个过滤条件，满足任一条件即可匹配。" />

        <!-- 精确匹配选项 -->
        <div class="exact-match-section">
          <CheckboxField v-model="formData.exact_match" label="精确匹配"
            help="勾选后，发件人和收件人过滤将使用精确匹配（必须完全相等），且必须携带完整域名（如：user@example.com）。未勾选则使用包含匹配。" />
        </div>

        <!-- 不推送到默认通道选项 -->
        <div class="skip-default-webhook-section">
          <CheckboxField v-model="formData.skip_default_webhook" label="不推送到默认通道" help="勾选后，当此规则匹配时，将不会推送到系统默认推送渠道" />
        </div>

        <!-- Webhook 配置列表 -->
        <div class="webhooks-section">
          <div class="section-header">
            <label class="section-label">Webhook 配置</label>
            <button type="button" class="btn btn-sm btn-secondary" @click="addWebhook">
              ➕ 添加 Webhook
            </button>
          </div>
          <div v-if="formData.webhooks.length === 0" class="empty-webhooks">
            <p>至少需要添加一个 Webhook 配置</p>
          </div>
          <div v-else class="webhooks-list">
            <div v-for="(webhook, index) in formData.webhooks" :key="index" class="webhook-item">
              <div class="webhook-header">
                <span class="webhook-number">Webhook {{ index + 1 }}</span>
                <button v-if="formData.webhooks.length > 1" type="button" class="btn btn-sm btn-danger"
                  @click="removeWebhook(index)">
                  删除
                </button>
              </div>
              <WebhookConfigFields :model-value="{
                url: webhook.webhook_url || '',
                type: webhook.webhook_type || 'custom',
                secret: webhook.webhook_secret || '',
                custom_message: webhook.custom_message || ''
              }" layout="horizontal" :required="true" :error="formErrors[`webhook_${index}_url`]" @update:model-value="(val) => {
                console.log('Webhook 配置更新:', index, val)
                webhook.webhook_url = val.url || ''
                webhook.webhook_type = val.type || 'custom'
                webhook.webhook_secret = val.secret || ''
                webhook.custom_message = val.custom_message || ''
              }" />
            </div>
          </div>
        </div>


      </form>
      <template #footer>
        <button type="button" class="btn btn-secondary" @click="closeCreateModal">取消</button>
        <button type="button" class="btn btn-primary" @click="handleSubmitRule" :disabled="submitting">
          {{ submitting ? (editingRule ? '保存中...' : '创建中...') : (editingRule ? '保存修改' : '创建规则') }}
        </button>
      </template>
    </Modal>

    <!-- 配置默认推送渠道模态窗口 -->
    <Modal :show="showDefaultWebhookModal" title="配置默认推送渠道" size="large" @close="closeDefaultWebhookModal">
      <form @submit.prevent="handleSaveDefaultWebhook">
        <div class="default-webhook-notice">
          <div class="notice-icon">📌</div>
          <div class="notice-text">
            <strong>提示：</strong>默认推送渠道配置存储在用户表中，支持钉钉、飞书、Bark 和自定义类型。所有未被规则命中的邮件都会发送到此 webhook。
          </div>
        </div>
        <WebhookConfigFields :modelValue="defaultWebhookForm"
          @update:modelValue="(val) => Object.assign(defaultWebhookForm, val)" layout="horizontal" />
      </form>
      <template #footer>
        <button type="button" class="btn btn-secondary" @click="closeDefaultWebhookModal">取消</button>
        <button type="button" class="btn btn-primary" @click="handleSaveDefaultWebhook"
          :disabled="savingDefaultWebhook">
          {{ savingDefaultWebhook ? '保存中...' : '保存' }}
        </button>
      </template>
    </Modal>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted, reactive } from 'vue'
import { ElMessage } from 'element-plus'
import { usePaginatedPageData } from '@/composables/useUnifiedPageData'
import { usePageRefreshRegistry, useGlobalRefreshEventListener } from '@/composables/globalRefreshManager'
import { apiService } from '@/composables/api'
import { useRequestManager } from '@/composables/useRequestManager'
import { useRouteApiManager } from '@/composables/routeApiManager'
import { smartCache } from '@/composables/smartCache'
import { useAuthStore } from '@/composables/stores'
import LoadingOverlay from '@/views/shared/components/AppLoadingSpinner.vue'
import { PageHeader, Pagination, Modal, FormField, TagListInput, CheckboxField } from '@/components'
import { WebhookConfigFields } from '@/components/business'

// 使用统一页面数据管理（带缓存）
const {
  data,
  loading,
  error,
  pagination,
  refreshData,
  changePage
} = usePaginatedPageData()

const authStore = useAuthStore()
const requestManager = useRequestManager()
const routeApiManager = useRouteApiManager()

// 失效仪表板的转发规则统计缓存
const invalidateDashboardCache = () => {
  const userId = authStore.user?.id
  if (userId) {
    // 使用统一请求管理器清除缓存
    requestManager.clearCache(`forward_rule_stats_${userId}`)
    requestManager.clearCache(`dashboard_forward_rules_stats`)
    console.log('🗑️ 已失效仪表板的转发规则统计缓存')
  }
}

// 页面信息
const pageTitle = computed(() => '转发管理')
const pageIcon = computed(() => '🔄')

// 多选功能
const selectedRuleIds = ref<number[]>([])

const isRuleSelected = (ruleId: number): boolean => {
  return selectedRuleIds.value.includes(ruleId)
}

const toggleRuleSelection = (ruleId: number) => {
  const index = selectedRuleIds.value.indexOf(ruleId)
  if (index > -1) {
    selectedRuleIds.value.splice(index, 1)
  } else {
    selectedRuleIds.value.push(ruleId)
  }
}

const isAllSelected = computed(() => {
  return rules.value.length > 0 && selectedRuleIds.value.length === rules.value.length
})

const handleSelectAll = (event: Event) => {
  const checked = (event.target as HTMLInputElement).checked
  if (checked) {
    selectedRuleIds.value = rules.value.map((rule: any) => rule.id)
  } else {
    selectedRuleIds.value = []
  }
}

// 截取 URL 显示前 15 位和后 6 位
const formatWebhookUrl = (url: string | null | undefined): string => {
  const tmp = url?.replace('https://', '').replace('http://', '')
  if (!tmp) {
    return ''

  }
  // 显示前 10 位 + ... + 后 6 位
  return `${url?.includes('https://') ? 'https://' : 'http://'}${tmp.slice(0, 5)}...${tmp.slice(-5)}`
}

// 默认推送渠道信息
const defaultWebhookInfo = ref<string | null>(null)

// 获取默认推送渠道信息
const fetchDefaultWebhookInfo = async (forceRefresh = false) => {
  try {
    // 使用统一的请求管理系统，支持缓存
    const response = await routeApiManager.callApi('getDefaultWebhook', {}, {
      forceRefresh,
      routeName: 'forward-rules'
    })

    if (response.success && response.data) {
      const url = response.data.default_webhook_url
      const type = response.data.default_webhook_type || 'custom'
      if (!url) {
        defaultWebhookInfo.value = '未配置'
        return
      }
      const typeMap: Record<string, string> = {
        dingtalk: '钉钉',
        feishu: '飞书',
        bark: 'Bark',
        custom: '自定义'
      }
      defaultWebhookInfo.value = `${typeMap[type] || type} - ${formatWebhookUrl(url)}`
    } else {
      defaultWebhookInfo.value = '未配置'
    }
  } catch (error) {
    console.error('获取默认推送渠道信息失败:', error)
    defaultWebhookInfo.value = '未配置'
  }
}

// 搜索相关
const searchKeyword = ref('')
const searchResults = ref<any>(null)

// 提取数据
const rules = computed(() => {
  const items = data.value?.data?.items || []
  if (searchKeyword.value) {
    const keyword = searchKeyword.value.toLowerCase()
    return items.filter((rule: any) => {
      const name = (rule.rule_name || '').toLowerCase()
      const description = (rule.description || '').toLowerCase()
      return name.includes(keyword) || description.includes(keyword)
    })
  }
  return items
})
const total = computed(() => {
  if (searchKeyword.value) {
    return rules.value.length
  }
  return data.value?.data?.total || 0
})
const hasRules = computed(() => rules.value.length > 0)

// 搜索处理
const handleSearch = () => {
  const startTime = Date.now()
  // 搜索时强制刷新数据
  refreshData().then(() => {
    searchResults.value = {
      total: total.value,
      time: Date.now() - startTime
    }
  })
}

const handleClearSearch = () => {
  searchKeyword.value = ''
  searchResults.value = null
  // 清除搜索后刷新数据
  refreshData()
}

// 注册刷新方法到全局刷新管理器
const { registerPageRefresh, unregisterPageRefresh } = usePageRefreshRegistry()
const { addGlobalRefreshListener, removeGlobalRefreshListener } = useGlobalRefreshEventListener()

// 全局刷新事件处理
const handleGlobalRefresh = () => {
  console.log('🌍 转发管理页面收到全局刷新事件')
  refreshData()
}

// 页面级刷新方法
const pageRefresh = async () => {
  console.log('🔄 转发管理页面级刷新触发')
  await refreshData()
}

// 创建/编辑规则模态窗口
const showCreateModal = ref(false)
const submitting = ref(false)
const editingRule = ref<any>(null) // 当前正在编辑的规则

// 配置默认推送渠道模态窗口
const showDefaultWebhookModal = ref(false)
const savingDefaultWebhook = ref(false)
const defaultWebhookForm = reactive<{
  url: string
  type: 'custom' | 'dingtalk' | 'feishu' | 'bark'
  secret: string
  custom_message: string
}>({
  url: '',
  type: 'custom',
  secret: '',
  custom_message: ''
})
const formData = reactive({
  rule_name: '',
  sender_filters: [] as string[],
  recipient_filters: [] as string[],
  exact_match: false,
  skip_default_webhook: false,
  webhooks: [
    {
      webhook_url: '',
      webhook_type: 'custom' as 'custom' | 'dingtalk' | 'feishu' | 'bark',
      webhook_secret: '',
      custom_message: '',
      enabled: 1
    }
  ] as Array<{
    webhook_url: string
    webhook_type: 'custom' | 'dingtalk' | 'feishu' | 'bark'
    webhook_secret: string
    custom_message: string
    enabled: number
  }>
})
const formErrors = reactive<Record<string, string>>({})

// 打开创建规则模态窗口
const openCreateModal = () => {
  editingRule.value = null // 清除编辑状态
  // 重置表单
  formData.rule_name = ''
  formData.sender_filters = []
  formData.recipient_filters = []
  formData.exact_match = false
  formData.skip_default_webhook = false
  formData.webhooks = [
    {
      webhook_url: '',
      webhook_type: 'custom',
      webhook_secret: '',
      custom_message: '',
      enabled: 1
    }
  ]
  // 清除错误
  Object.keys(formErrors).forEach(key => delete formErrors[key])
  showCreateModal.value = true
}

// 关闭创建/编辑规则模态窗口
const closeCreateModal = () => {
  showCreateModal.value = false
  // 延迟重置表单，避免关闭动画时看到表单清空
  setTimeout(() => {
    editingRule.value = null
    formData.rule_name = ''
    formData.sender_filters = []
    formData.recipient_filters = []
    formData.exact_match = false
    formData.skip_default_webhook = false
    formData.webhooks = [
      {
        webhook_url: '',
        webhook_type: 'custom',
        webhook_secret: '',
        custom_message: '',
        enabled: 1
      }
    ]
    Object.keys(formErrors).forEach(key => delete formErrors[key])
  }, 300)
}

// 添加 Webhook
const addWebhook = () => {
  formData.webhooks.push({
    webhook_url: '',
    webhook_type: 'custom',
    webhook_secret: '',
    custom_message: '',
    enabled: 1
  })
}

// 删除 Webhook
const removeWebhook = (index: number) => {
  if (formData.webhooks.length > 1) {
    formData.webhooks.splice(index, 1)
    // 清除相关的错误信息
    delete formErrors[`webhook_${index}_url`]
    // 重新索引错误信息
    const newErrors: Record<string, string> = {}
    Object.keys(formErrors).forEach(key => {
      if (key.startsWith('webhook_') && key.endsWith('_url')) {
        const match = key.match(/webhook_(\d+)_url/)
        if (match) {
          const oldIndex = parseInt(match[1])
          if (oldIndex > index) {
            newErrors[`webhook_${oldIndex - 1}_url`] = formErrors[key]
          } else if (oldIndex < index) {
            newErrors[key] = formErrors[key]
          }
        }
      } else {
        newErrors[key] = formErrors[key]
      }
    })
    Object.keys(formErrors).forEach(key => delete formErrors[key])
    Object.assign(formErrors, newErrors)
  }
}

// 验证表单
const validateForm = (): boolean => {
  // 清除之前的错误
  Object.keys(formErrors).forEach(key => delete formErrors[key])

  let isValid = true

  // 验证规则名称
  if (!formData.rule_name.trim()) {
    formErrors.rule_name = '规则名称不能为空'
    isValid = false
  }

  // 验证 Webhooks
  if (formData.webhooks.length === 0) {
    ElMessage.warning('至少需要添加一个 Webhook 配置')
    isValid = false
  } else {
    console.log('验证 Webhooks:', JSON.stringify(formData.webhooks, null, 2))
    formData.webhooks.forEach((webhook, index) => {
      console.log(`验证 Webhook ${index}:`, {
        url: webhook.webhook_url,
        type: webhook.webhook_type,
        secret: webhook.webhook_secret?.substring(0, 5) + '...'
      })
      if (!webhook.webhook_url || !webhook.webhook_url.trim()) {
        formErrors[`webhook_${index}_url`] = 'Webhook URL 不能为空'
        console.error(`Webhook ${index} URL 为空`)
        isValid = false
      } else {
        // 验证 URL 格式
        try {
          new URL(webhook.webhook_url)
        } catch {
          formErrors[`webhook_${index}_url`] = '请输入有效的 URL 地址'
          console.error(`Webhook ${index} URL 格式无效:`, webhook.webhook_url)
          isValid = false
        }
      }
    })
  }

  return isValid
}

// 统一处理创建和编辑规则
const handleSubmitRule = async () => {
  if (!validateForm()) {
    return
  }

  submitting.value = true
  try {
    const webhooks = formData.webhooks.map(wh => ({
      webhook_url: wh.webhook_url.trim(),
      webhook_type: wh.webhook_type,
      webhook_secret: wh.webhook_secret.trim() || undefined,
      custom_message: wh.custom_message.trim() || undefined,
      enabled: 1
    }))

    // 将发件人过滤数组转换为逗号分隔的字符串
    const senderFilter = formData.sender_filters.length > 0
      ? formData.sender_filters.join(',')
      : undefined

    // 将收件人过滤数组转换为逗号分隔的字符串
    const recipientFilter = formData.recipient_filters.length > 0
      ? formData.recipient_filters.join(',')
      : undefined

    const ruleData = {
      rule_name: formData.rule_name.trim(),
      sender_filter: senderFilter,
      recipient_filter: recipientFilter,
      exact_match: formData.exact_match ? 1 : 0,
      skip_default_webhook: formData.skip_default_webhook ? 1 : 0,
      enabled: 1,
      webhooks
    }

    if (editingRule.value) {
      // 编辑模式
      await apiService.updateForwardRule(editingRule.value.id, ruleData)
      ElMessage.success('转发规则更新成功')
    } else {
      // 创建模式
      await apiService.createForwardRule(ruleData)
      ElMessage.success('转发规则创建成功')
    }

    invalidateDashboardCache()
    await refreshData()
    closeCreateModal()
  } catch (error: any) {
    console.error(`${editingRule.value ? '更新' : '创建'}规则失败:`, error)
    const errorMessage = error?.response?.data?.message || error?.message || `${editingRule.value ? '更新' : '创建'}规则失败，请检查输入`
    ElMessage.error(errorMessage)
  } finally {
    submitting.value = false
  }
}

// 打开编辑规则模态窗口
const editRule = (rule: any) => {
  editingRule.value = rule

  // 填充表单数据
  formData.rule_name = rule.rule_name || ''

  // 解析发件人过滤（从逗号分隔字符串转为数组）
  formData.sender_filters = rule.sender_filter
    ? rule.sender_filter.split(',').map((s: string) => s.trim()).filter(Boolean)
    : []

  // 解析收件人过滤（从逗号分隔字符串转为数组）
  formData.recipient_filters = rule.recipient_filter
    ? rule.recipient_filter.split(',').map((s: string) => s.trim()).filter(Boolean)
    : []

  formData.exact_match = rule.exact_match === 1
  formData.skip_default_webhook = rule.skip_default_webhook === 1

  // 填充 webhooks 数据
  if (rule.webhooks && rule.webhooks.length > 0) {
    formData.webhooks = rule.webhooks.map((wh: any) => ({
      webhook_url: wh.webhook_url || '',
      webhook_type: wh.webhook_type || 'custom',
      webhook_secret: wh.webhook_secret || '',
      custom_message: wh.custom_message || '',
      enabled: wh.enabled || 1
    }))
  } else {
    // 如果没有 webhooks，初始化一个空的
    formData.webhooks = [
      {
        webhook_url: '',
        webhook_type: 'custom',
        webhook_secret: '',
        custom_message: '',
        enabled: 1
      }
    ]
  }

  // 清除错误
  Object.keys(formErrors).forEach(key => delete formErrors[key])

  showCreateModal.value = true
}

const toggleRule = async (rule: any) => {
  const nextState = rule.enabled ? 0 : 1
  try {
    await apiService.updateForwardRule(rule.id, { enabled: nextState })
    invalidateDashboardCache()
    await refreshData()
    ElMessage.success(`规则已${nextState ? '启用' : '禁用'}`)
  } catch (error) {
    console.error('切换规则状态失败:', error)
    ElMessage.error('切换规则状态失败')
  }
}

const deleteRule = async (rule: any) => {
  if (!confirm(`确定要删除规则 "${rule.rule_name}" 吗？`)) {
    return
  }

  try {
    await apiService.deleteForwardRule(rule.id)

    // 如果删除的是选中的规则，从选中列表中移除
    const index = selectedRuleIds.value.indexOf(rule.id)
    if (index > -1) {
      selectedRuleIds.value.splice(index, 1)
    }

    invalidateDashboardCache()
    await refreshData()
    ElMessage.success('转发规则删除成功')
  } catch (error) {
    console.error('删除规则失败:', error)
    ElMessage.error('删除规则失败')
  }
}

// 批量启用
const batchEnable = async () => {
  if (selectedRuleIds.value.length === 0) return

  if (!confirm(`确定要启用选中的 ${selectedRuleIds.value.length} 个规则吗？`)) {
    return
  }

  try {
    const count = selectedRuleIds.value.length
    // 批量更新规则状态
    await Promise.all(
      selectedRuleIds.value.map(id =>
        apiService.updateForwardRule(id, { enabled: 1 })
      )
    )

    selectedRuleIds.value = []
    invalidateDashboardCache()
    await refreshData()
    ElMessage.success(`成功启用 ${count} 个规则`)
  } catch (error) {
    console.error('批量启用失败:', error)
    ElMessage.error('批量启用失败，请稍后重试')
  }
}

// 批量禁用
const batchDisable = async () => {
  if (selectedRuleIds.value.length === 0) return

  if (!confirm(`确定要禁用选中的 ${selectedRuleIds.value.length} 个规则吗？`)) {
    return
  }

  try {
    const count = selectedRuleIds.value.length
    // 批量更新规则状态
    await Promise.all(
      selectedRuleIds.value.map(id =>
        apiService.updateForwardRule(id, { enabled: 0 })
      )
    )

    selectedRuleIds.value = []
    invalidateDashboardCache()
    await refreshData()
    ElMessage.success(`成功禁用 ${count} 个规则`)
  } catch (error) {
    console.error('批量禁用失败:', error)
    ElMessage.error('批量禁用失败，请稍后重试')
  }
}

// 批量删除
const batchDelete = async () => {
  if (selectedRuleIds.value.length === 0) return

  if (!confirm(`确定要删除选中的 ${selectedRuleIds.value.length} 个规则吗？此操作不可撤销！`)) {
    return
  }

  try {
    const count = selectedRuleIds.value.length
    // 批量删除规则
    await Promise.all(
      selectedRuleIds.value.map(id =>
        apiService.deleteForwardRule(id)
      )
    )

    selectedRuleIds.value = []
    invalidateDashboardCache()
    await refreshData()
    ElMessage.success(`成功删除 ${count} 个规则`)
  } catch (error) {
    console.error('批量删除失败:', error)
    ElMessage.error('批量删除失败，请稍后重试')
  }
}

// 打开配置默认推送渠道模态窗口
const openDefaultWebhookModal = async () => {
  try {
    console.log('🔧 开始加载默认 webhook 配置...')

    // 使用统一的请求管理系统，强制刷新数据
    const response = await routeApiManager.callApi('getDefaultWebhook', {}, {
      forceRefresh: true,  // 强制刷新，确保获取最新数据
      routeName: 'forward-rules'
    })

    console.log('📥 获取到的配置:', response)

    if (response.success && response.data) {
      // 直接更新表单对象的所有字段
      defaultWebhookForm.url = response.data.default_webhook_url || ''
      defaultWebhookForm.type = response.data.default_webhook_type || 'custom'
      defaultWebhookForm.secret = response.data.default_webhook_secret || ''
      defaultWebhookForm.custom_message = response.data.default_webhook_custom_message || ''

      console.log('✅ 表单数据已更新:', defaultWebhookForm)
    } else {
      console.warn('⚠️ 响应数据格式不正确:', response)
    }
  } catch (error) {
    console.error('❌ 获取默认推送渠道配置失败:', error)
    ElMessage.error('获取配置失败')
    return  // 如果获取失败，不打开模态框
  }

  // 确保数据更新后再打开模态框
  showDefaultWebhookModal.value = true
}

// 关闭配置默认推送渠道模态窗口
const closeDefaultWebhookModal = () => {
  showDefaultWebhookModal.value = false
}

// 保存默认推送渠道配置
const handleSaveDefaultWebhook = async () => {
  savingDefaultWebhook.value = true
  try {
    console.log('📝 保存前的表单数据:', defaultWebhookForm)

    const updateData = {
      default_webhook_url: defaultWebhookForm.url.trim() || '',
      default_webhook_type: defaultWebhookForm.type,
      default_webhook_secret: defaultWebhookForm.secret.trim() || '',
      default_webhook_custom_message: defaultWebhookForm.custom_message.trim() || ''
    }

    console.log('📤 发送的数据:', updateData)

    // 直接使用 apiService 进行更新操作（写操作不需要缓存）
    const response = await apiService.updateDefaultWebhook(updateData)

    console.log('📥 服务器响应:', response)

    if (response.success) {
      // 触发智能缓存的依赖更新，失效相关缓存
      smartCache.invalidate('update_default_webhook')
      console.log('🗑️ 已失效默认 webhook 缓存')

      // 清除请求管理器中的缓存
      requestManager.clearCache('default_webhook')

      // 强制刷新默认推送渠道信息显示
      await fetchDefaultWebhookInfo(true)

      ElMessage.success('默认推送渠道配置已保存')
      closeDefaultWebhookModal()
    } else {
      ElMessage.error(response.message || '保存失败')
    }
  } catch (error: any) {
    console.error('保存默认推送渠道配置失败:', error)
    ElMessage.error(error?.response?.data?.message || '保存失败，请稍后重试')
  } finally {
    savingDefaultWebhook.value = false
  }
}

// 页面初始化
onMounted(async () => {
  console.log('🔄 转发管理页面初始化')

  // 获取默认推送渠道信息
  await fetchDefaultWebhookInfo()

  // 注册页面级刷新方法
  registerPageRefresh(pageRefresh)

  // 监听全局刷新事件
  addGlobalRefreshListener(handleGlobalRefresh)
})

// 页面卸载
onUnmounted(() => {
  // 注销页面级刷新方法
  unregisterPageRefresh()

  // 移除全局刷新事件监听
  removeGlobalRefreshListener(handleGlobalRefresh)
})
</script>

<style scoped>
/* 规则列表样式 */
.rules-list {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

/* 批量操作工具栏样式 */
.rules-actions {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 16px 20px;
  background: #f8f9fa;
  border-radius: 8px;
  margin-bottom: 16px;
  border: 1px solid #e9ecef;
}

.rules-actions-left {
  display: flex;
  align-items: center;
  gap: 16px;
}

.rules-actions-right {
  display: flex;
  align-items: center;
  gap: 12px;
}

.select-all-checkbox {
  display: flex;
  align-items: center;
  gap: 8px;
  cursor: pointer;
  user-select: none;
  font-weight: 500;
  color: #495057;
}

.select-all-checkbox input[type="checkbox"] {
  width: 18px;
  height: 18px;
  cursor: pointer;
}

.selection-info {
  padding: 6px 12px;
  background: #e3f2fd;
  border-radius: 4px;
  color: #1976d2;
  font-size: 14px;
}

.selection-count {
  font-size: 14px;
}

.selection-count strong {
  font-weight: 700;
  color: #0d47a1;
}

.rule-item {
  background: white;
  border-radius: 8px;
  padding: 20px;
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
  display: flex;
  justify-content: space-between;
  align-items: center;
  transition: all 0.3s ease;
  border: 2px solid transparent;
}

.rule-item:hover {
  box-shadow: 0 4px 8px rgba(0, 0, 0, 0.15);
}

.rule-item.selected {
  border-color: #007bff;
  background: #f0f8ff;
}

.rule-checkbox {
  display: flex;
  align-items: center;
  margin-right: 16px;
}

.rule-checkbox input[type="checkbox"] {
  width: 20px;
  height: 20px;
  cursor: pointer;
}

.rule-info {
  flex: 1;
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.rule-header {
  display: flex;
  align-items: center;
  gap: 12px;
}

.rule-name {
  font-size: 16px;
  font-weight: 600;
  color: #2c3e50;
  flex: 0 0 auto;
}

.rule-details-inline {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
  color: #6c757d;
  font-size: 13px;
}

.detail-tag {
  display: inline-flex;
  align-items: center;
  padding: 4px 10px;
  background: #f8f9fa;
  border: 1px solid #dee2e6;
  border-radius: 4px;
  font-size: 12px;
  color: #495057;
  white-space: nowrap;
}

.webhook-info {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  color: #495057;
  font-size: 12px;
}

.webhook-tag {
  display: inline-block;
  padding: 3px 8px;
  background: #e3f2fd;
  border: 1px solid #90caf9;
  border-radius: 4px;
  font-size: 12px;
  color: #1976d2;
  font-weight: 500;
}

.legacy-webhook {
  display: inline-block;
  padding: 4px 10px;
  font-size: 12px;
  color: #856404;
  background: #fff3cd;
  border: 1px solid #ffc107;
  border-radius: 4px;
}

.rule-status {
  padding: 4px 12px;
  border-radius: 12px;
  font-size: 12px;
  font-weight: 500;
  white-space: nowrap;
}

.status-enabled {
  background: #d4edda;
  color: #155724;
}

.status-disabled {
  background: #f8d7da;
  color: #721c24;
}

.rule-actions {
  display: flex;
  gap: 8px;
}

/* 状态样式 */
.error-state,
.empty-state {
  text-align: center;
  padding: 60px 20px;
  background: white;
  border-radius: 8px;
}

.error-icon,
.empty-icon {
  font-size: 48px;
  margin-bottom: 16px;
}

.error-state p,
.empty-state p {
  color: #6c757d;
  margin-bottom: 20px;
  font-size: 16px;
}

@media (max-width: 768px) {
  .rule-item {
    flex-direction: column;
    align-items: stretch;
    gap: 16px;
  }

  .rule-header {
    flex-direction: column;
    align-items: flex-start;
    gap: 8px;
  }

  .rule-details-inline {
    flex-direction: column;
    align-items: flex-start;
  }

  .rule-actions {
    justify-content: center;
    flex-wrap: wrap;
  }
}

/* 创建规则表单样式 */
/* 表单样式已由组件内部处理 */

.webhooks-section {
  margin-top: 24px;
  padding-top: 24px;
  border-top: 1px solid #e0e0e0;
}

.section-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 16px;
}

.section-label {
  font-weight: 600;
  color: #333;
  font-size: 16px;
}

.empty-webhooks {
  padding: 20px;
  text-align: center;
  background: #f8f9fa;
  border-radius: 4px;
  color: #6c757d;
}

.webhooks-list {
  display: flex;
  flex-direction: column;
  gap: 20px;
}

.webhook-item {
  padding: 16px;
  background: #f8f9fa;
  border-radius: 8px;
  border: 1px solid #e0e0e0;
}

.webhook-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 16px;
}

.webhook-number {
  font-weight: 600;
  color: #333;
  font-size: 14px;
}

/* Webhook 配置字段样式已移至 WebhookConfigFields 组件 */

/* 默认推送渠道信息 */
.default-webhook-info {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 12px 16px;
  margin-bottom: 16px;
  background: #f0f7ff;
  border: 1px solid #b3d9ff;
  border-radius: 6px;
}

.default-webhook-info .btn {
  margin-left: auto;
  flex-shrink: 0;
}

.info-icon {
  font-size: 20px;
  flex-shrink: 0;
}

.info-content {
  flex: 1;
}

.info-title {
  font-weight: 600;
  color: #333;
  font-size: 14px;
  margin-bottom: 4px;
}

.info-detail {
  color: #666;
  font-size: 13px;
  word-break: break-all;
  margin-bottom: 4px;
}

.info-hint {
  color: #0066cc;
  font-size: 12px;
  margin-top: 4px;
}

/* 默认 webhook 配置提示 */
.default-webhook-notice {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  padding: 12px;
  margin-bottom: 20px;
  background-color: #fff3cd;
  border: 1px solid #ffc107;
  border-radius: 6px;
}

.notice-icon {
  font-size: 18px;
  flex-shrink: 0;
}

.notice-text {
  flex: 1;
  font-size: 13px;
  color: #856404;
  line-height: 1.5;
}

.notice-text strong {
  font-weight: 600;
}

/* 跳过默认通道标识 */
.skip-default-badge {
  display: inline-block;
  padding: 4px 10px;
  background: #fff3cd;
  border: 1px solid #ffc107;
  border-radius: 4px;
  font-size: 12px;
  color: #856404;
  font-weight: 500;
  white-space: nowrap;
}

/* 精确匹配标识 */
.exact-match-badge {
  display: inline-block;
  padding: 4px 10px;
  background: #d1ecf1;
  border: 1px solid #17a2b8;
  border-radius: 4px;
  font-size: 12px;
  color: #0c5460;
  font-weight: 500;
  white-space: nowrap;
}


/* 默认推送渠道配置表单样式已移至 WebhookConfigFields 组件 */
</style>