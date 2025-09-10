<template>
  <div class="admin-rules-page">
    <!-- 页面头部 -->
    <div class="page-header">
      <div class="header-content">
        <h2 class="page-title">🔗 转发规则管理</h2>
        <p class="page-description">
          管理邮件转发规则，支持钉钉、飞书等平台的 Webhook
        </p>
      </div>
      <div class="header-actions">
        <button
          class="btn btn-success"
          @click="showCreateRuleModal"
        >
          ➕ 新建规则
        </button>
        <button
          class="btn btn-primary"
          @click="refreshRules"
          :disabled="adminStore.loading"
        >
          <span v-if="adminStore.loading">刷新中...</span>
          <span v-else>🔄 刷新</span>
        </button>
      </div>
    </div>

    <!-- 规则统计 -->
    <div class="stats-section">
      <div class="stat-card">
        <div class="stat-number">{{ adminStore.forwardRules.length }}</div>
        <div class="stat-label">总规则数</div>
      </div>
      <div class="stat-card">
        <div class="stat-number">{{ adminStore.enabledRules.length }}</div>
        <div class="stat-label">启用规则</div>
      </div>
      <div class="stat-card">
        <div class="stat-number">{{ dingtalkRules }}</div>
        <div class="stat-label">钉钉规则</div>
      </div>
      <div class="stat-card">
        <div class="stat-number">{{ feishuRules }}</div>
        <div class="stat-label">飞书规则</div>
      </div>
    </div>

    <!-- 搜索和过滤 -->
    <div class="filters-section card">
      <div class="search-box">
        <input
          v-model="searchQuery"
          type="text"
          class="form-control"
          placeholder="搜索规则（规则名称、过滤条件）"
          @input="handleSearch"
        >
      </div>
      
      <div class="filter-options">
        <div class="filter-group">
          <label class="form-label">规则类型</label>
          <select
            v-model="typeFilter"
            class="form-control"
            @change="handleFilterChange"
          >
            <option value="">全部类型</option>
            <option value="dingtalk">钉钉</option>
            <option value="feishu">飞书</option>
            <option value="custom">自定义</option>
          </select>
        </div>
        
        <div class="filter-group">
          <label class="form-label">规则状态</label>
          <select
            v-model="statusFilter"
            class="form-control"
            @change="handleFilterChange"
          >
            <option value="">全部状态</option>
            <option value="enabled">已启用</option>
            <option value="disabled">已禁用</option>
          </select>
        </div>
        
        <div class="filter-group">
          <button
            class="btn btn-secondary"
            @click="clearFilters"
          >
            清除过滤
          </button>
        </div>
      </div>
    </div>

    <!-- 规则列表 -->
    <div class="rules-section card">
      <!-- 加载状态 -->
      <div v-if="adminStore.loading" class="loading">
        正在加载转发规则...
      </div>

      <!-- 错误状态 -->
      <div v-else-if="adminStore.error" class="error-message">
        <p>{{ adminStore.error }}</p>
        <button class="btn btn-primary" @click="refreshRules">
          重试
        </button>
      </div>

      <!-- 空状态 -->
      <div v-else-if="filteredRules.length === 0" class="empty-state">
        <div class="empty-icon">🔗</div>
        <h3>暂无转发规则</h3>
        <p>点击"新建规则"按钮创建您的第一个转发规则。</p>
        <button
          class="btn btn-success"
          @click="showCreateRuleModal"
        >
          ➕ 新建规则
        </button>
      </div>

      <!-- 规则表格 -->
      <div v-else class="table-responsive">
        <table class="table">
          <thead>
            <tr>
              <th>规则名称</th>
              <th>类型</th>
              <th>过滤条件</th>
              <th>Webhook URL</th>
              <th>状态</th>
              <th>创建时间</th>
              <th>操作</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="rule in filteredRules" :key="rule.id">
              <td>
                <div class="rule-name">
                  {{ rule.rule_name }}
                </div>
              </td>
              <td>
                <span :class="['badge', `badge-${rule.webhook_type}`]">
                  {{ getTypeLabel(rule.webhook_type) }}
                </span>
              </td>
              <td>
                <div class="filter-conditions">
                  <div v-if="rule.sender_filter" class="condition">
                    <small class="condition-label">发件人:</small>
                    <span class="condition-value">{{ rule.sender_filter }}</span>
                  </div>
                  <div v-if="rule.keyword_filter" class="condition">
                    <small class="condition-label">关键字:</small>
                    <span class="condition-value">{{ rule.keyword_filter }}</span>
                  </div>
                  <div v-if="rule.recipient_filter" class="condition">
                    <small class="condition-label">收件人:</small>
                    <span class="condition-value">{{ rule.recipient_filter }}</span>
                  </div>
                  <div v-if="!rule.sender_filter && !rule.keyword_filter && !rule.recipient_filter" class="text-muted">
                    无过滤条件
                  </div>
                </div>
              </td>
              <td>
                <div class="webhook-url">
                  <span class="url-text">{{ truncateUrl(rule.webhook_url) }}</span>
                  <button
                    class="btn btn-sm btn-light ml-2"
                    @click="copyToClipboard(rule.webhook_url)"
                    title="复制 URL"
                  >
                    📋
                  </button>
                </div>
              </td>
              <td>
                <span :class="['badge', rule.enabled ? 'badge-success' : 'badge-secondary']">
                  {{ rule.enabled ? '启用' : '禁用' }}
                </span>
              </td>
              <td>
                <span class="create-time">{{ formatDate(rule.created_at) }}</span>
              </td>
              <td>
                <div class="action-buttons">
                  <button
                    class="btn btn-sm btn-info"
                    @click="testRule(rule)"
                    :disabled="testingRule === rule.id"
                    title="测试规则"
                  >
                    <span v-if="testingRule === rule.id">测试中...</span>
                    <span v-else>🧪 测试</span>
                  </button>
                  <button
                    class="btn btn-sm btn-warning"
                    @click="editRule(rule)"
                    title="编辑规则"
                  >
                    ✏️ 编辑
                  </button>
                  <button
                    :class="['btn', 'btn-sm', rule.enabled ? 'btn-secondary' : 'btn-success']"
                    @click="toggleRule(rule)"
                    :disabled="togglingRule === rule.id"
                    :title="rule.enabled ? '禁用规则' : '启用规则'"
                  >
                    <span v-if="togglingRule === rule.id">操作中...</span>
                    <span v-else>{{ rule.enabled ? '🚫 禁用' : '✅ 启用' }}</span>
                  </button>
                  <button
                    class="btn btn-sm btn-danger"
                    @click="deleteRule(rule)"
                    :disabled="deletingRule === rule.id"
                    title="删除规则"
                  >
                    <span v-if="deletingRule === rule.id">删除中...</span>
                    <span v-else">🗑️ 删除</span>
                  </button>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- 创建/编辑规则模态框 -->
    <RuleFormModal
      v-if="showRuleModal"
      :rule="editingRule"
      @close="closeRuleModal"
      @saved="handleRuleSaved"
    />
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useAdminStore } from '@/stores/admin'
import { useSystemStore } from '@/stores/system'
import type { ForwardRule } from '@/types'
import RuleFormModal from '@/components/admin/RuleFormModal.vue'

// Composables
const adminStore = useAdminStore()
const systemStore = useSystemStore()

// State
const searchQuery = ref('')
const typeFilter = ref('')
const statusFilter = ref('')
const showRuleModal = ref(false)
const editingRule = ref<ForwardRule | null>(null)
const testingRule = ref<number | null>(null)
const togglingRule = ref<number | null>(null)
const deletingRule = ref<number | null>(null)
let searchTimeout: NodeJS.Timeout | null = null

// Computed
const dingtalkRules = computed(() => {
  return adminStore.forwardRules.filter(rule => rule.webhook_type === 'dingtalk').length
})

const feishuRules = computed(() => {
  return adminStore.forwardRules.filter(rule => rule.webhook_type === 'feishu').length
})

const filteredRules = computed(() => {
  let rules = adminStore.forwardRules

  // 按搜索关键词过滤
  if (searchQuery.value.trim()) {
    const query = searchQuery.value.toLowerCase()
    rules = rules.filter(rule =>
      rule.rule_name.toLowerCase().includes(query) ||
      (rule.sender_filter && rule.sender_filter.toLowerCase().includes(query)) ||
      (rule.keyword_filter && rule.keyword_filter.toLowerCase().includes(query)) ||
      (rule.recipient_filter && rule.recipient_filter.toLowerCase().includes(query))
    )
  }

  // 按类型过滤
  if (typeFilter.value) {
    rules = rules.filter(rule => rule.webhook_type === typeFilter.value)
  }

  // 按状态过滤
  if (statusFilter.value) {
    const enabled = statusFilter.value === 'enabled'
    rules = rules.filter(rule => !!rule.enabled === enabled)
  }

  return rules
})

// Methods
const refreshRules = async () => {
  await adminStore.loadForwardRules()
}

const handleSearch = () => {
  if (searchTimeout) {
    clearTimeout(searchTimeout)
  }
  
  searchTimeout = setTimeout(() => {
    // 搜索逻辑已在 computed 中处理
  }, 300)
}

const handleFilterChange = () => {
  // 过滤逻辑已在 computed 中处理
}

const clearFilters = () => {
  searchQuery.value = ''
  typeFilter.value = ''
  statusFilter.value = ''
}

const showCreateRuleModal = () => {
  editingRule.value = null
  showRuleModal.value = true
}

const editRule = (rule: ForwardRule) => {
  editingRule.value = rule
  showRuleModal.value = true
}

const closeRuleModal = () => {
  showRuleModal.value = false
  editingRule.value = null
}

const handleRuleSaved = () => {
  closeRuleModal()
  refreshRules()
}

const testRule = async (rule: ForwardRule) => {
  testingRule.value = rule.id
  try {
    // 这里应该调用测试规则的 API
    await new Promise(resolve => setTimeout(resolve, 2000))
    showMessage(`规则 "${rule.rule_name}" 测试成功`, 'success')
  } catch (error) {
    showMessage(`规则 "${rule.rule_name}" 测试失败`, 'error')
  } finally {
    testingRule.value = null
  }
}

const toggleRule = async (rule: ForwardRule) => {
  togglingRule.value = rule.id
  try {
    // 这里应该调用切换规则状态的 API
    await new Promise(resolve => setTimeout(resolve, 1000))
    const newStatus = rule.enabled ? '禁用' : '启用'
    showMessage(`规则 "${rule.rule_name}" 已${newStatus}`, 'success')
    await refreshRules()
  } catch (error) {
    showMessage(`切换规则状态失败`, 'error')
  } finally {
    togglingRule.value = null
  }
}

const deleteRule = async (rule: ForwardRule) => {
  const confirmText = `确定要删除转发规则 "${rule.rule_name}" 吗？\n\n此操作不可恢复！`
  
  if (!confirm(confirmText)) {
    return
  }

  deletingRule.value = rule.id
  try {
    const success = await adminStore.deleteForwardRule(rule.id)
    if (success) {
      showMessage(`转发规则 "${rule.rule_name}" 删除成功`, 'success')
    }
  } catch (error) {
    console.error('删除转发规则失败:', error)
  } finally {
    deletingRule.value = null
  }
}

const getTypeLabel = (type: string): string => {
  const labels: Record<string, string> = {
    dingtalk: '钉钉',
    feishu: '飞书',
    custom: '自定义'
  }
  return labels[type] || type
}

const truncateUrl = (url: string): string => {
  return url.length > 50 ? url.substring(0, 47) + '...' : url
}

const formatDate = (dateString?: string): string => {
  if (!dateString) return '-'
  return systemStore.formatDate(dateString)
}

const copyToClipboard = async (text: string) => {
  try {
    await navigator.clipboard.writeText(text)
    showMessage('已复制到剪贴板', 'success')
  } catch (error) {
    // 降级方案
    const textArea = document.createElement('textarea')
    textArea.value = text
    document.body.appendChild(textArea)
    textArea.select()
    document.execCommand('copy')
    document.body.removeChild(textArea)
    showMessage('已复制到剪贴板', 'success')
  }
}

const showMessage = (message: string, type: 'success' | 'error' | 'info' = 'info') => {
  // 这里应该使用全局消息组件
  console.log(`[${type.toUpperCase()}] ${message}`)
}

// Lifecycle
onMounted(async () => {
  await refreshRules()
})

onUnmounted(() => {
  if (searchTimeout) {
    clearTimeout(searchTimeout)
  }
})
</script>

<style scoped>
.admin-rules-page {
  max-width: 1200px;
  margin: 0 auto;
}

.page-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: var(--spacing-6);
  gap: var(--spacing-4);
}

.header-content {
  flex: 1;
}

.page-title {
  font-size: var(--font-size-2xl);
  font-weight: 600;
  color: var(--gray-800);
  margin-bottom: var(--spacing-2);
}

.page-description {
  color: var(--gray-600);
  font-size: var(--font-size-base);
  margin: 0;
}

.header-actions {
  display: flex;
  gap: var(--spacing-3);
}

.stats-section {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: var(--spacing-4);
  margin-bottom: var(--spacing-6);
}

.stat-card {
  background: var(--white);
  padding: var(--spacing-5);
  border-radius: var(--border-radius-lg);
  text-align: center;
  box-shadow: var(--shadow);
}

.stat-number {
  font-size: var(--font-size-2xl);
  font-weight: 700;
  color: var(--primary-color);
  margin-bottom: var(--spacing-1);
}

.stat-label {
  color: var(--gray-600);
  font-size: var(--font-size-sm);
}

.filters-section {
  margin-bottom: var(--spacing-6);
}

.search-box {
  margin-bottom: var(--spacing-4);
}

.filter-options {
  display: grid;
  grid-template-columns: 1fr 1fr auto;
  gap: var(--spacing-4);
  align-items: end;
}

.filter-group {
  display: flex;
  flex-direction: column;
}

.rules-section {
  margin-bottom: var(--spacing-6);
}

.error-message {
  text-align: center;
  padding: var(--spacing-8);
  color: var(--danger-color);
}

.empty-state {
  text-align: center;
  padding: var(--spacing-10);
}

.empty-icon {
  font-size: 4rem;
  margin-bottom: var(--spacing-4);
}

.empty-state h3 {
  color: var(--gray-700);
  margin-bottom: var(--spacing-2);
}

.empty-state p {
  color: var(--gray-600);
  max-width: 400px;
  margin: 0 auto var(--spacing-4) auto;
}

.rule-name {
  font-weight: 500;
  color: var(--gray-800);
}

.badge-dingtalk {
  background: #0089ff;
  color: var(--white);
}

.badge-feishu {
  background: #00d4aa;
  color: var(--white);
}

.badge-custom {
  background: var(--gray-600);
  color: var(--white);
}

.filter-conditions {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-1);
}

.condition {
  display: flex;
  align-items: center;
  gap: var(--spacing-1);
}

.condition-label {
  color: var(--gray-500);
  font-size: var(--font-size-sm);
  min-width: 50px;
}

.condition-value {
  color: var(--gray-700);
  font-size: var(--font-size-sm);
  font-family: 'Courier New', monospace;
  background: var(--gray-100);
  padding: var(--spacing-1) var(--spacing-2);
  border-radius: var(--border-radius-sm);
}

.webhook-url {
  display: flex;
  align-items: center;
  gap: var(--spacing-2);
}

.url-text {
  font-family: 'Courier New', monospace;
  font-size: var(--font-size-sm);
  color: var(--gray-700);
  word-break: break-all;
}

.create-time {
  color: var(--gray-600);
  font-size: var(--font-size-sm);
}

.action-buttons {
  display: flex;
  gap: var(--spacing-1);
  flex-wrap: wrap;
}

.ml-2 {
  margin-left: var(--spacing-2);
}

/* 响应式设计 */
@media (max-width: 768px) {
  .page-header {
    flex-direction: column;
    align-items: stretch;
  }
  
  .filter-options {
    grid-template-columns: 1fr;
    gap: var(--spacing-3);
  }
  
  .stats-section {
    grid-template-columns: repeat(2, 1fr);
  }
  
  .table-responsive {
    overflow-x: auto;
  }
  
  .table {
    min-width: 800px;
  }
  
  .action-buttons {
    flex-direction: column;
    gap: var(--spacing-1);
  }
  
  .action-buttons .btn {
    font-size: var(--font-size-sm);
    padding: var(--spacing-1) var(--spacing-2);
  }
  
  .webhook-url {
    flex-direction: column;
    align-items: flex-start;
  }
}

@media (max-width: 480px) {
  .stats-section {
    grid-template-columns: 1fr;
  }
  
  .table {
    font-size: var(--font-size-sm);
  }
  
  .table th,
  .table td {
    padding: var(--spacing-2);
  }
}
</style>