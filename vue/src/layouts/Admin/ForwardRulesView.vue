<template>
  <div class="forward-rules-page">
    <div class="page-header">
      <h1>{{ pageIcon }} {{ pageTitle }}</h1>
      <div class="page-actions">
        <button class="btn btn-primary btn-sm" @click="createRule">
          ➕ 新建规则
        </button>
      </div>
    </div>

    <!-- 搜索栏 -->
    <div class="search-section">
      <div class="search-box">
        <input v-model="searchKeyword" type="text" placeholder="搜索规则名称或描述..." class="form-control"
          @keyup.enter="() => handleSearch(searchKeyword)" />
        <button class="btn btn-primary" @click="() => handleSearch(searchKeyword)">
          🔍 搜索
        </button>
      </div>
    </div>

    <div class="forward-rules-content">
      <!-- 加载状态 -->
      <LoadingOverlay v-if="loading" :show="true" text="加载转发规则..." type="local" />

      <!-- 错误状态 -->
      <div v-else-if="error" class="error-state">
        <div class="error-icon">❌</div>
        <p>{{ error }}</p>
        <button class="btn btn-primary" @click="loadData(true)">重试</button>
      </div>

      <!-- 空状态 -->
      <div v-else-if="!hasRules" class="empty-state">
        <div class="empty-icon">🔄</div>
        <p>{{ searchKeyword ? '没有找到匹配的规则' : '暂无转发规则' }}</p>
        <button v-if="searchKeyword" class="btn btn-secondary"
          @click="() => { setSearchKeyword(''); handleSearch('') }">
          清除搜索
        </button>
        <button v-else class="btn btn-primary" @click="createRule">
          创建第一个规则
        </button>
      </div>

      <!-- 规则列表 -->
      <div v-else class="rules-list">
        <div v-for="rule in rules" :key="rule.id" class="rule-item">
          <div class="rule-info">
            <div class="rule-name">{{ rule.name }}</div>
            <div class="rule-description">{{ rule.description }}</div>
            <div class="rule-details">
              <div class="rule-source">
                <strong>源邮箱:</strong> {{ rule.source_email }}
              </div>
              <div class="rule-target">
                <strong>目标邮箱:</strong> {{ rule.target_email }}
              </div>
            </div>
            <div class="rule-status">
              <span class="status-badge" :class="rule.enabled ? 'status-enabled' : 'status-disabled'">
                {{ rule.enabled ? '已启用' : '已禁用' }}
              </span>
            </div>
          </div>
          <div class="rule-actions">
            <button class="btn btn-warning btn-sm" @click="toggleRule(rule.id, !rule.enabled)">
              {{ rule.enabled ? '禁用' : '启用' }}
            </button>
            <button class="btn btn-primary btn-sm" @click="editRule(rule.id)">
              ✏️ 编辑
            </button>
            <button class="btn btn-danger btn-sm" @click="deleteRule(rule.id)">
              🗑️ 删除
            </button>
          </div>
        </div>
      </div>

      <!-- 分页信息 -->
      <div v-if="!loading && !error && hasRules" class="pagination-info">
        <p>共 {{ total }} 个规则，当前第 {{ currentPage }} 页</p>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useRoute } from 'vue-router'
import LoadingOverlay from '@/layouts/AppLoadingSpinner.vue'
import { adminApiService } from '@/composables/api'

const route = useRoute()
const routeName = computed(() => route.name as string)

// 简单的响应式数据 - 不用煞笔的 useSimplePageData
const rulesResponse = ref(null)
const loading = ref(false)
const error = ref(null)
const searchKeyword = ref('')

// 页面信息
const pageTitle = computed(() => '转发管理')
const pageIcon = computed(() => '🔄')

// 提取数据
const rules = computed(() => rulesResponse.value?.items || [])
const total = computed(() => rulesResponse.value?.total || 0)
const currentPage = ref(1)

// 加载数据
const loadData = async (forceRefresh = false) => {
  if (loading.value) return

  loading.value = true
  error.value = null
  try {
    const params = {
      page: currentPage.value,
      pageSize: 20,
      scope: 'all',
      search: searchKeyword.value || undefined
    }

    const response = await adminApiService.getForwardRules(params)
    rulesResponse.value = response
  } catch (err) {
    console.error('加载转发规则失败:', err)
    error.value = '加载转发规则失败'
  } finally {
    loading.value = false
  }
}

// 搜索处理
const handleSearch = (query: string) => {
  searchKeyword.value = query
  currentPage.value = 1
  loadData(true)
}

// 设置搜索关键词
const setSearchKeyword = (keyword: string) => {
  searchKeyword.value = keyword
}

// 初始化
onMounted(() => {
  loadData()
})

// 暴露刷新方法给全局刷新按钮使用
const refreshData = () => {
  loadData(true)
}

// 注册到全局，让MainLayoutView的刷新按钮能调用
window.refreshCurrentPage = refreshData

// 计算属性
const hasRules = computed(() => rules.value && rules.value.length > 0)

// 创建规则
const createRule = () => {
  console.log('创建新规则')
  // TODO: 实现创建规则功能
}

// 编辑规则
const editRule = (ruleId: string) => {
  console.log('编辑规则:', ruleId)
  // TODO: 实现编辑规则功能
}

// 删除规则
const deleteRule = async (ruleId: string) => {
  if (!confirm('确定要删除这个转发规则吗？此操作不可撤销。')) {
    return
  }

  try {
    const response = await adminApiService.deleteForwardRule(parseInt(ruleId))
    if (response.success) {
      // 删除成功后刷新列表
      await loadData(true)
      console.log('规则删除成功')
    } else {
      console.error('删除规则失败:', response.message)
    }
  } catch (error) {
    console.error('删除规则失败:', error)
  }
}

// 切换规则状态
const toggleRule = async (ruleId: string, enabled: boolean) => {
  try {
    const response = await adminApiService.updateForwardRule(parseInt(ruleId), { enabled })
    if (response.success) {
      // 更新成功后刷新列表
      await loadData(true)
      console.log(`规则${enabled ? '启用' : '禁用'}成功`)
    } else {
      console.error('更新规则状态失败:', response.message)
    }
  } catch (error) {
    console.error('更新规则状态失败:', error)
  }
}

// 页面初始化
onMounted(() => {
  loadData()
})
</script>

<style scoped>
.forward-rules-page {
  padding: 20px;
  background: #f8f9fa;
  min-height: 100%;
}

.page-header {
  margin-bottom: 20px;
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.page-header h1 {
  margin: 0;
  color: #2c3e50;
  font-size: 24px;
  font-weight: 600;
}

.page-actions {
  display: flex;
  gap: 10px;
}

.search-section {
  margin-bottom: 20px;
}

.search-box {
  display: flex;
  gap: 10px;
  max-width: 400px;
}

.search-box .form-control {
  flex: 1;
}

.forward-rules-content {
  position: relative;
  min-height: 200px;
}

.empty-state,
.error-state {
  text-align: center;
  padding: 40px;
  color: #6c757d;
}

.empty-icon,
.error-icon {
  font-size: 48px;
  margin-bottom: 15px;
}

.error-state {
  color: #dc3545;
}

.rules-list {
  display: flex;
  flex-direction: column;
  gap: 15px;
}

.rule-item {
  background: white;
  border-radius: 10px;
  padding: 20px;
  box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.rule-info {
  flex: 1;
}

.rule-name {
  font-weight: 500;
  color: #2c3e50;
  font-size: 16px;
  margin-bottom: 5px;
}

.rule-description {
  color: #6c757d;
  font-size: 14px;
  margin-bottom: 10px;
}

.rule-details {
  margin-bottom: 10px;
  font-size: 13px;
  color: #495057;
}

.rule-source,
.rule-target {
  margin-bottom: 5px;
}

.rule-status {
  display: flex;
  align-items: center;
  gap: 10px;
}

.status-badge {
  padding: 4px 8px;
  border-radius: 12px;
  font-size: 12px;
  font-weight: 500;
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
  gap: 10px;
}

.btn {
  padding: 6px 12px;
  border: none;
  border-radius: 5px;
  font-size: 12px;
  cursor: pointer;
  transition: all 0.3s;
  font-weight: 500;
}

.btn-primary {
  background: #3498db;
  color: white;
}

.btn-primary:hover {
  background: #2980b9;
}

.btn-danger {
  background: #e74c3c;
  color: white;
}

.btn-danger:hover {
  background: #c0392b;
}

.btn-sm {
  padding: 4px 8px;
  font-size: 11px;
}

.btn-warning {
  background: #ffc107;
  color: #212529;
}

.btn-warning:hover {
  background: #e0a800;
}

.pagination-info {
  text-align: center;
  padding: 20px;
  color: #6c757d;
  font-size: 14px;
}
</style>