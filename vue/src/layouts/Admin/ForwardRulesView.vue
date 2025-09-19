<template>
  <div class="forward-rules-page">
    <div class="page-header">
      <h1>🔄 转发规则</h1>
    </div>

    <div class="forward-rules-content">
      <LoadingOverlay :show="loading" text="加载转发规则..." type="local" />

      <div v-if="!loading && rules.length === 0" class="empty-state">
        <div class="empty-icon">🔄</div>
        <p>暂无转发规则</p>
      </div>

      <div v-if="!loading && rules.length > 0" class="rules-list">
        <div v-for="rule in rules" :key="rule.id" class="rule-item">
          <div class="rule-info">
            <div class="rule-name">{{ rule.name }}</div>
            <div class="rule-description">{{ rule.description }}</div>
            <div class="rule-status">
              <span class="status-badge" :class="rule.enabled ? 'status-enabled' : 'status-disabled'">
                {{ rule.enabled ? '已启用' : '已禁用' }}
              </span>
            </div>
          </div>
          <div class="rule-actions">
            <button class="btn btn-primary btn-sm" @click="editRule(rule.id)">编辑</button>
            <button class="btn btn-danger btn-sm" @click="deleteRule(rule.id)">删除</button>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import LoadingOverlay from '@/layouts/AppLoadingSpinner.vue'

const rules = ref<any[]>([])
const loading = ref(false)

const loadRules = async () => {
  loading.value = true
  try {
    // 这里可以调用 API 加载转发规则
    // const response = await apiService.getForwardRules()
    // if (response.success && response.data) {
    //   rules.value = response.data.items
    // }
  } catch (error) {
    console.error('加载转发规则失败:', error)
  } finally {
    loading.value = false
  }
}

const editRule = (ruleId: string) => {
  // 编辑规则逻辑
  console.log('编辑规则:', ruleId)
}

const deleteRule = (ruleId: string) => {
  // 删除规则逻辑
  console.log('删除规则:', ruleId)
}

onMounted(() => {
  loadRules()
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
}

.page-header h1 {
  margin: 0;
  color: #2c3e50;
  font-size: 24px;
  font-weight: 600;
}

.forward-rules-content {
  position: relative;
  min-height: 200px;
}

.empty-state {
  text-align: center;
  padding: 40px;
  color: #6c757d;
}

.empty-icon {
  font-size: 48px;
  margin-bottom: 15px;
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
</style>