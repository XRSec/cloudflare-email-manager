<template>
  <div class="admin-page">
    <div class="page-header">
      <h1>{{ pageIcon }} {{ pageTitle }}</h1>
    </div>

    <div class="page-content">
      <LoadingOverlay v-if="loading" text="加载系统配置..." />

      <div v-if="!loading" class="settings-container">
        <!-- 基本设置 -->
        <div class="settings-section">
          <h3>基本设置</h3>

          <div class="form-group">
            <div class="form-switch">
              <label class="form-label">调试模式</label>
              <label class="switch">
                <input v-model="systemConfig.debug_mode" type="checkbox">
                <span class="slider"></span>
              </label>
            </div>
          </div>

          <div class="form-group">
            <div class="form-switch">
              <label class="form-label">允许注册</label>
              <label class="switch">
                <input v-model="systemConfig.allow_registration" type="checkbox">
                <span class="slider"></span>
              </label>
            </div>
          </div>

          <div class="form-group">
            <div class="form-switch">
              <label class="form-label">自动审核邮箱</label>
              <label class="switch">
                <input v-model="systemConfig.auto_approve_mailbox" type="checkbox">
                <span class="slider"></span>
              </label>
            </div>
          </div>
        </div>

        <!-- 邮箱设置 -->
        <div class="settings-section">
          <h3>邮箱设置</h3>

          <div class="form-group">
            <label class="form-label">支持的域名</label>
            <div class="form-tags">
              <div v-for="(domain, index) in systemConfig.supported_domains" :key="index" class="tag">
                {{ domain }}
                <button type="button" class="tag-remove" @click="removeDomain(index)">×</button>
              </div>
              <input v-model="newDomain" type="text" class="form-control tag-input" placeholder="添加域名..."
                @keyup.enter="addDomain">
            </div>
          </div>

          <div class="form-group">
            <label class="form-label">邮件保留天数</label>
            <input v-model.number="systemConfig.mail_retention_days" type="number" class="form-control" min="1"
              max="365">
          </div>

          <div class="form-group">
            <label class="form-label">附件最大大小 (MB)</label>
            <input v-model.number="systemConfig.attachment_max_size" type="number" class="form-control" min="1"
              max="50">
          </div>
        </div>

        <!-- 操作按钮 -->
        <div class="settings-actions">
          <button class="btn btn-primary" @click="saveSettings" :disabled="loading">
            {{ loading ? '保存中...' : '保存设置' }}
          </button>
          <button class="btn btn-secondary" @click="resetSettings" :disabled="loading">
            重置
          </button>
          <button class="btn btn-warning" @click="clearCache" :disabled="loading">
            清除缓存
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { apiService } from '@/composables/api'
import { cacheService } from '@/composables/cache'
import LoadingOverlay from '@/layouts/AppLoadingSpinner.vue'

// 直接使用 API 加载数据
const systemConfig = ref({
  debug_mode: false,
  allow_registration: false,
  auto_approve_mailbox: false,
  supported_domains: [] as string[],
  mail_retention_days: 30,
  attachment_max_size: 10
})

const loading = ref(false)
const pageTitle = '🛠️ 系统设置'
const pageIcon = '🛠️'

// 加载系统配置
const loadSystemConfig = async (forceRefresh = false) => {
  loading.value = true
  try {
    const cacheKey = 'system-config'

    // 检查缓存
    if (!forceRefresh) {
      const cached = cacheService.get<typeof systemConfig.value>(cacheKey)
      if (cached) {
        console.log('从缓存加载系统配置')
        systemConfig.value = cached
        loading.value = false
        return
      }
    }

    // 从API获取
    console.log('从API加载系统配置')
    const response = await apiService.getSystemConfig()
    if (response.success && response.data) {
      const config = {
        debug_mode: response.data.debug_mode || false,
        allow_registration: response.data.allow_registration || false,
        auto_approve_mailbox: response.data.auto_approve_mailbox || false,
        supported_domains: response.data.supported_domains || [],
        mail_retention_days: response.data.mail_retention_days || 30,
        attachment_max_size: response.data.attachment_max_size || 10
      }

      systemConfig.value = config

      // 存入缓存（5分钟）
      cacheService.set(cacheKey, config, 5 * 60 * 1000)
    }
  } catch (error) {
    console.error('加载系统配置失败:', error)
  } finally {
    loading.value = false
  }
}

// 刷新数据
const refreshData = async () => {
  await loadSystemConfig(true)
}

// 页面加载时获取数据
onMounted(() => {
  loadSystemConfig()
})

// 新域名输入
const newDomain = ref('')

// 添加域名
const addDomain = () => {
  const domain = newDomain.value.trim()
  if (domain && !systemConfig.value.supported_domains.includes(domain)) {
    systemConfig.value.supported_domains.push(domain)
    newDomain.value = ''
  }
}

// 删除域名
const removeDomain = (index: number) => {
  systemConfig.value.supported_domains.splice(index, 1)
}

// 保存设置
const saveSettings = async () => {
  try {
    const response = await apiService.updateSystemConfig(systemConfig.value)
    if (response.success) {
      alert('设置保存成功')
      await refreshData()
    } else {
      alert('保存失败: ' + (response.message || '未知错误'))
    }
  } catch (error) {
    console.error('保存设置失败:', error)
    alert('保存设置失败')
  }
}

// 重置设置
const resetSettings = async () => {
  if (confirm('确定要重置所有设置吗？')) {
    await refreshData()
  }
}

// 清除缓存
const clearCache = async () => {
  try {
    const response = await apiService.clearSystemCache()
    if (response.success) {
      alert('缓存清除成功')
    } else {
      alert('清除缓存失败: ' + (response.message || '未知错误'))
    }
  } catch (error) {
    console.error('清除缓存失败:', error)
    alert('清除缓存失败')
  }
}
</script>

<style scoped>
.settings-container {
  max-width: 800px;
  margin: 0 auto;
}

.settings-section {
  background: white;
  border-radius: 10px;
  padding: 20px;
  margin-bottom: 20px;
  box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
}

.settings-section h3 {
  margin: 0 0 20px 0;
  color: #2c3e50;
  font-size: 1.2rem;
  border-bottom: 2px solid #ecf0f1;
  padding-bottom: 10px;
}

.form-group {
  margin-bottom: 20px;
}

.form-label {
  display: block;
  margin-bottom: 8px;
  font-weight: 500;
  color: #2c3e50;
}

.form-switch {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 15px;
}

.form-label {
  flex: 1;
}

.switch {
  position: relative;
  display: inline-block;
  width: 50px;
  height: 24px;
  flex-shrink: 0;
}

.switch input {
  opacity: 0;
  width: 0;
  height: 0;
}

.slider {
  position: absolute;
  cursor: pointer;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background-color: #ccc;
  transition: .4s;
  border-radius: 24px;
}

.slider:before {
  position: absolute;
  content: "";
  height: 18px;
  width: 18px;
  left: 3px;
  bottom: 3px;
  background-color: white;
  transition: .4s;
  border-radius: 50%;
}

input:checked+.slider {
  background-color: #3498db;
}

input:checked+.slider:before {
  transform: translateX(26px);
}

.form-control {
  width: 100%;
  padding: 10px;
  border: 1px solid #ddd;
  border-radius: 5px;
  font-size: 14px;
}

.form-control:focus {
  outline: none;
  border-color: #3498db;
  box-shadow: 0 0 0 2px rgba(52, 152, 219, 0.2);
}

.form-tags {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  align-items: center;
  padding: 10px;
  border: 1px solid #ddd;
  border-radius: 5px;
  min-height: 40px;
}

.tag {
  display: inline-flex;
  align-items: center;
  background: #3498db;
  color: white;
  padding: 4px 8px;
  border-radius: 12px;
  font-size: 12px;
  gap: 4px;
}

.tag-remove {
  background: none;
  border: none;
  color: white;
  cursor: pointer;
  font-size: 16px;
  line-height: 1;
  padding: 0;
  margin-left: 4px;
}

.tag-input {
  border: none;
  outline: none;
  flex: 1;
  min-width: 120px;
  padding: 4px;
}

.settings-actions {
  display: flex;
  gap: 10px;
  justify-content: flex-end;
  margin-top: 20px;
}

/* 按钮样式已移至全局样式，这里只保留SettingsView特有的样式 */
.btn:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}
</style>
