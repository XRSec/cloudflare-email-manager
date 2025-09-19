<template>
  <div class="settings-page">
    <div class="page-header">
      <h1>⚙️ 账户设置</h1>
    </div>

    <div class="settings-content">
      <LoadingOverlay :show="loading" text="加载设置..." type="local" />

      <div v-if="!loading" class="settings-form">
        <div class="form-section">
          <h2>个人信息</h2>
          <div class="form-group">
            <label class="form-label">用户名</label>
            <input v-model="userInfo.username" type="text" class="form-control" disabled>
          </div>
          <div class="form-group">
            <label class="form-label">邮箱</label>
            <input v-model="userInfo.email" type="email" class="form-control" disabled>
          </div>
          <div class="form-group">
            <label class="form-label">用户类型</label>
            <input v-model="userInfo.user_type" type="text" class="form-control" disabled>
          </div>
        </div>

        <div class="form-section">
          <h2>Webhook 设置</h2>
          <div class="form-group">
            <label class="form-label">Webhook URL</label>
            <input v-model="webhookSettings.webhook_url" type="url" class="form-control"
              placeholder="https://hooks.slack.com/services/xxx">
            <small class="form-text">用于接收邮件通知的 Webhook 地址</small>
          </div>
          <div class="form-group">
            <label class="form-label">Webhook 密钥</label>
            <input v-model="webhookSettings.webhook_secret" type="password" class="form-control"
              placeholder="可选，用于验证 Webhook 请求">
            <small class="form-text">用于验证 Webhook 请求的密钥（可选）</small>
          </div>
        </div>

        <div class="form-section">
          <h2>安全设置</h2>
          <div class="form-group">
            <label class="form-label">当前密码</label>
            <input v-model="passwordForm.currentPassword" type="password" class="form-control" placeholder="输入当前密码">
          </div>
          <div class="form-group">
            <label class="form-label">新密码</label>
            <input v-model="passwordForm.newPassword" type="password" class="form-control" placeholder="输入新密码">
          </div>
          <div class="form-group">
            <label class="form-label">确认新密码</label>
            <input v-model="passwordForm.confirmPassword" type="password" class="form-control" placeholder="再次输入新密码">
          </div>
        </div>

        <div class="form-actions">
          <button class="btn btn-primary" @click="saveSettings" :disabled="saving">
            {{ saving ? '保存中...' : '保存设置' }}
          </button>
          <button class="btn btn-secondary" @click="resetForm">重置</button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useAuthStore } from '@/composables/stores'
import { apiService } from '@/composables/api'
import LoadingOverlay from '@/layouts/AppLoadingSpinner.vue'

const authStore = useAuthStore()
const loading = ref(false)
const saving = ref(false)

const userInfo = ref({
  username: authStore.user?.username || '',
  email: authStore.user?.email || '',
  user_type: authStore.user?.user_type || ''
})

const webhookSettings = ref({
  webhook_url: authStore.user?.settings?.webhook_url || '',
  webhook_secret: authStore.user?.settings?.webhook_secret || ''
})

const passwordForm = ref({
  currentPassword: '',
  newPassword: '',
  confirmPassword: ''
})

const loadSettings = async () => {
  loading.value = true
  try {
    // 调用 API 获取用户详细信息
    const response = await apiService.getUserProfile()
    if (response.success && response.data) {
      userInfo.value = {
        username: response.data.username,
        email: response.data.email,
        user_type: response.data.user_type
      }
      webhookSettings.value = {
        webhook_url: response.data.settings?.webhook_url || '',
        webhook_secret: response.data.settings?.webhook_secret || ''
      }
    }
  } catch (error) {
    console.error('加载设置失败:', error)
  } finally {
    debugger
    loading.value = false
  }
}

const saveSettings = async () => {
  saving.value = true
  try {
    // 验证密码表单
    if (passwordForm.value.newPassword && passwordForm.value.newPassword !== passwordForm.value.confirmPassword) {
      alert('新密码和确认密码不匹配')
      return
    }

    // 准备更新数据
    const updateData: any = {}

    // 如果有新密码，添加密码更新
    if (passwordForm.value.newPassword) {
      updateData.password = passwordForm.value.newPassword
    }

    // 添加 Webhook 设置
    updateData.webhook_url = webhookSettings.value.webhook_url
    updateData.webhook_secret = webhookSettings.value.webhook_secret

    // 调用 API 更新用户设置
    const response = await apiService.updateUserSettings(updateData)
    if (response.success) {
      alert('设置保存成功！')
      // 清空密码表单
      passwordForm.value = {
        currentPassword: '',
        newPassword: '',
        confirmPassword: ''
      }
    } else {
      alert('保存失败：' + (response.message || '未知错误'))
    }
  } catch (error) {
    console.error('保存设置失败:', error)
    alert('保存失败：' + (error as Error).message)
  } finally {
    saving.value = false
  }
}

const resetForm = () => {
  userInfo.value = {
    username: authStore.user?.username || '',
    email: authStore.user?.email || '',
    user_type: authStore.user?.user_type || ''
  }
  webhookSettings.value = {
    webhook_url: authStore.user?.settings?.webhook_url || '',
    webhook_secret: authStore.user?.settings?.webhook_secret || ''
  }
  passwordForm.value = {
    currentPassword: '',
    newPassword: '',
    confirmPassword: ''
  }
}

onMounted(() => {
  loadSettings()
})
</script>

<style scoped>
.settings-page {
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

.settings-content {
  position: relative;
  min-height: 200px;
}

.settings-form {
  background: white;
  border-radius: 10px;
  padding: 30px;
  box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
}

.form-section {
  margin-bottom: 30px;
}

.form-section h2 {
  margin: 0 0 20px 0;
  color: #2c3e50;
  font-size: 18px;
  font-weight: 600;
}

.form-group {
  margin-bottom: 20px;
}

.form-label {
  display: block;
  margin-bottom: 5px;
  font-weight: 500;
  color: #555;
}

.form-control {
  width: 100%;
  padding: 10px;
  border: 1px solid #ddd;
  border-radius: 5px;
  font-size: 14px;
  transition: border-color 0.3s;
}

.form-control:focus {
  outline: none;
  border-color: #3498db;
  box-shadow: 0 0 0 3px rgba(52, 152, 219, 0.1);
}

.form-control:disabled {
  background-color: #f8f9fa;
  color: #6c757d;
}

.form-actions {
  display: flex;
  gap: 10px;
  justify-content: flex-end;
}

.btn {
  padding: 8px 16px;
  border: none;
  border-radius: 5px;
  font-size: 14px;
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
  transform: translateY(-1px);
}

.btn-secondary {
  background: #6c757d;
  color: white;
}

.btn-secondary:hover {
  background: #5a6268;
}

.form-text {
  display: block;
  margin-top: 5px;
  font-size: 12px;
  color: #6c757d;
}

.btn:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.btn:disabled:hover {
  transform: none;
}
</style>