<template>
  <div class="settings-page">
    <div class="page-header">
      <h1>⚙️ 账户设置</h1>
    </div>
    
    <div class="settings-content">
      <div class="settings-card">
        <h2>密码设置</h2>
        <form @submit.prevent="updatePassword">
          <div class="form-group">
            <label class="form-label">新密码</label>
            <input 
              v-model="passwordForm.newPassword"
              type="password" 
              class="form-control" 
              placeholder="输入新密码"
              minlength="6"
            >
          </div>
          <button type="submit" class="btn btn-primary" :disabled="updating">
            {{ updating ? '更新中...' : '更新密码' }}
          </button>
        </form>
      </div>
      
      <div class="settings-card">
        <h2>Webhook 设置</h2>
        <form @submit.prevent="updateWebhook">
          <div class="form-group">
            <label class="form-label">Webhook URL</label>
            <input 
              v-model="webhookForm.url"
              type="url" 
              class="form-control" 
              placeholder="https://example.com/webhook"
            >
          </div>
          <div class="form-group">
            <label class="form-label">Webhook 密钥</label>
            <input 
              v-model="webhookForm.secret"
              type="text" 
              class="form-control" 
              placeholder="可选，用于验证请求"
            >
          </div>
          <button type="submit" class="btn btn-primary" :disabled="updating">
            {{ updating ? '更新中...' : '更新 Webhook' }}
          </button>
        </form>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue'
import { useAuthStore } from '@/stores/auth'

const authStore = useAuthStore()
const updating = ref(false)

const passwordForm = reactive({
  newPassword: ''
})

const webhookForm = reactive({
  url: '',
  secret: ''
})

const loadUserSettings = () => {
  if (authStore.user?.settings) {
    webhookForm.url = authStore.user.settings.webhook_url || ''
    webhookForm.secret = authStore.user.settings.webhook_secret || ''
  }
}

const updatePassword = async () => {
  if (!passwordForm.newPassword) {
    alert('请输入新密码')
    return
  }
  
  updating.value = true
  try {
    const result = await authStore.updateUserSettings({
      password: passwordForm.newPassword
    })
    
    if (result.success) {
      alert('密码更新成功')
      passwordForm.newPassword = ''
    } else {
      alert(result.error || '密码更新失败')
    }
  } catch (error) {
    console.error('更新密码失败:', error)
    alert('更新密码失败')
  } finally {
    updating.value = false
  }
}

const updateWebhook = async () => {
  updating.value = true
  try {
    const result = await authStore.updateUserSettings({
      webhook_url: webhookForm.url,
      webhook_secret: webhookForm.secret
    })
    
    if (result.success) {
      alert('Webhook 设置更新成功')
    } else {
      alert(result.error || 'Webhook 设置更新失败')
    }
  } catch (error) {
    console.error('更新 Webhook 设置失败:', error)
    alert('更新 Webhook 设置失败')
  } finally {
    updating.value = false
  }
}

onMounted(() => {
  loadUserSettings()
})
</script>

<style scoped>
.settings-page {
  padding: 20px;
  background: #f8f9fa;
  min-height: 100%;
}

.page-header {
  margin-bottom: 30px;
}

.page-header h1 {
  margin: 0;
  color: #2c3e50;
  font-size: 24px;
  font-weight: 600;
}

.settings-content {
  display: flex;
  flex-direction: column;
  gap: 20px;
}

.settings-card {
  background: white;
  border-radius: 10px;
  padding: 20px;
  box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
}

.settings-card h2 {
  margin: 0 0 20px 0;
  color: #2c3e50;
  font-size: 18px;
  font-weight: 600;
  padding-bottom: 10px;
  border-bottom: 1px solid #e9ecef;
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

.btn {
  padding: 10px 20px;
  border: none;
  border-radius: 5px;
  font-size: 14px;
  cursor: pointer;
  transition: all 0.3s;
  font-weight: 500;
  display: inline-block;
}

.btn-primary {
  background: #3498db;
  color: white;
}

.btn-primary:hover:not(:disabled) {
  background: #2980b9;
  transform: translateY(-1px);
}

.btn:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}
</style>
