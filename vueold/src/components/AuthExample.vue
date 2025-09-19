<template>
  <div class="auth-example">
    <h3>认证状态管理示例 (VueUse + Ant Design Vue)</h3>
    
    <div v-if="!isAuthenticated" class="login-form">
      <h4>登录</h4>
      <a-form @finish="handleLogin" layout="vertical">
        <a-form-item label="用户名">
          <a-input v-model:value="username" placeholder="请输入用户名" />
        </a-form-item>
        <a-form-item label="密码">
          <a-input-password 
            v-model:value="password" 
            placeholder="请输入密码" 
          />
        </a-form-item>
        <a-form-item>
          <a-button 
            type="primary" 
            html-type="submit" 
            :loading="isLoading"
            block
          >
            登录
          </a-button>
        </a-form-item>
      </a-form>
    </div>

    <div v-else class="user-info">
      <h4>用户信息</h4>
      <a-card>
        <a-descriptions :column="1">
          <a-descriptions-item label="用户名">
            {{ user?.username }}
          </a-descriptions-item>
          <a-descriptions-item label="邮箱">
            {{ user?.email }}
          </a-descriptions-item>
          <a-descriptions-item label="角色">
            {{ user?.role }}
          </a-descriptions-item>
        </a-descriptions>
        <template #actions>
          <a-button @click="handleLogout" danger>
            登出
          </a-button>
        </template>
      </a-card>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import { useAuthStore } from '@/stores/auth-vueuse'

// 使用状态管理
const { user, isAuthenticated, isLoading, login, logout } = useAuthStore()

// 表单数据
const username = ref('')
const password = ref('')

// 登录处理
const handleLogin = async () => {
  const result = await login(username.value, password.value)
  if (result.success) {
    console.log('登录成功')
  } else {
    console.error('登录失败:', result.error)
  }
}

// 登出处理
const handleLogout = () => {
  logout()
  username.value = ''
  password.value = ''
}
</script>

<style scoped>
.auth-example {
  max-width: 400px;
  margin: 0 auto;
  padding: 20px;
}

.login-form {
  background: #f5f5f5;
  padding: 20px;
  border-radius: 8px;
}

.user-info {
  background: #f0f9ff;
  padding: 20px;
  border-radius: 8px;
}
</style>
