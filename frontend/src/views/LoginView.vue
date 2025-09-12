<template>
  <div class="login-page">
    <LoginForm @login-success="handleLoginSuccess" />
  </div>
</template>

<script setup lang="ts">
import { onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import LoginForm from '@/components/Auth/LoginForm.vue'

const router = useRouter()
const authStore = useAuthStore()

onMounted(async () => {
  // 如果已经登录，重定向到首页
  if (authStore.isAuthenticated) {
    router.push('/')
  }
})

const handleLoginSuccess = () => {
  router.push('/')
}
</script>

<style scoped>
.login-page {
  min-height: 100vh;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 20px;
}
</style>
