<template>
  <LoginCard
    :username="loginForm.username"
    :password="loginForm.password"
    :loading="loading"
    :error-message="errorMessage"
    :allow-registration="allowRegistration"
    @update:username="loginForm.username = $event"
    @update:password="loginForm.password = $event"
    @submit="handleLogin"
  />
</template>

<script setup lang="ts">
import { onMounted, ref } from 'vue'
import LoginCard from '@/components/auth/LoginCard.vue'

const emit = defineEmits<{
  loginSuccess: [user: any]
}>()

const loading = ref(false)
const errorMessage = ref('')
const allowRegistration = ref(false)
const loginForm = ref({
  username: '',
  password: ''
})

const loadRegistrationStatus = async () => {
  try {
    const response = await fetch('/api/system/health', {
      credentials: 'include'
    })
    const health = await response.json()
    allowRegistration.value = health.success && health.data?.health?.config?.allow_registration === 1
  } catch (error) {
    console.error('获取注册状态失败:', error)
    allowRegistration.value = false
  }
}

const handleLogin = async () => {
  loading.value = true
  errorMessage.value = ''

  try {
    const response = await fetch('/api/auth/login', {
      method: 'POST',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(loginForm.value)
    })

    const result = await response.json()

    if (result.success && result.data?.user) {
      emit('loginSuccess', result.data.user)
      return
    }

    errorMessage.value = result.message || result.error || '登录失败'
  } catch (error) {
    console.error('登录错误:', error)
    errorMessage.value = '登录时发生错误，请重试'
  } finally {
    loading.value = false
  }
}

onMounted(async () => {
  await loadRegistrationStatus()
})
</script>
