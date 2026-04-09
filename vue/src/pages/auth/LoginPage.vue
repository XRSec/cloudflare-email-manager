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
import { ref, onMounted, nextTick } from 'vue'
import { useAuthStore } from '@/composables/auth'
import { systemApiService } from '@/composables/api-system'
import LoginCard from '@/components/auth/LoginCard.vue'

const authStore = useAuthStore()

const emit = defineEmits<{
  'login-success': []
}>()

const handleLoginSuccess = async () => {
  if (window.handleLoginSuccess) {
    await window.handleLoginSuccess()
  } else {
    await nextTick()
    emit('login-success')
  }
}

declare global {
  interface Window {
    CEM_CONFIG?: {
      allow_registration: number
      debug_mode: number
      attachment_max_size: number
      api_base_url: string
      version: string
      build_time: string
    }
    ConfigManager?: {
      isRegistrationAllowed(): boolean
      isDebugMode(): boolean
      getMaxAttachmentSize(): number
    }
    handleLoginSuccess?: () => Promise<void>
  }
}

const loading = ref(false)
const errorMessage = ref('')
const loginForm = ref({
  username: '',
  password: ''
})
const allowRegistration = ref(false)

const loadRegistrationStatus = async () => {
  try {
    if (window.CEM_CONFIG && window.ConfigManager) {
      allowRegistration.value = window.ConfigManager.isRegistrationAllowed()
      return
    }

    const health = await systemApiService.getSystemHealth()
    if (health.success && health.data) {
      allowRegistration.value = health.data.config?.allow_registration === 1
    }
  } catch (error) {
    console.error('获取注册状态失败:', error)
    allowRegistration.value = false
  }
}

onMounted(async () => {
  await loadRegistrationStatus()
})

const handleLogin = async () => {
  loading.value = true
  errorMessage.value = ''

  try {
    const result = await authStore.login(
      loginForm.value.username,
      loginForm.value.password
    )

    if (result.success) {
      const loginPage = document.querySelector('.login-page') as HTMLElement
      if (loginPage) {
        loginPage.style.display = 'none'
      }

      await handleLoginSuccess()
    } else {
      errorMessage.value = result.error || '登录失败'
    }
  } catch (error) {
    console.error('登录错误:', error)
    errorMessage.value = '登录时发生错误，请重试'
  } finally {
    loading.value = false
  }
}
</script>
