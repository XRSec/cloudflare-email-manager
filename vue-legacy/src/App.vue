<template>
  <div id="app">
    <!-- 阶段1: 初始加载 -->
    <div v-if="isInitialLoading" class="stage-container">
      <AppLoadingSpinner :text="loadingText" />
    </div>

    <!-- 阶段2: 权限验证 -->
    <div v-if="isAuthCheck" class="stage-container">
      <AppLoadingSpinner :text="loadingText" />
    </div>

    <!-- 阶段3: 登录界面 -->
    <div v-if="isLogin" class="stage-container">
      <LoginView @login-success="handleLoginSuccess" />
    </div>

    <!-- 阶段4: 主界面预加载 -->
    <div v-if="isMainPreload" class="stage-container">
      <AppLoadingSpinner :text="loadingText" />
    </div>

    <!-- 阶段5: 主界面显示 -->
    <div v-if="isMain" class="stage-container">
      <router-view @logout="handleLogout" />
    </div>
  </div>
</template>

<script setup lang="ts">
import { onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore, useApp } from '@/composables/stores'
import { smartCache } from '@/composables/smartCache'
import { defineAsyncComponent } from 'vue'

const AppLoadingSpinner = defineAsyncComponent(() => import('@/views/shared/components/AppLoadingSpinner.vue'))
const LoginView = defineAsyncComponent(() => import('@/views/auth/LoginView.vue'))

const router = useRouter()
const authStore = useAuthStore()
const {
  currentStage,
  loadingText,
  setStage,
  setLoadingText,
  showGlobalLoading,
  hideGlobalLoading,
  isInitialLoading,
  isAuthCheck,
  isLogin,
  isMainPreload,
  isMain
} = useApp()

// 声明全局类型
declare global {
  interface Window {
    showGlobalLoading: (text?: string) => void
    hideGlobalLoading: () => void
    showMessage?: (message: string, type?: 'success' | 'error' | 'warning' | 'info') => void
    router?: typeof router
    refreshCurrentPage?: () => void
  }
}

// 将方法挂载到全局，方便其他组件使用
window.showGlobalLoading = showGlobalLoading
window.hideGlobalLoading = hideGlobalLoading
window.router = router

// 全局消息提示函数
window.showMessage = (message: string, type: 'success' | 'error' | 'warning' | 'info' = 'info') => {
  console.log(`[${type.toUpperCase()}] ${message}`)
  // 这里可以替换为更好的消息组件
  if (type === 'error') {
    alert(message)
  } else {
    console.log(message)
  }
}

// 流式加载函数
const loadNextStage = async (stage: typeof currentStage.value) => {
  console.log(`🔄 切换到阶段: ${stage}`)
  setStage(stage)

  switch (stage) {
    case 'initial-loading':
      setLoadingText('正在初始化系统...')
      // 模拟初始化时间
      await new Promise(resolve => setTimeout(resolve, 800))
      await loadNextStage('auth-check')
      break

    case 'auth-check':
      setLoadingText('正在验证用户身份...')
      try {
        await authStore.initAuth()
        console.log('🔐 认证状态:', authStore.isAuthenticated)
        if (authStore.isAuthenticated) {
          console.log('✅ 用户已认证，进入主界面')
          await loadNextStage('main-preload')
        } else {
          console.log('❌ 用户未认证，进入登录页')
          await loadNextStage('login')
        }
      } catch (error) {
        console.error('权限验证失败:', error)
        await loadNextStage('login')
      }
      break

    case 'login':
      // 登录界面直接显示，不需要额外加载
      break

    case 'main-preload':
      setLoadingText('正在加载主界面...')
      // 模拟预加载时间
      await new Promise(resolve => setTimeout(resolve, 600))
      setStage('main')
      break

    case 'main':
      // 主界面直接显示
      break
  }
}

// 处理登录成功
const handleLoginSuccess = async () => {
  console.log('🎯 App.vue 收到登录成功事件')
  setLoadingText('正在跳转至主界面...')
  // 检查是否有重定向参数
  const urlParams = new URLSearchParams(window.location.search)
  const redirectUrl = urlParams.get('redirect')
  console.log('📍 重定向URL:', redirectUrl)
  let newUrl = decodeURIComponent(redirectUrl ?? '/')
  await loadNextStage('main-preload')
  router.push(newUrl)
}

// 处理退出登录
const handleLogout = async () => {
  await authStore.logout()
  await loadNextStage('login')
}

// 应用初始化
onMounted(async () => {
  // 初始化智能缓存系统
  console.log('🚀 智能缓存系统已启动')
  console.log('📊 缓存统计:', smartCache.getStats())

  await loadNextStage('initial-loading')
})

// 监听路由变化，实现智能预加载
router.afterEach((to, from) => {
  console.log(`🔄 路由切换: ${String(from.name || '')} → ${String(to.name || '')}`)

  // 预加载相关页面
  if (to.name === 'dashboard') {
    // 预加载邮件和邮箱页面
    setTimeout(() => {
      // 简单的预加载逻辑，暂时用 push 替代
      console.log('预加载邮件和邮箱页面')
    }, 1000)
  }
})
</script>

<style>
/* ===== 全局 Reset ===== */
* {
  margin: 0;
  padding: 0;
  box-sizing: border-box;
}

html,
body {
  height: 100%;
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
}

#app {
  height: 100vh;
}

/* ===== 阶段容器样式 ===== */
.stage-container {
  position: fixed;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  display: flex;
  align-items: center;
  justify-content: center;
  background: #ffffff;
  z-index: 1000;
  animation: fadeIn 0.5s ease-in-out;
}

@keyframes fadeIn {
  from {
    opacity: 0;
    transform: translateY(20px);
  }

  to {
    opacity: 1;
    transform: translateY(0);
  }
}
</style>