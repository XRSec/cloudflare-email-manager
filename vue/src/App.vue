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
import { useAuthStore, useApp } from '@/composables/stores'
import { defineAsyncComponent } from 'vue'

const AppLoadingSpinner = defineAsyncComponent(() => import('@/layouts/AppLoadingSpinner.vue'))
const LoginView = defineAsyncComponent(() => import('@/layouts/LoginView.vue'))
const MainLayoutView = defineAsyncComponent(() => import('@/layouts/MainLayoutView.vue'))

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
  }
}

// 将方法挂载到全局，方便其他组件使用
window.showGlobalLoading = showGlobalLoading
window.hideGlobalLoading = hideGlobalLoading

// 流式加载函数
const loadNextStage = async (stage: typeof currentStage.value) => {
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
        if (authStore.isAuthenticated) {
          await loadNextStage('main-preload')
        } else {
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
  await loadNextStage('main-preload')
}

// 处理退出登录
const handleLogout = async () => {
  await authStore.logout()
  await loadNextStage('login')
}

// 应用初始化
onMounted(async () => {
  await loadNextStage('initial-loading')
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