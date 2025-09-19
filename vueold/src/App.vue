<script setup lang="ts">
import { ref, onMounted, nextTick } from 'vue'
import { useAuthStore } from '@/stores/auth'
// 移除 naive-ui 导入，使用 Ant Design Vue
import LoginView from '@/views/LoginView.vue'
import MainLayout from '@/views/MainLayoutView.vue'
import AppLoadingSpinner from '@/components/UI/AppLoadingSpinner.vue'

const authStore = useAuthStore()

// 流式加载状态
const currentStage = ref<'loading' | 'login' | 'preloading' | 'admin'>('loading')
const loadingText = ref('正在初始化系统...')
const showLogin = ref(false)
const showAdmin = ref(false)
const preloadComplete = ref(false)

// 预加载组件引用
const mainLayoutRef = ref<InstanceType<typeof MainLayout> | null>(null)

// 流式加载函数
const loadStage = async (stage: 'login' | 'admin' | 'preloading') => {
  currentStage.value = stage
  if (stage === 'login') {
    showLogin.value = true
  } else if (stage === 'preloading') {
    // 开始预加载阶段
    loadingText.value = '正在加载主界面...'
    showAdmin.value = true
    preloadComplete.value = false
    
    // 等待下一个 tick 确保组件已渲染
    await nextTick()
    
    // 模拟预加载时间，让用户看到加载过程
    await new Promise(resolve => setTimeout(resolve, 800))
    
    // 标记预加载完成
    preloadComplete.value = true
    
    // 短暂延迟后切换到完全显示状态
    await new Promise(resolve => setTimeout(resolve, 300))
    currentStage.value = 'admin'
  }
}

// 处理登录成功事件
const handleLoginSuccess = async () => {
  // 隐藏登录界面
  showLogin.value = false
  
  // 开始预加载主界面
  await loadStage('admin')
}

// 处理退出登录事件
const handleLogout = async () => {
  console.log('开始退出登录流程')
  
  // 先隐藏主界面
  showAdmin.value = false
  console.log('隐藏主界面，showAdmin:', showAdmin.value)
  
  // 显示加载动画
  currentStage.value = 'loading'
  loadingText.value = '正在退出登录...'
  console.log('显示加载动画，currentStage:', currentStage.value)
  
  // 执行登出操作
  await authStore.logout()
  console.log('登出操作完成')
  
  // 短暂延迟后显示登录页面
  await new Promise(resolve => setTimeout(resolve, 500))
  await loadStage('login')
  console.log('显示登录页面')
}

// 初始化应用
onMounted(async () => {
  try {
    loadingText.value = '正在验证用户身份...'
    await authStore.initAuth()
    if (!authStore.isAuthenticated) {
      await loadStage('login')
    }
    await loadStage('preloading')
  } catch (error) {
    console.error('应用初始化失败:', error)
    loadingText.value = '初始化失败，请刷新页面重试'
    // 3秒后自动加载登录页面
    // setTimeout(async () => {
    //   await loadStage('login')
    // }, 3000)
  }
})

// 暴露给子组件的方法
defineExpose({
  handleLoginSuccess,
  handleLogout
})
</script>

<template>
  <!-- 初始加载层 -->
  <div v-if="currentStage === 'loading'" class="full-screen loading-overlay">
    <AppLoadingSpinner :text="loadingText" />
  </div>
  
  <!-- 登录层 -->
  <div v-if="showLogin" class="full-screen login-overlay">
    <LoginView @login-success="handleLoginSuccess" />
  </div>
  
  <!-- 预加载层 - 显示加载动画，同时渲染主界面 -->
  <div v-if="currentStage === 'preloading'" class="full-screen loading-overlay">
    <AppLoadingSpinner :text="loadingText" />
    <!-- 隐藏的主界面，在后台渲染 -->
    <div class="hidden-main-layout">
      <MainLayout ref="mainLayoutRef" />
    </div>
  </div>
  
  <!-- 主界面层 -->
  <div v-if="currentStage === 'admin' && showAdmin" class="full-screen admin-overlay">
    <MainLayout ref="mainLayoutRef" @logout="handleLogout" />
  </div>
</template>

<style>
/* ===== 全局 Reset ===== */
* {
  margin: 0;
  padding: 0;
  box-sizing: border-box;
}

html, body {
  height: 100%;
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
}

#app {
  height: 100vh;
}

/* ===== 通用全屏覆盖层 ===== */
.full-screen {
  position: fixed;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  background: #ffffff;
}

/* ===== 动画 ===== */
@keyframes spin {
  0% {
    transform: rotate(0deg);
  }
  100% {
    transform: rotate(360deg);
  }
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

/* ===== 加载层 ===== */
.loading-overlay {
  z-index: 9999;
  display: flex;
  align-items: center;
  justify-content: center;
  color: #2c3e50;
  transition: opacity 0.8s ease-out, transform 0.8s ease-out;
}

.loading-content {
  text-align: center;
}

/* ===== 登录层 ===== */
.login-overlay {
  z-index: 1000;
  display: flex;
  align-items: center;
  justify-content: center;
  animation: fadeIn 0.5s ease-in;
}

.hidden-main-layout {
  position: absolute;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  opacity: 0;
  pointer-events: none;
  z-index: -1;
}

/* ===== 后台层 ===== */
.admin-overlay {
  z-index: 500;
  animation: fadeIn 0.5s ease-in;
}
</style>
