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
      <LoginPage @login-success="handleLoginSuccess" />
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
import { defineAsyncComponent, onMounted, nextTick } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore } from '@/composables/auth'
import { useApp } from '@/composables/useApp'
import { preloadLoginPage, preloadRouteComponents } from '@/composables/routes'
import AppLoadingSpinner from '@/components/shared/AppLoadingSpinner.vue'

const LoginPage = defineAsyncComponent({
  loader: preloadLoginPage,
  suspensible: false
})

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
    handleLoginSuccess?: () => Promise<void>
  }
}

// 将方法挂载到全局，方便其他组件使用
window.showGlobalLoading = showGlobalLoading
window.hideGlobalLoading = hideGlobalLoading
window.router = router

// 全局消息提示函数
window.showMessage = (message: string, type: 'success' | 'error' | 'warning' | 'info' = 'info') => {
  console.log(`[${type.toUpperCase()}] ${message}`)
  void import('@/utils/toast').then(({ toast }) => {
    switch (type) {
      case 'success':
        toast.success(message)
        break
      case 'error':
        toast.error(message)
        break
      case 'warning':
        toast.warning(message)
        break
      case 'info':
        toast.info(message)
        break
    }
  })
}

// 通用的主界面加载函数（从 main-preload 到 main）
const loadMainInterface = async (
  targetUrl: string = '/',
  options: {
    skipPreload?: boolean
  } = {}
) => {
  const { skipPreload = false } = options

  console.log('⏳ 准备切换到 main-preload 阶段')
  await loadNextStage('main-preload')
  console.log('✅ 已切换到 main-preload 阶段')

  // 等待阶段切换完成
  await nextTick()
  console.log('✅ nextTick 完成')

  // 在预加载阶段真正预取目标路由的 chunk，避免主界面展示后再二次等待
  if (!skipPreload) {
    try {
      console.log('📦 预加载目标路由资源:', targetUrl)
      await preloadRouteComponents(targetUrl)
      console.log('✅ 目标路由资源预加载完成')
    } catch (error) {
      console.warn('⚠️ 目标路由资源预加载失败，回退到正常路由加载:', error)
    }
  }

  // 在预加载阶段执行路由跳转（此时 router-view 还没有显示）
  console.log('🚀 执行路由跳转到:', targetUrl)
  try {
    await router.push(targetUrl)
    console.log('✅ 路由跳转完成')
  } catch (error) {
    console.error('❌ 路由跳转失败:', error)
    // 如果路由跳转失败，仍然切换到主界面
  }

  // 等待路由跳转完成
  await nextTick()
  console.log('✅ 路由跳转后的 nextTick 完成')

  // 现在切换到主界面阶段（router-view 会显示，此时路由已经准备好）
  console.log('⏳ 准备切换到 main 阶段')
  setStage('main')
  await nextTick()
  console.log('✅ 已切换到 main 阶段')

  console.log('✅ 主界面已加载')
}

const resolveTargetUrl = () => {
  const urlParams = new URLSearchParams(window.location.search)
  const redirectUrl = urlParams.get('redirect')
  const currentPath = window.location.pathname

  if (redirectUrl) {
    return decodeURIComponent(redirectUrl)
  }

  if (currentPath !== '/login') {
    return currentPath
  }

  return '/'
}

const hasStoredUser = () => {
  return !!localStorage.getItem('user_info')
}

const verifySessionFromLoginStage = async () => {
  try {
    const result = await authStore.fetchCurrentUser()
    if (result.success && authStore.isAuthenticated) {
      console.log('✅ 登录页后台认证成功，直接进入主界面')
      await loadMainInterface(resolveTargetUrl())
    }
  } catch (error) {
    console.log('ℹ️ 登录页后台认证未命中有效会话')
  }
}

// 流式加载函数
const loadNextStage = async (stage: typeof currentStage.value) => {
  console.log(`🔄 切换到阶段: ${stage}`)
  setStage(stage)

  switch (stage) {
    case 'initial-loading':
      setLoadingText('正在初始化系统...')
      await nextTick()

      if (window.location.pathname === '/login' && !hasStoredUser()) {
        console.log('⚡ 未检测到本地登录态，快速进入登录页')
        await preloadLoginPage()
        setStage('login')
        void verifySessionFromLoginStage()
        return
      }

      await loadNextStage('auth-check')
      break

    case 'auth-check':
      setLoadingText('正在验证用户身份...')
      try {
        const targetUrl = resolveTargetUrl()
        const routePreloadPromise = hasStoredUser()
          ? preloadRouteComponents(targetUrl).catch((error) => {
            console.warn('⚠️ 认证阶段并行预加载失败，后续回退到串行预加载:', error)
          })
          : Promise.resolve()

        await authStore.initAuth()
        console.log('🔐 认证状态:', authStore.isAuthenticated)
        if (authStore.isAuthenticated) {
          console.log('✅ 用户已认证，进入主界面')
          console.log('📍 目标URL:', targetUrl)
          await routePreloadPromise
          // 使用通用函数加载主界面
          await loadMainInterface(targetUrl, {
            skipPreload: hasStoredUser()
          })
        } else {
          console.log('❌ 用户未认证，进入登录页')
          setLoadingText('正在加载登录界面...')
          await preloadLoginPage()
          await loadNextStage('login')
        }
      } catch (error) {
        console.error('权限验证失败:', error)
        setLoadingText('正在加载登录界面...')
        await preloadLoginPage()
        await loadNextStage('login')
      }
      break

    case 'login':
      // 登录界面直接显示，不需要额外加载
      break

    case 'main-preload':
      setLoadingText('正在加载主界面...')
      await nextTick()
      // 注意：不在这里切换到 main，由调用者控制切换时机
      console.log('✅ 主界面预加载完成')
      break

    case 'main':
      // 主界面直接显示
      break
  }
}

// 处理登录成功
const handleLoginSuccess = async () => {
  console.log('🎯 App.vue 收到登录成功事件')
  console.log('🔍 当前阶段:', currentStage.value)
  console.log('🔍 认证状态:', authStore.isAuthenticated)

  setLoadingText('正在跳转至主界面...')

  const targetUrl = resolveTargetUrl()
  console.log('📍 目标URL:', targetUrl)

  // 使用通用函数加载主界面
  await loadMainInterface(targetUrl)

  console.log('✅ 登录成功，主界面已加载')
}

// 将 handleLoginSuccess 挂载到全局，方便 LoginPage 直接调用
window.handleLoginSuccess = handleLoginSuccess

// 处理退出登录
const handleLogout = async () => {
  const currentUrl = `${window.location.pathname}${window.location.search}${window.location.hash}`
  await authStore.logout()
  window.location.assign(`/login?redirect=${encodeURIComponent(currentUrl)}`)
}

// 应用初始化
onMounted(async () => {
  // 缓存系统已迁移到统一请求管理器

  await loadNextStage('initial-loading')
})

// 监听路由变化，实现智能预加载
router.afterEach((to, from) => {
  console.log(`🔄 路由切换: ${String(from.name || '')} → ${String(to.name || '')}`)

  // 预加载相关页面
  if (to.name === 'dashboard') {
    // 在用户进入主界面后，低优先级预加载高频管理页面
    setTimeout(() => {
      void Promise.allSettled([
        preloadRouteComponents('/all-emails'),
        preloadRouteComponents('/system-settings')
      ])
      console.log('📦 已触发高频管理页面预加载')
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
  /* position: fixed; */
  /* top: 0; */
  /* left: 0; */
  /* width: 100%; */
  /* height: 100%; */
  /* display: flex; */
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
