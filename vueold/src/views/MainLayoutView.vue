<template>
  <div class="main-layout">
    <!-- 侧边栏 -->
    <Sidebar :is-open="sidebarOpen" @toggle="toggleSidebar" @navigate="handleNavigation" @logout="handleLogout" />

    <!-- 主内容区域 -->
    <div class="main-content" :class="{ 'sidebar-open': sidebarOpen }">
      <!-- 顶部栏 -->
      <TopBar @toggle-sidebar="toggleSidebar" @refresh-config="refreshConfig" />

      <!-- 页面内容 -->
      <div class="content-area">
        <router-view />
      </div>
    </div>

    <!-- 全局加载覆盖层 -->
    <LoadingOverlay :show="globalLoading.loading.value" :text="globalLoading.text.value" type="global" />
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import Sidebar from '@/components/Layout/Sidebar.vue'
import TopBar from '@/components/Layout/TopBar.vue'
import LoadingOverlay from '@/components/UI/LoadingOverlay.vue'
import { useGlobalLoading } from '@/composables/useLoading'

interface Emits {
  (e: 'logout'): void
}

const emit = defineEmits<Emits>()
const router = useRouter()
const sidebarOpen = ref(false)
const globalLoading = useGlobalLoading()

const toggleSidebar = () => {
  sidebarOpen.value = !sidebarOpen.value
}

const handleNavigation = (route: string) => {
  // 在移动端导航后关闭侧边栏
  if (window.innerWidth <= 768) {
    sidebarOpen.value = false
  }
}

const refreshConfig = async () => {
  // 这里可以刷新系统配置
  console.log('刷新配置')
  // 可以触发全局事件或调用相关服务
}

const handleLogout = () => {
  // 触发退出登录事件，让 App.vue 处理
  emit('logout')
}

// 监听窗口大小变化
onMounted(() => {
  const handleResize = () => {
    // 在移动端强制关闭侧边栏
    if (window.innerWidth <= 768) {
      sidebarOpen.value = false
    } else {
      // 在桌面端默认打开侧边栏
      sidebarOpen.value = true
    }
  }

  // 初始设置
  handleResize()

  // 监听窗口大小变化
  window.addEventListener('resize', handleResize)

  // 清理监听器
  return () => {
    window.removeEventListener('resize', handleResize)
  }
})
</script>

<style scoped>
.full-screen {
  position: fixed;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  background: #ffffff;
}

.main-layout {
  display: flex;
  height: 100vh;
  background: #f8f9fa;
}

.main-content {
  flex: 1;
  display: flex;
  flex-direction: column;
  margin-left: 0;
  transition: margin-left 0.3s ease;
  min-height: 100vh;
}

.main-content.sidebar-open {
  margin-left: 250px;
}

.content-area {
  flex: 1;
  padding: 0 20px 20px 20px;
  overflow-y: auto;
}

@media (max-width: 768px) {
  .content-area {
    padding: 0 15px 15px 15px;
  }

  .main-content.sidebar-open {
    margin-left: unset;
  }
}
</style>
