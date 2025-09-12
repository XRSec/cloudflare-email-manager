<template>
  <div class="main-layout">
    <!-- 侧边栏 -->
    <Sidebar 
      :is-open="sidebarOpen"
      @toggle="toggleSidebar"
      @navigate="handleNavigation"
    />
    
    <!-- 主内容区域 -->
    <div class="main-content" :class="{ 'sidebar-open': sidebarOpen }">
      <!-- 顶部栏 -->
      <TopBar 
        @toggle-sidebar="toggleSidebar"
        @refresh-config="refreshConfig"
      />
      
      <!-- 页面内容 -->
      <div class="content-area">
        <router-view />
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import Sidebar from './Sidebar.vue'
import TopBar from './TopBar.vue'

const router = useRouter()
const sidebarOpen = ref(false)

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

// 监听窗口大小变化
onMounted(() => {
  const handleResize = () => {
    if (window.innerWidth > 768) {
      sidebarOpen.value = true
    } else {
      sidebarOpen.value = false
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
  .main-content {
    margin-left: 0 !important;
  }
  
  .content-area {
    padding: 0 15px 15px 15px;
  }
}

@media (min-width: 769px) {
  .main-content {
    margin-left: 250px;
  }
}
</style>
