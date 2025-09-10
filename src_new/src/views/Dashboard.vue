<template>
  <div class="dashboard-container">
    <!-- 侧边栏 -->
    <aside 
      :class="['sidebar', { 
        'sidebar-open': sidebarOpen,
        'sidebar-hidden': !sidebarOpen 
      }]"
    >
      <!-- 侧边栏头部 -->
      <div class="sidebar-header">
        <div class="user-info">
          <div class="user-avatar">
            {{ userInitial }}
          </div>
          <div class="user-details">
            <div class="user-email">{{ userEmail }}</div>
            <div class="user-type">{{ userTypeText }}</div>
          </div>
        </div>
      </div>

      <!-- 侧边栏菜单 -->
      <nav class="sidebar-nav">
        <ul class="nav-list">
          <!-- 普通用户菜单 -->
          <li>
            <router-link
              to="/dashboard/emails"
              class="nav-item"
              active-class="active"
            >
              <span class="nav-icon">📧</span>
              <span class="nav-text">邮件列表</span>
            </router-link>
          </li>
          <li>
            <router-link
              to="/dashboard/settings"
              class="nav-item"
              active-class="active"
            >
              <span class="nav-icon">⚙️</span>
              <span class="nav-text">个人设置</span>
            </router-link>
          </li>

          <!-- 管理员菜单 -->
          <li v-if="authStore.isAdmin" class="nav-divider">
            <span class="divider-text">管理员功能</span>
          </li>
          <li v-if="authStore.isAdmin">
            <router-link
              to="/dashboard/admin/users"
              class="nav-item"
              active-class="active"
            >
              <span class="nav-icon">👥</span>
              <span class="nav-text">用户管理</span>
            </router-link>
          </li>
          <li v-if="authStore.isAdmin">
            <router-link
              to="/dashboard/admin/rules"
              class="nav-item"
              active-class="active"
            >
              <span class="nav-icon">🔗</span>
              <span class="nav-text">转发规则</span>
            </router-link>
          </li>
          <li v-if="authStore.isAdmin">
            <router-link
              to="/dashboard/admin/emails"
              class="nav-item"
              active-class="active"
            >
              <span class="nav-icon">📬</span>
              <span class="nav-text">所有邮件</span>
            </router-link>
          </li>
          <li v-if="authStore.isAdmin">
            <router-link
              to="/dashboard/admin/settings"
              class="nav-item"
              active-class="active"
            >
              <span class="nav-icon">🔧</span>
              <span class="nav-text">系统设置</span>
            </router-link>
          </li>

          <!-- 调试菜单 -->
          <li v-if="systemStore.debugMode" class="nav-divider">
            <span class="divider-text">调试工具</span>
          </li>
          <li v-if="systemStore.debugMode">
            <router-link
              to="/dashboard/debug"
              class="nav-item"
              active-class="active"
            >
              <span class="nav-icon">🐛</span>
              <span class="nav-text">调试工具</span>
            </router-link>
          </li>
        </ul>
      </nav>

      <!-- 侧边栏底部 -->
      <div class="sidebar-footer">
        <button
          class="btn btn-outline-primary btn-block"
          @click="handleLogout"
        >
          退出登录
        </button>
      </div>
    </aside>

    <!-- 主内容区 -->
    <main :class="['main-content', { 'sidebar-expanded': sidebarOpen }]">
      <!-- 顶部栏 -->
      <header class="top-bar">
        <div class="top-bar-left">
          <button
            class="sidebar-toggle btn btn-light"
            @click="toggleSidebar"
          >
            <span v-if="sidebarOpen">←</span>
            <span v-else">→</span>
          </button>
          <h1 class="page-title">{{ currentPageTitle }}</h1>
        </div>
        <div class="top-bar-right">
          <button
            class="btn btn-light"
            @click="refreshData"
            :disabled="refreshing"
          >
            <span v-if="refreshing">刷新中...</span>
            <span v-else>🔄 刷新</span>
          </button>
        </div>
      </header>

      <!-- 页面内容 -->
      <div class="content-area">
        <router-view v-slot="{ Component, route }">
          <Transition name="page" mode="out-in">
            <component :is="Component" :key="route.path" />
          </Transition>
        </router-view>
      </div>
    </main>

    <!-- 移动端遮罩层 -->
    <div
      v-if="sidebarOpen"
      class="mobile-overlay"
      @click="closeSidebar"
    ></div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import { useSystemStore } from '@/stores/system'

// Composables
const router = useRouter()
const route = useRoute()
const authStore = useAuthStore()
const systemStore = useSystemStore()

// State
const sidebarOpen = ref(true)
const refreshing = ref(false)

// Computed
const userInitial = computed(() => {
  return authStore.currentUser?.email_prefix?.charAt(0).toUpperCase() || 'U'
})

const userEmail = computed(() => {
  if (!authStore.currentUser) return ''
  return systemStore.getFullEmailAddress(authStore.currentUser.email_prefix)
})

const userTypeText = computed(() => {
  return authStore.currentUser?.user_type === 'admin' ? '管理员' : '普通用户'
})

const currentPageTitle = computed(() => {
  return route.meta.title as string || '仪表盘'
})

// Methods
const toggleSidebar = () => {
  sidebarOpen.value = !sidebarOpen.value
  localStorage.setItem('sidebar_open', sidebarOpen.value.toString())
}

const closeSidebar = () => {
  sidebarOpen.value = false
  localStorage.setItem('sidebar_open', 'false')
}

const handleLogout = async () => {
  if (confirm('确定要退出登录吗？')) {
    await authStore.logout()
    router.push('/login')
  }
}

const refreshData = async () => {
  refreshing.value = true
  try {
    // 刷新系统配置
    await systemStore.loadConfig()
    // 刷新用户信息
    await authStore.refreshUser()
  } catch (error) {
    console.error('刷新数据失败:', error)
  } finally {
    refreshing.value = false
  }
}

// 响应式处理
const handleResize = () => {
  if (window.innerWidth <= 768) {
    sidebarOpen.value = false
  } else {
    const saved = localStorage.getItem('sidebar_open')
    sidebarOpen.value = saved !== 'false'
  }
}

// Lifecycle
onMounted(() => {
  // 恢复侧边栏状态
  const saved = localStorage.getItem('sidebar_open')
  if (saved !== null) {
    sidebarOpen.value = saved === 'true'
  }
  
  // 添加窗口大小监听
  window.addEventListener('resize', handleResize)
  handleResize()
})

onUnmounted(() => {
  window.removeEventListener('resize', handleResize)
})
</script>

<style scoped>
.dashboard-container {
  display: flex;
  min-height: 100vh;
  background: var(--gray-100);
}

/* 侧边栏样式 */
.sidebar {
  width: 280px;
  background: var(--white);
  box-shadow: var(--shadow-lg);
  display: flex;
  flex-direction: column;
  position: fixed;
  left: 0;
  top: 0;
  height: 100vh;
  z-index: 1000;
  transform: translateX(-100%);
  transition: var(--transition);
}

.sidebar-open {
  transform: translateX(0);
}

.sidebar-header {
  padding: var(--spacing-6);
  border-bottom: 1px solid var(--gray-200);
  background: linear-gradient(135deg, var(--primary-color) 0%, var(--primary-dark) 100%);
  color: var(--white);
}

.user-info {
  display: flex;
  align-items: center;
  gap: var(--spacing-4);
}

.user-avatar {
  width: 50px;
  height: 50px;
  border-radius: var(--border-radius-full);
  background: rgba(255, 255, 255, 0.2);
  display: flex;
  align-items: center;
  justify-content: center;
  font-weight: 600;
  font-size: var(--font-size-lg);
}

.user-details {
  flex: 1;
}

.user-email {
  font-weight: 600;
  font-size: var(--font-size-base);
  margin-bottom: var(--spacing-1);
}

.user-type {
  font-size: var(--font-size-sm);
  opacity: 0.9;
}

.sidebar-nav {
  flex: 1;
  overflow-y: auto;
  padding: var(--spacing-4) 0;
}

.nav-list {
  list-style: none;
  margin: 0;
  padding: 0;
}

.nav-item {
  display: flex;
  align-items: center;
  padding: var(--spacing-4) var(--spacing-6);
  color: var(--gray-700);
  text-decoration: none;
  transition: var(--transition);
  gap: var(--spacing-3);
}

.nav-item:hover {
  background: var(--gray-100);
  color: var(--primary-color);
}

.nav-item.active {
  background: var(--primary-color);
  color: var(--white);
  border-right: 4px solid var(--primary-dark);
}

.nav-icon {
  font-size: var(--font-size-lg);
  width: 24px;
  text-align: center;
}

.nav-text {
  font-weight: 500;
}

.nav-divider {
  margin: var(--spacing-4) 0 var(--spacing-2) 0;
  padding: 0 var(--spacing-6);
}

.divider-text {
  font-size: var(--font-size-sm);
  color: var(--gray-500);
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.sidebar-footer {
  padding: var(--spacing-6);
  border-top: 1px solid var(--gray-200);
}

/* 主内容区样式 */
.main-content {
  flex: 1;
  display: flex;
  flex-direction: column;
  margin-left: 0;
  transition: var(--transition);
}

.sidebar-expanded {
  margin-left: 280px;
}

.top-bar {
  background: var(--white);
  padding: var(--spacing-4) var(--spacing-6);
  border-bottom: 1px solid var(--gray-200);
  display: flex;
  justify-content: space-between;
  align-items: center;
  box-shadow: var(--shadow-sm);
  position: sticky;
  top: 0;
  z-index: 100;
}

.top-bar-left {
  display: flex;
  align-items: center;
  gap: var(--spacing-4);
}

.sidebar-toggle {
  padding: var(--spacing-2) var(--spacing-3);
  min-width: 40px;
}

.page-title {
  font-size: var(--font-size-xl);
  font-weight: 600;
  color: var(--gray-800);
  margin: 0;
}

.top-bar-right {
  display: flex;
  align-items: center;
  gap: var(--spacing-3);
}

.content-area {
  flex: 1;
  padding: var(--spacing-6);
  overflow-y: auto;
}

/* 移动端遮罩层 */
.mobile-overlay {
  position: fixed;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  background: rgba(0, 0, 0, 0.5);
  z-index: 999;
  display: none;
}

/* 页面过渡动画 */
.page-enter-active,
.page-leave-active {
  transition: all 0.3s ease;
}

.page-enter-from {
  opacity: 0;
  transform: translateY(20px);
}

.page-leave-to {
  opacity: 0;
  transform: translateY(-20px);
}

/* 响应式设计 */
@media (max-width: 768px) {
  .sidebar {
    width: 100%;
  }
  
  .main-content {
    margin-left: 0;
  }
  
  .sidebar-expanded {
    margin-left: 0;
  }
  
  .mobile-overlay {
    display: block;
  }
  
  .top-bar {
    padding: var(--spacing-3) var(--spacing-4);
  }
  
  .content-area {
    padding: var(--spacing-4);
  }
  
  .page-title {
    font-size: var(--font-size-lg);
  }
}

@media (min-width: 769px) {
  .sidebar {
    position: relative;
    transform: none;
  }
  
  .sidebar-open {
    transform: none;
  }
  
  .mobile-overlay {
    display: none !important;
  }
}
</style>