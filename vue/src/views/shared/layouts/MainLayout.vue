<template>
  <div class="main-layout">
    <!-- 侧边栏 -->
    <div id="sidebar" class="sidebar" :class="{ hidden: !sidebarOpen }">
      <!--    <div class="sidebar" :class="{ 'sidebar-open': sidebarOpen }">-->
      <div class="sidebar-header">
        <h2>CEM 邮箱管理系统</h2>
      </div>
      <div class="sidebar-menu">
        <router-link to="/" class="sidebar-item" :class="{ active: $route.path === '/' }" @click="closeSidebarOnMobile">
          🏠 仪表板
        </router-link>

        <!-- 使用v-for渲染导航菜单 -->
        <template v-for="section in navigationSections" :key="section.title">
          <div v-if="section.show" class="nav-section">
            <div v-if="section.title" class="section-title">{{ section.title }}</div>

            <template v-for="item in section.items" :key="`${item.path}-${item.show}`">
              <router-link v-if="item.show" :to="item.path" class="sidebar-item"
                :class="{ active: isRouteActive(item.path, item.exactMatch) }" @click="closeSidebarOnMobile">
                {{ item.icon }} {{ item.title }}
                <span v-if="item.badge" class="nav-badge" :class="item.badgeClass">
                  {{ item.badge }}
                </span>
              </router-link>
            </template>
          </div>
        </template>
      </div>

      <div class="sidebar-footer">
        <div class="btn-secondary" @click="toggleSidebar">☰ 关闭菜单</div>
        <div class="logout-btn" @click="handleLogout">🚪 退出登录</div>
      </div>
    </div>

    <!-- 主内容区域 -->
    <div class="main-content" :class="{ 'sidebar-open': sidebarOpen }">
      <!-- 顶部栏 -->
      <div class="top-bar">
        <div class="left-section">
          <Button variant="secondary" size="sm" @click="toggleSidebar">☰ 菜单</Button>
          <Button variant="primary" size="sm" @click="refreshCurrentPage" :disabled="refreshing">
            {{ refreshing ? '🔄 刷新中...' : '🔄 刷新' }}
          </Button>
        </div>
        <div class="user-info">
          <div class="user-avatar">
            {{ userInitials }}
          </div>
          <div class="user-details">
            <div class="user-email">{{ userEmail }}</div>
            <div class="user-type">{{ userType }}</div>
          </div>
        </div>
      </div>

      <!-- 页面内容 -->
      <div class="page-content">
        <router-view />
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, nextTick } from 'vue'
import { useRoute } from 'vue-router'
import { useAuthStore } from '@/composables/stores'
import { useSystemStore } from '@/composables/system'
import { useUnifiedGlobalRefreshManager } from '@/composables/globalRefreshManager'
import { Button } from '@/components/common'
// 在开发模式下导入测试
if (import.meta.env.DEV) {
  import('@/composables/testRouteApiMapper')
  import('@/composables/testCacheKeys')
}

// 调试工具函数
const debugLog = (...args: any[]) => {
  if (systemStore.isDebugMode) {
    console.log('[MainLayout]', ...args)
  }
}

const authStore = useAuthStore()
const systemStore = useSystemStore()
const route = useRoute()

// 定义事件
const emit = defineEmits<{
  'logout': []
}>()

// 侧边栏状态
const sidebarOpen = ref(false)

// 使用统一全局刷新管理器
const { executeGlobalRefresh, isRefreshing, getCurrentPageRefreshInfo } = useUnifiedGlobalRefreshManager()

// 刷新状态
// 使用统一刷新管理器的状态
const refreshing = isRefreshing

// 计算属性
const isAdmin = computed(() => authStore.user?.user_type === 1)

const isDebugMode = computed(() => systemStore.isDebugMode)

const userInitials = computed(() => {
  if (authStore.user?.username) {
    return authStore.user.username.charAt(0).toUpperCase()
  }
  return 'U'
})

const userEmail = computed(() => {
  if (authStore.user?.email) {
    return authStore.user.email
  }
  return 'user@example.com'
})

const userType = computed(() => {
  if (authStore.user?.user_type) {
    return authStore.user.user_type === 1 ? '管理员' : '普通用户'
  }
  return '用户'
})

// 导航配置 - 智能化管理
const navigationSections = computed(() => {
  debugLog('isDebugMode:', isDebugMode.value, 'type:', typeof isDebugMode.value)
  return [
    {
      title: '', // 主要功能不显示标题
      show: true,
      items: [
        {
          path: '/my-emails',
          title: '我的邮件',
          icon: '📧',
          show: true,
          exactMatch: true
        },
        {
          path: '/my-mailboxes',
          title: '我的邮箱',
          icon: '📮',
          show: true,
          exactMatch: true
        },
        {
          path: '/forward-rules',
          title: '转发规则',
          icon: '📤',
          show: true,
          exactMatch: true
        }
      ]
    },
    {
      title: '系统管理',
      show: isAdmin,
      items: [
        {
          path: '/admin-users',
          title: '用户管理',
          icon: '👥',
          show: isAdmin,
          exactMatch: false
        },
        {
          path: '/mailbox-management',
          title: '邮箱管理',
          icon: '📮',
          show: isAdmin,
          exactMatch: false,
          badge: '新',
          badgeClass: 'badge-success'
        },
        {
          path: '/all-emails',
          title: '全部邮件',
          icon: '📨',
          show: isAdmin,
          exactMatch: false
        },
        {
          path: '/admin-rules',
          title: '转发管理',
          icon: '🔄',
          show: isAdmin,
          exactMatch: false
        },
        {
          path: '/admin-security-overview',
          title: '安全概览',
          icon: '🛡️',
          show: isAdmin,
          exactMatch: false
        },
        {
          path: '/system-settings',
          title: '系统设置',
          icon: '🛠️',
          show: isAdmin,
          exactMatch: false
        }
      ]
    },
    {
      title: '其他功能',
      show: true,
      items: [
        {
          path: '/personal-settings',
          title: '个人设置',
          icon: '⚙️',
          show: true,
          exactMatch: true
        },
        {
          path: '/debug',
          title: '调试模式',
          icon: '🐛',
          show: isDebugMode.value,
          exactMatch: true,
          badge: 'DEV',
          badgeClass: 'badge-warning'
        }
      ]
    }
  ]
})

// 智能路由激活判断
const isRouteActive = (path: string, exactMatch: boolean = false) => {
  if (exactMatch) {
    return route.path === path
  } else {
    return route.path.startsWith(path)
  }
}

// 方法
const toggleSidebar = () => {
  sidebarOpen.value = !sidebarOpen.value
}

// 在移动端点击菜单项后关闭侧边栏
const closeSidebarOnMobile = () => {
  if (window.innerWidth <= 768) {
    sidebarOpen.value = false
  }
}


// 全局刷新当前页面
const refreshCurrentPage = async () => {
  try {
    const refreshInfo = getCurrentPageRefreshInfo()
    console.log('🌍 全局刷新触发', refreshInfo)

    await executeGlobalRefresh()
  } catch (error) {
    console.error('刷新页面失败:', error)
  }
}

// 处理退出登录
const handleLogout = () => {
  emit('logout')
}

// 初始化
onMounted(async () => {
  // 获取系统配置（包括调试模式设置）
  // fetchSystemHealth 无需认证，适合在 MainLayoutView 中使用
  await systemStore.fetchSystemHealth()

  // 强制触发响应式更新
  nextTick(() => {
    // 触发计算属性重新计算
    systemStore.systemConfig = { ...systemStore.systemConfig }
  })

  // 检查屏幕大小，设置侧边栏状态
  const checkScreenSize = () => {
    if (window.innerWidth < 768) {
      sidebarOpen.value = false
    } else {
      sidebarOpen.value = true
    }
  }

  checkScreenSize()
  window.addEventListener('resize', checkScreenSize)

  // 清理监听器
  return () => {
    window.removeEventListener('resize', checkScreenSize)
  }
})
</script>

<style scoped>
/* ===== 主布局样式 ===== */
.main-layout {
  display: flex;
  width: 100%;
  height: 100vh;
  background: #f8f9fa;
}

/* ===== 侧边栏样式 ===== */
.sidebar {
  position: fixed;
  left: 0;
  top: 0;
  width: 200px;
  height: 100vh;
  background: #fff;
  border-right: 2px solid #e0e0e0;
  box-shadow: 2px 0 8px rgba(0, 0, 0, .16);
  color: black;
  z-index: 1000;
  transition: transform 0.3s ease;
  overflow-y: auto;
}

.sidebar.hidden {
  transform: translateX(-100%);
}

.sidebar-header {
  padding: 20px;
  border-bottom: 1px solid #d2d2d2;
}

.sidebar-header h2 {
  margin: 0;
  font-size: 18px;
  font-weight: 600;
  color: #2c3e50;
}

.sidebar-menu {
  padding: 10px 0;
}

.sidebar-menu .active {
  background: #d2d2d2;
  color: #3498db;
  border-right-color: #3498db;
}

.sidebar-item {
  display: block;
  padding: 12px 20px;
  text-decoration: none;
  transition: all 0.3s ease;
  border-right: 3px solid transparent;
  cursor: pointer;
  color: #2c3e50;
}

.sidebar-item:hover {
  background: #d2d2d2;
  color: #3498db;
  border-right-color: #3498db;
}

.sidebar-item.active {
  background: #e3f2fd;
  color: #1976d2;
  border-right-color: #1976d2;
}

/* 导航徽章样式 */
.nav-badge {
  padding: 2px 6px;
  border-radius: 10px;
  font-size: 10px;
  font-weight: 500;
  margin-left: auto;
  float: right;
}

.badge-success {
  background: #28a745;
  color: white;
}

.badge-warning {
  background: #ffc107;
  color: #212529;
}

.badge-info {
  background: #17a2b8;
  color: white;
}

/* 分组标题样式 */
.section-title {
  font-size: 12px;
  color: #6c757d;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  padding: 8px 20px 4px;
  margin-top: 10px;
  border-bottom: 1px solid #e9ecef;
}

.nav-section:first-child .section-title {
  margin-top: 0;
}

.admin-menu {
  border-top: 1px solid #d2d2d2;
  margin-top: 10px;
  padding-top: 10px;
}

.sidebar-footer {
  position: absolute;
  bottom: 0;
  left: 0;
  right: 0;
  padding: 20px;
  border-top: 1px solid #d2d2d2;
}

.sidebar-footer>.btn-secondary,
.sidebar-footer>.logout-btn {
  display: block;
  padding: 8px 15px;
  border: none;
  border-radius: 5px;
  cursor: pointer;
  text-align: center;
  border-right: 3px solid transparent;
  margin-bottom: 10px;
  transition: background 0.3s ease;
}

.sidebar-footer>.btn-secondary:hover,
.sidebar-footer>.logout-btn:hover {
  color: #3498db;
  border-right-color: #3498db;
}

.logout-btn {
  color: #e74c3c !important;
}

/* ===== 主内容区域样式 ===== */
.main-content {
  flex: 1;
  display: flex;
  flex-direction: column;
  margin-left: 0;
  transition: margin-left 0.3s ease;
  min-height: 98vh;
  /* overflow: hidden; */
}

.main-content.sidebar-open {
  margin-left: 200px;
}

/* ===== 顶部栏样式 ===== */
.top-bar {
  background: white;
  padding: 15px 20px;
  box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
  display: flex;
  justify-content: space-between;
  align-items: center;
  z-index: 1001;
  position: relative;
  height: 60px;
  flex-shrink: 0;
}

.left-section {
  display: flex;
  gap: 10px;
}

.user-info {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 10px;
  border-radius: 5px;
}

.user-avatar {
  width: 40px;
  height: 40px;
  border-radius: 50%;
  background: #3498db;
  color: white;
  display: flex;
  align-items: center;
  justify-content: center;
  font-weight: bold;
  font-size: 16px;
}

.user-details {
  display: flex;
  flex-direction: column;
}

.user-email,
.user-type {
  font-size: 0.8rem;
  color: #6c757d;
}

/* MainLayoutView 特有的样式在下面的 <style scoped> 块中 */

/* ===== 响应式设计 ===== */
@media (max-width: 768px) {
  /* .sidebar {
    width: 80%;
    max-width: 300px;
  } */

  .main-content.sidebar-open {
    margin-left: 0;
  }

  .top-bar {
    padding: 10px 15px;
  }

  .user-info {
    gap: 8px;
  }

  .user-avatar {
    width: 35px;
    height: 35px;
    font-size: 14px;
  }
}

@media (max-width: 480px) {
  /* .sidebar {
    width: 90%;
  } */
}
</style>

<!-- 全局样式 -->
<style>
/* ===== 全局样式 ===== */

/* ===== 按钮样式 ===== */
.btn {
  padding: 8px 16px;
  border: none;
  border-radius: 5px;
  font-size: 14px;
  cursor: pointer;
  transition: all 0.3s;
  font-weight: 500;
  display: inline-block;
  text-decoration: none;
}

.btn-secondary {
  background: #3498db;
  color: white;
}

.btn-secondary:hover {
  background: #0056b3;
  transform: translateY(-1px);
}

.btn-success {
  background: #28a745;
  color: white;
}

.btn-success:hover {
  background: #218838;
  transform: translateY(-1px);
}

.btn-primary {
  background: #007bff;
  color: white;
}

.btn-primary:hover {
  background: #0056b3;
  transform: translateY(-1px);
}

.btn-danger {
  background: #dc3545;
  color: white;
}

.btn-danger:hover {
  background: #c82333;
  transform: translateY(-1px);
}

.btn-warning {
  background: #ffc107;
  color: #212529;
}

.btn-warning:hover {
  background: #e0a800;
  transform: translateY(-1px);
}

.btn-info {
  background: #17a2b8;
  color: white;
}

.btn-info:hover {
  background: #138496;
  transform: translateY(-1px);
}

.btn-sm {
  padding: 6px 12px;
  font-size: 12px;
}

.btn-lg {
  padding: 12px 24px;
  font-size: 16px;
}

/* ===== 表单样式 ===== */
.form-group {
  margin-bottom: 20px;
}

.form-label {
  display: block;
  margin-bottom: 8px;
  font-weight: 500;
  color: #2c3e50;
}

.form-control {
  width: 100%;
  padding: 12px 16px;
  border: 1px solid #ddd;
  border-radius: 5px;
  font-size: 14px;
  transition: border-color 0.3s ease;
}

.form-control:focus {
  outline: none;
  border-color: #007bff;
  box-shadow: 0 0 0 2px rgba(0, 123, 255, 0.25);
}

.form-control.is-invalid {
  border-color: #dc3545;
}

.form-control.is-valid {
  border-color: #28a745;
}

/* ===== 卡片样式 ===== */
.card {
  background: white;
  border-radius: 10px;
  box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
  overflow: hidden;
}

.card-header {
  padding: 20px;
  border-bottom: 1px solid #e0e0e0;
  background: #f8f9fa;
}

.card-body {
  padding: 20px;
}

.card-footer {
  padding: 20px;
  border-top: 1px solid #e0e0e0;
  background: #f8f9fa;
}

/* ===== 通用搜索组件样式 ===== */
.search-container {
  display: flex;
  align-items: center;
  gap: 20px;
  flex-wrap: wrap;
}

.search-input-wrapper {
  display: flex;
  align-items: center;
  flex: 1;
  min-width: 300px;
  max-width: 500px;
  position: relative;
}

.search-input {
  flex: 1;
  padding: 10px 16px;
  border: 1px solid #ddd;
  border-radius: 8px 0 0 8px;
  font-size: 14px;
  transition: border-color 0.3s ease;
}

.search-input:focus {
  outline: none;
  border-color: #007bff;
  box-shadow: 0 0 0 2px rgba(0, 123, 255, 0.25);
}

.search-btn {
  padding: 10px 16px;
  background: #007bff;
  color: white;
  border: 1px solid #007bff;
  border-left: none;
  border-radius: 0;
  cursor: pointer;
  transition: background-color 0.3s ease;
  min-width: 50px;
  display: flex;
  align-items: center;
  justify-content: center;
}

.search-btn:hover:not(:disabled) {
  background: #0056b3;
}

.search-btn:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.clear-btn {
  background: #6c757d;
  color: white;
  border: 1px solid #6c757d;
  border-left: none;
  border-radius: 0 8px 8px 0;
  padding: 10px 12px;
  cursor: pointer;
  transition: background-color 0.3s ease;
  display: flex;
  align-items: center;
  justify-content: center;
}

.clear-btn:hover {
  background: #5a6268;
}

.loading-spinner-sm {
  animation: spin 1s linear infinite;
  display: inline-block;
}

.search-stats {
  color: #6c757d;
  font-size: 14px;
  white-space: nowrap;
}

.search-time {
  color: #28a745;
  font-weight: 500;
}

/* ===== 通用页面头部样式 ===== */
.page-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 20px;
}

.page-header h1 {
  margin: 0;
  color: #2c3e50;
  font-size: 24px;
  font-weight: 600;
}

.header-actions {
  display: flex;
  align-items: center;
  gap: 20px;
}

/* ===== 标签页样式 ===== */
.view-tabs {
  display: flex;
  background: #f8f9fa;
  border-radius: 8px;
  padding: 4px;
  gap: 4px;
}

.tab-btn {
  padding: 8px 16px;
  border: none;
  background: transparent;
  border-radius: 6px;
  cursor: pointer;
  font-size: 14px;
  font-weight: 500;
  color: #6c757d;
  transition: all 0.3s ease;
}

.tab-btn:hover {
  background: #e9ecef;
  color: #495057;
}

.tab-btn.active {
  background: #007bff;
  color: white;
  box-shadow: 0 2px 4px rgba(0, 123, 255, 0.25);
}

/* ===== 批量操作样式 ===== */
.batch-actions {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 8px 16px;
  background: #e3f2fd;
  border-radius: 6px;
  border: 1px solid #2196f3;
  margin-bottom: 20px;
}

.selected-count {
  font-size: 14px;
  color: #1976d2;
  font-weight: 500;
}

/* ===== 工具栏样式 ===== */
.page-toolbar {
  background: white;
  padding: 15px 20px;
  border-bottom: 1px solid #e0e0e0;
  border-radius: 10px 10px 0 0;
  display: flex;
  justify-content: space-between;
  align-items: center;
  flex-wrap: wrap;
  gap: 15px;
  margin-bottom: 20px;
}

.toolbar-left,
.toolbar-right {
  display: flex;
  align-items: center;
  gap: 12px;
}

/* ===== 通用操作按钮组样式 ===== */
.action-buttons {
  display: flex;
  gap: 4px;
  justify-content: center;
}

.action-buttons .btn {
  min-width: 36px;
  height: 32px;
  display: flex;
  align-items: center;
  justify-content: center;
}

/* ===== 响应式通用样式 ===== */
@media (max-width: 768px) {
  .page-header {
    flex-direction: column;
    gap: 12px;
    align-items: stretch;
  }

  .header-actions {
    justify-content: center;
    flex-wrap: wrap;
  }

  .search-input-wrapper {
    min-width: 200px;
    max-width: 100%;
  }

  .page-toolbar {
    flex-direction: column;
    align-items: stretch;
  }

  .toolbar-left,
  .toolbar-right {
    justify-content: center;
  }

  .view-tabs {
    justify-content: center;
  }

  .action-buttons {
    flex-wrap: wrap;
    gap: 8px;
  }
}

/* ===== 页面内容样式 ===== */
.page-content {
  flex: 1;
  padding: 20px;
  overflow-y: auto;
  background: #f8f9fa;
  min-height: calc(80vh - 60px);
}


.page-header {
  margin-bottom: 20px;
}

.page-header h1 {
  margin: 0;
  color: #2c3e50;
  font-size: 24px;
  font-weight: 600;
}

.page-header h2 {
  margin: 0;
  color: #2c3e50;
  font-size: 20px;
  font-weight: 500;
}

.page-header h3 {
  margin: 0;
  color: #2c3e50;
  font-size: 18px;
  font-weight: 500;
}

/* ===== 空状态样式 ===== */
.empty-state {
  text-align: center;
  padding: 40px;
  color: #6c757d;
}

.empty-icon {
  font-size: 48px;
  margin-bottom: 15px;
}

.empty-title {
  font-size: 18px;
  font-weight: 500;
  margin-bottom: 10px;
  color: #2c3e50;
}

.empty-description {
  font-size: 14px;
  color: #6c757d;
}

/* ===== 列表样式 ===== */
.list {
  display: flex;
  flex-direction: column;
  gap: 15px;
}

.list-item {
  background: white;
  border-radius: 10px;
  padding: 20px;
  box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
  cursor: pointer;
  transition: all 0.3s ease;
}

.list-item:hover {
  transform: translateY(-2px);
  box-shadow: 0 4px 20px rgba(0, 0, 0, 0.15);
}

/* ===== 表格样式 ===== */
.table {
  width: 100%;
  border-collapse: collapse;
  background: white;
  border-radius: 10px;
  overflow: hidden;
  box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
}

.table th,
.table td {
  padding: 12px 16px;
  text-align: left;
  border-bottom: 1px solid #e0e0e0;
}

.table th {
  background: #f8f9fa;
  font-weight: 600;
  color: #2c3e50;
}

.table tr:hover {
  background: #f8f9fa;
}

/* ===== 徽章样式 ===== */
.badge {
  display: inline-block;
  padding: 4px 8px;
  font-size: 12px;
  font-weight: 500;
  border-radius: 4px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.badge-primary {
  background: #007bff;
  color: white;
}

.badge-secondary {
  background: #6c757d;
  color: white;
}

.badge-success {
  background: #28a745;
  color: white;
}

.badge-danger {
  background: #dc3545;
  color: white;
}

.badge-warning {
  background: #ffc107;
  color: #212529;
}

.badge-info {
  background: #17a2b8;
  color: white;
}

/* ===== 工具提示样式 ===== */
.tooltip {
  position: relative;
  display: inline-block;
}

.tooltip .tooltiptext {
  visibility: hidden;
  width: 120px;
  background-color: #555;
  color: #fff;
  text-align: center;
  border-radius: 6px;
  padding: 5px 0;
  position: absolute;
  z-index: 1;
  bottom: 125%;
  left: 50%;
  margin-left: -60px;
  opacity: 0;
  transition: opacity 0.3s;
}

.tooltip .tooltiptext::after {
  content: "";
  position: absolute;
  top: 100%;
  left: 50%;
  margin-left: -5px;
  border-width: 5px;
  border-style: solid;
  border-color: #555 transparent transparent transparent;
}

.tooltip:hover .tooltiptext {
  visibility: visible;
  opacity: 1;
}

/* ===== 加载状态样式 ===== */
.loading {
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 20px;
  color: #6c757d;
}

.loading-spinner {
  width: 20px;
  height: 20px;
  border: 2px solid #f3f3f3;
  border-top: 2px solid #007bff;
  border-radius: 50%;
  animation: spin 1s linear infinite;
  margin-right: 10px;
}

@keyframes spin {
  0% {
    transform: rotate(0deg);
  }

  100% {
    transform: rotate(360deg);
  }
}

/* ===== 响应式设计 ===== */
@media (max-width: 768px) {
  .btn {
    padding: 10px 16px;
    font-size: 14px;
  }

  .btn-sm {
    padding: 8px 12px;
    font-size: 12px;
  }

  .page-content {
    padding: 15px;
  }

  .card-body {
    padding: 15px;
  }

  .table th,
  .table td {
    padding: 8px 12px;
    font-size: 14px;
  }
}

@media (max-width: 480px) {
  .page-content {
    padding: 10px;
  }

  .card-body {
    padding: 10px;
  }

  .btn {
    padding: 8px 12px;
    font-size: 12px;
  }
}
</style>
