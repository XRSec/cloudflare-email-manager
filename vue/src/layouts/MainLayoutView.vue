<template>
  <div class="main-layout">
    <!-- 侧边栏 -->
    <div id="sidebar" class="sidebar" :class="{ hidden: !sidebarOpen }">
      <!--    <div class="sidebar" :class="{ 'sidebar-open': sidebarOpen }">-->
      <div class="sidebar-header">
        <h2>CEM 邮箱管理系统</h2>
        <!-- <button class="sidebar-toggle" @click="toggleSidebar">
          ☰
        </button> -->
      </div>

      <div class="sidebar-menu">
        <router-link to="/" class="sidebar-item" :class="{ active: $route.path === '/' }" @click="closeSidebarOnMobile">
          🏠 仪表板
        </router-link>

        <router-link to="/emails" class="sidebar-item" :class="{ active: $route.path === '/emails' }"
          @click="closeSidebarOnMobile">
          📧 我的邮件
        </router-link>

        <router-link to="/mailboxes" class="sidebar-item" :class="{ active: $route.path === '/mailboxes' }"
          @click="closeSidebarOnMobile">
          📮 我的邮箱
        </router-link>

        <router-link to="/forward-rules" class="sidebar-item" :class="{ active: $route.path === '/forward-rules' }"
          @click="closeSidebarOnMobile">
          🔄 转发规则
        </router-link>

        <!-- 管理员菜单 -->
        <div v-if="isAdmin" class="admin-menu">
          <!--          <div class="section-title">管理员</div>-->
          <router-link v-if="isDebugMode" to="/debug" class="sidebar-item" :class="{ active: $route.path === '/debug' }"
            @click="closeSidebarOnMobile">
            🐛 调试模式
          </router-link>
          <router-link to="/admin-users" class="sidebar-item" :class="{ active: $route.path === '/admin-users' }"
            @click="closeSidebarOnMobile">
            👥 用户管理
          </router-link>

          <router-link to="/admin-rules" class="sidebar-item" :class="{ active: $route.path === '/admin-rules' }"
            @click="closeSidebarOnMobile">
            🔄 转发管理</router-link>

          <router-link to="/admin-emails" class="sidebar-item" :class="{ active: $route.path === '/admin-emails' }"
            @click="closeSidebarOnMobile">
            📨 全部邮件
          </router-link>

          <router-link to="/admin-mailboxes" class="sidebar-item"
            :class="{ active: $route.path === '/admin-mailboxes' }" @click="closeSidebarOnMobile">
            📮 邮箱管理
          </router-link>

          <router-link to="/admin-applications" class="sidebar-item"
            :class="{ active: $route.path === '/admin-applications' }" @click="closeSidebarOnMobile">
            📋 申请审核
          </router-link>

          <router-link to="/admin-security-overview" class="sidebar-item"
            :class="{ active: $route.path === '/admin-security-overview' }" @click="closeSidebarOnMobile">
            🛡️ 安全概览
          </router-link>

          <router-link to="/admin-settings" class="sidebar-item" :class="{ active: $route.path === '/admin-settings' }"
            @click="closeSidebarOnMobile">
            🛠️ 系统设置
          </router-link>
        </div>
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
          <button class="btn btn-secondary btn-sm" @click="toggleSidebar">☰ 菜单</button>
          <button class="btn btn-primary btn-sm" @click="refreshCurrentPage" :disabled="refreshing">
            {{ refreshing ? '🔄 刷新中...' : '🔄 刷新' }}
          </button>
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
import { ref, computed, onMounted } from 'vue'
import { useRoute } from 'vue-router'
import { useAuthStore } from '@/composables/stores'
import { useSystemStore } from '@/composables/system'
import { pageRefreshManager } from '@/composables/cache'

const authStore = useAuthStore()
const systemStore = useSystemStore()
const route = useRoute()

// 定义事件
const emit = defineEmits<{
  'logout': []
}>()

// 侧边栏状态
const sidebarOpen = ref(false)

// 刷新状态
const refreshing = ref(false)

// 计算属性
const isAdmin = computed(() => authStore.user?.user_type === 'admin')

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
    return authStore.user.user_type === 'admin' ? '管理员' : '普通用户'
  }
  return '用户'
})

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

// 刷新当前页面 - 简单直接的方式
const refreshCurrentPage = async () => {
  if (refreshing.value) return

  refreshing.value = true
  try {
    // 直接调用当前页面暴露的刷新方法
    if (window.refreshCurrentPage) {
      await window.refreshCurrentPage()
    } else {
      console.warn('当前页面没有暴露刷新方法')
    }
  } catch (error) {
    console.error('刷新页面失败:', error)
  } finally {
    refreshing.value = false
  }
}

// 处理退出登录
const handleLogout = () => {
  emit('logout')
}

// 初始化
onMounted(() => {
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
  min-height: 100vh;
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
  background: #6c757d;
  color: white;
}

.btn-secondary:hover {
  background: #5a6268;
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

/* ===== 页面内容样式 ===== */
.page-content {
  flex: 1;
  padding: 20px;
  overflow-y: auto;
  background: #f8f9fa;
  min-height: calc(100vh - 60px);
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
