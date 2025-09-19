<template>
  <div class="main-layout">
    <!-- 侧边栏 -->
    <div id="sidebar" class="sidebar" :class="{ hidden: !sidebarOpen }">
      <div class="sidebar-header">
        <h3>CEM 邮箱管理系统</h3>
        <!-- <p>用户面板</p> -->
      </div>

      <div class="sidebar-menu">
        <div class="sidebar-item" @click="navigateTo('dashboard')">🏠 仪表板</div>
        <div class="sidebar-item" @click="navigateTo('emails')">📧 我的邮件</div>
        <div class="sidebar-item" @click="navigateTo('mailboxes')">📮 我的邮箱</div>
        <div class="sidebar-item" @click="navigateTo('mailbox-applications')">📝 邮箱申请</div>
        <div class="sidebar-item" @click="navigateTo('settings')">⚙️ 账户设置</div>
        <div v-if="isDebugMode" class="sidebar-item" @click="navigateTo('debug')">🐛 调试模式</div>

        <div v-if="isAdmin" class="admin-menu">
          <div class="sidebar-item" @click="navigateTo('admin-users')">👥 用户管理</div>
          <div class="sidebar-item" @click="navigateTo('admin-rules')">🔄 转发规则</div>
          <div class="sidebar-item" @click="navigateTo('admin-emails')">📨 全部邮件</div>
          <div class="sidebar-item" @click="navigateTo('admin-mailboxes')">📮 邮箱管理</div>
          <div class="sidebar-item" @click="navigateTo('admin-applications')">📋 申请审核</div>
          <div class="sidebar-item" @click="navigateTo('admin-security-overview')">🛡️ 安全概览</div>
          <div class="sidebar-item" @click="navigateTo('admin-settings')">🛠️ 系统设置</div>
        </div>
      </div>

      <!-- 手机端底部按钮区域 -->
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
          <button class="btn btn-success btn-sm" @click="refreshConfig">🔄 刷新配置</button>
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
      <div class="content-area">
        <router-view />
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore } from '@/composables/stores'

const authStore = useAuthStore()
const router = useRouter()

// 定义事件
const emit = defineEmits<{
  'logout': []
}>()

// 侧边栏状态
const sidebarOpen = ref(false)

// 计算属性
const isAdmin = computed(() => authStore.user?.user_type === 'admin')
const isDebugMode = computed(() => {
  // 这里可以根据系统配置来判断是否显示调试模式
  return false
})

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

const navigateTo = (route: string) => {
  // 在移动端导航后关闭侧边栏
  if (window.innerWidth <= 768) {
    sidebarOpen.value = false
  }
  // 进行路由跳转
  router.push({ name: route })
}

const refreshConfig = async () => {
  // 这里可以刷新系统配置
  console.log('刷新配置')
  // 可以触发全局事件或调用相关服务
}

const handleLogout = () => {
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
/* ===== 主布局 ===== */
.main-layout {
  display: flex;
  width: 100%;
  height: 100vh;
  background: #f8f9fa;
}

/* ===== 侧边栏 ===== */
.sidebar {
  position: fixed;
  left: 0;
  top: 0;
  width: 250px;
  height: 100vh;
  background: #fff;
  border-right: 2px solid #e0e0e0;
  box-shadow: 2px 0 8px rgba(0, 0, 0, .16);
  color: black;
  z-index: 1000;
  transition: transform 0.3s ease;
  overflow-y: auto;
}

/* ===== 主内容区域 ===== */
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

/* ===== 顶部栏 ===== */
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

.sidebar.hidden {
  transform: translateX(-100%);
}

.sidebar-header {
  padding: 20px;
  border-bottom: 1px solid #d2d2d2;
}

.sidebar-header h3 {
  margin: 0 0 5px 0;
  font-size: 18px;
  font-weight: 600;
  color: #2c3e50;
}

.sidebar-header p {
  margin: 0;
  font-size: 14px;
  color: #6c757d;
}

.sidebar-menu {
  padding: 10px 0;
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
  /* color: black; */
  border: none;
  border-radius: 5px;
  cursor: pointer;
  text-align: center;
  border-right: 3px solid transparent;
  margin-bottom: 10px;
  transition: background 0.3s ease;
  /* background: #f8f9fa; */
}

.sidebar-footer>.btn-secondary:hover,
.sidebar-footer>.logout-btn:hover {
  /* background: #d2d2d2; */
  color: #3498db;
  border-right-color: #3498db;
}

.logout-btn {
  color: #e74c3c !important;
}

/* 主内容区域样式已在上面的 .main-content 中定义 */

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

.btn-sm {
  padding: 6px 12px;
  font-size: 12px;
}

/* ===== 内容区域 ===== */
.content-area {
  flex: 1;
  padding: 20px;
  overflow-y: auto;
  background: #f8f9fa;
  min-height: calc(100vh - 60px);
}

/* 欢迎卡片样式已移除，现在使用 router-view 显示内容 */

/* ===== 响应式设计 ===== */
@media (max-width: 768px) {
  .sidebar {
    width: 80%;
    max-width: 300px;
  }

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

  .content-area {
    padding: 15px;
  }
}

@media (max-width: 480px) {
  .sidebar {
    width: 90%;
  }

  .content-area {
    padding: 10px;
  }
}
</style>