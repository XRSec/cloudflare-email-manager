<template>
  <div id="sidebar" class="sidebar" :class="{ hidden: !isOpen }">
    <div class="sidebar-header">
      <h3>邮箱管理</h3>
      <p id="sidebarUserInfo">用户面板</p>
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
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore } from '@/stores/auth'

interface Props {
  isOpen: boolean
}

interface Emits {
  (e: 'toggle'): void
  (e: 'navigate', route: string): void
  (e: 'logout'): void
}

const props = defineProps<Props>()
const emit = defineEmits<Emits>()

const router = useRouter()
const authStore = useAuthStore()

const isAdmin = computed(() => authStore.isAdmin)
const isDebugMode = computed(() => {
  // 这里可以根据系统配置来判断是否显示调试模式
  return false
})

const navigateTo = (route: string) => {
  emit('navigate', route)
  router.push({ name: route })
}

const toggleSidebar = () => {
  emit('toggle')
}

const handleLogout = () => {
  // 触发退出登录事件，让 App.vue 处理
  emit('logout')
}
</script>

<style scoped>
.sidebar {
  position: fixed;
  left: 5px;
  top: 5px;
  width: 250px;
  height: 98vh;
  background: #fff;
  border: 2px solid #e0e0e0;
  border-radius: 5px 5px 5px 5px;
  box-shadow: 0 4px 8px rgba(0, 0, 0, .16);
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

.sidebar-header h3 {
  margin: 0 0 5px 0;
  font-size: 18px;
  font-weight: 600;
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
  /* color: #ecf0f1; */
  text-decoration: none;
  transition: all 0.3s ease;
  border-right: 3px solid transparent;
  cursor: pointer;
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

.btn-secondary,
.logout-btn {
  display: block;
  padding: 8px 15px;
  /* background: #34495e; */
  color: black;
  border: none;
  border-radius: 5px;
  cursor: pointer;
  text-align: center;
  border-right: 3px solid transparent;
  margin-bottom: 10px;
  transition: background 0.3s ease;
}

.btn-secondary:hover,
.logout-btn:hover {
  background: #d2d2d2;
  color: #3498db;
  border-right-color: #3498db;
}

.logout-btn {
  color: #e74c3c !important;
}

@media (max-width: 768px) {
  .sidebar {
    width: 50%;
  }
}
</style>
