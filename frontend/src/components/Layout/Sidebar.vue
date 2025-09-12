<template>
  <div id="sidebar" class="sidebar" :class="{ hidden: !isOpen }">
    <div class="sidebar-header">
      <h3>邮箱管理</h3>
      <p id="sidebarUserInfo">用户面板</p>
    </div>

    <div class="sidebar-menu">
      <a href="#emails" class="sidebar-item" @click="navigateTo('emails')">📧 我的邮件</a>
      <a href="#mailboxes" class="sidebar-item" @click="navigateTo('mailboxes')">📮 我的邮箱</a>
      <a href="#applications" class="sidebar-item" @click="navigateTo('applications')">📝 邮箱申请</a>
      <a href="#settings" class="sidebar-item" @click="navigateTo('settings')">⚙️ 账户设置</a>
      <a href="#debug" v-if="isDebugMode" class="sidebar-item" @click="navigateTo('debug')">🐛 调试模式</a>
      
      <div v-if="isAdmin" class="admin-menu">
        <a href="#admin-users" class="sidebar-item" @click="navigateTo('admin-users')">👥 用户管理</a>
        <a href="#admin-rules" class="sidebar-item" @click="navigateTo('admin-rules')">🔄 转发规则</a>
        <a href="#admin-emails" class="sidebar-item" @click="navigateTo('admin-emails')">📨 全部邮件</a>
        <a href="#admin-mailboxes" class="sidebar-item" @click="navigateTo('admin-mailboxes')">📮 邮箱管理</a>
        <a href="#admin-applications" class="sidebar-item" @click="navigateTo('admin-applications')">📋 申请审核</a>
        <a href="#admin-settings" class="sidebar-item" @click="navigateTo('admin-settings')">🛠️ 系统设置</a>
      </div>
    </div>

    <!-- 手机端底部按钮区域 -->
    <div class="sidebar-footer">
      <div class="btn-secondary" @click="toggleSidebar">☰ 关闭菜单</div>
      <div class="sidebar-item logout-btn" @click="handleLogout">🚪 退出登录</div>
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

const handleLogout = async () => {
  await authStore.logout()
  router.push('/login')
}
</script>

<style scoped>
.sidebar {
  position: fixed;
  left: 0;
  top: 0;
  width: 250px;
  height: 100vh;
  background: #2c3e50;
  color: white;
  z-index: 1000;
  transition: transform 0.3s ease;
  overflow-y: auto;
}

.sidebar.hidden {
  transform: translateX(-100%);
}

.sidebar-header {
  padding: 20px;
  border-bottom: 1px solid #34495e;
}

.sidebar-header h3 {
  margin: 0 0 5px 0;
  font-size: 18px;
  font-weight: 600;
}

.sidebar-header p {
  margin: 0;
  font-size: 14px;
  color: #bdc3c7;
}

.sidebar-menu {
  padding: 10px 0;
}

.sidebar-item {
  display: block;
  padding: 12px 20px;
  color: #ecf0f1;
  text-decoration: none;
  transition: all 0.3s ease;
  border-left: 3px solid transparent;
}

.sidebar-item:hover {
  background: #34495e;
  color: #3498db;
  border-left-color: #3498db;
}

.admin-menu {
  border-top: 1px solid #34495e;
  margin-top: 10px;
  padding-top: 10px;
}

.sidebar-footer {
  position: absolute;
  bottom: 0;
  left: 0;
  right: 0;
  padding: 20px;
  border-top: 1px solid #34495e;
}

.btn-secondary {
  display: block;
  padding: 8px 15px;
  background: #34495e;
  color: white;
  border: none;
  border-radius: 5px;
  cursor: pointer;
  text-align: center;
  margin-bottom: 10px;
  transition: background 0.3s ease;
}

.btn-secondary:hover {
  background: #4a5f7a;
}

.logout-btn {
  color: #e74c3c !important;
  cursor: pointer;
}

.logout-btn:hover {
  background: #34495e;
  color: #c0392b !important;
}

@media (max-width: 768px) {
  .sidebar {
    width: 100%;
  }
}
</style>
