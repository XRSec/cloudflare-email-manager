<template>
  <div class="main-layout">
    <!-- 侧边栏 -->
    <div id="sidebar" class="sidebar" :class="{ hidden: !sidebarOpen }">
      <!--    <div class="sidebar" :class="{ 'sidebar-open': sidebarOpen }">-->
      <div class="sidebar-header">
        <h2>CEM 邮箱管理系统</h2>
      </div>
      <div class="sidebar-menu">
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

    <div v-if="sidebarOpen" class="sidebar-backdrop" @click="toggleSidebar"></div>

    <!-- 主内容区域 -->
    <div class="main-content" :class="{ 'sidebar-open': sidebarOpen }">
      <!-- 顶部栏 -->
      <div class="top-bar">
        <div class="left-section">
          <Button variant="secondary" size="sm" @click="toggleSidebar">
            <span class="btn-emoji">☰</span>
            <span>菜单</span>
          </Button>
          <Button variant="primary" size="sm" @click="refreshCurrentPage" :disabled="refreshing">
            <span class="btn-emoji">{{ refreshing ? '🔄' : '🔄' }}</span>
            <span>{{ refreshing ? '刷新中...' : '刷新' }}</span>
          </Button>
        </div>
        <div class="user-info clickable" @click="openUserInfoModal">
          <div class="user-avatar">
            {{ userInitials }}
          </div>
          <div class="user-details">
            <div class="user-name">{{ authStore.user?.username || '未登录' }}</div>
          </div>
        </div>
      </div>

      <!-- 页面内容 -->
      <div class="page-content">
        <router-view />
      </div>
    </div>

    <!-- 修改用户信息模态框 -->
    <Modal :show="showPasswordModal" title="修改用户信息" @close="closePasswordModal" size="small">
      <form @submit.prevent="handleChangeUserInfo">
        <FormField v-model="userForm.username" label="用户名" type="text" placeholder="请输入用户名（3-50个字符）" />
        <FormField v-model="userForm.newPassword" label="新密码" type="password" placeholder="请输入新密码（至少6位，留空则不修改）" />
        <FormField v-model="userForm.confirmPassword" label="确认密码" type="password" placeholder="请再次输入新密码" />
        <div v-if="passwordError" class="error-message">{{ passwordError }}</div>
      </form>
      <template #footer>
        <Button variant="secondary" @click="closePasswordModal">取消</Button>
        <Button variant="primary" @click="handleChangeUserInfo" :disabled="changingPassword">
          {{ changingPassword ? '修改中...' : '确认修改' }}
        </Button>
      </template>
    </Modal>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onBeforeUnmount, nextTick } from 'vue'
import { useRoute } from 'vue-router'
import { useAuthStore } from '@/composables/auth'
import { useSystemStore } from '@/composables/system'
import { useUnifiedGlobalRefreshManager } from '@/composables/globalRefreshManager'
import { Button, Modal, FormField } from '@/components/common'
import { userApiService } from '@/composables/api-user'
import { toast } from '@/utils/toast'
// 在开发模式下导入测试
if (import.meta.env.DEV) {
  import('@/composables/testRouteApiMapper')
  import('@/composables/testCacheKeys')
}

const authStore = useAuthStore()
const systemStore = useSystemStore()
const route = useRoute()

interface NavigationItem {
  path: string
  title: string
  icon: string
  show: boolean
  exactMatch: boolean
  badge?: string
  badgeClass?: string
}

interface NavigationSection {
  title: string
  show: boolean
  items: NavigationItem[]
}

// 定义事件
const emit = defineEmits<{
  'logout': []
}>()

// 侧边栏状态
const sidebarOpen = ref(false)

// 使用统一全局刷新管理器
const { executeGlobalRefresh, isRefreshing, getCurrentPageRefreshInfo } = useUnifiedGlobalRefreshManager()
let changeSignalInterval: number | null = null
const CHANGE_SIGNAL_INTERVAL = 30 * 1000

// 刷新状态
// 使用统一刷新管理器的状态
const refreshing = isRefreshing

const userInitials = computed(() => {
  if (authStore.user?.username) {
    return authStore.user.username.charAt(0).toUpperCase()
  }
  return 'A'
})

const navigationSections = computed<NavigationSection[]>(() => [
  {
    title: '',
    show: true,
    items: [
      {
        path: '/',
        title: '仪表板',
        icon: '📊',
        show: true,
        exactMatch: true
      },
      {
        path: '/all-emails',
        title: '全部邮件',
        icon: '📨',
        show: true,
        exactMatch: false
      },
      {
        path: '/routing',
        title: '消息路由',
        icon: '🧭',
        show: true,
        exactMatch: false
      },
      {
        path: '/system-settings',
        title: '系统设置',
        icon: '⚙️',
        show: true,
        exactMatch: false
      },
      {
        path: '/tools',
        title: '工具',
        icon: '🛠️',
        show: true,
        exactMatch: true
      }
    ]
  }
])

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

const checkScreenSize = () => {
  if (window.innerWidth < 768) {
    sidebarOpen.value = false
  } else {
    sidebarOpen.value = true
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

const shouldRefreshCurrentRoute = (changedKeys: string[]) => {
  const routeName = route.name as string | undefined
  if (!routeName) return false

  const dependencies: Record<string, string[]> = {
    dashboard: ['emails', 'dashboard', 'forward_logs'],
    'all-emails': ['emails'],
    routing: ['routing_config', 'forward_logs', 'dashboard', 'system_config'],
    'system-settings': ['system_config'],
    tools: ['emails', 'dashboard', 'forward_logs', 'routing_config', 'system_config']
  }

  const routeDependencies = dependencies[routeName]
  if (!routeDependencies) return false
  return changedKeys.some((key) => routeDependencies.includes(key))
}

const checkChangeSignals = async () => {
  if (document.hidden) return

  const result = await systemStore.fetchSystemChanges()
  const changedKeys = result.success ? (result as { changedKeys?: string[] }).changedKeys || [] : []

  if (changedKeys.length > 0 && shouldRefreshCurrentRoute(changedKeys)) {
    console.log('🔄 检测到后端数据变更，刷新当前页面:', changedKeys)
    await executeGlobalRefresh()
  }
}

const startChangeSignalPolling = () => {
  if (changeSignalInterval) return
  changeSignalInterval = window.setInterval(() => {
    void checkChangeSignals()
  }, CHANGE_SIGNAL_INTERVAL)
}

const stopChangeSignalPolling = () => {
  if (!changeSignalInterval) return
  clearInterval(changeSignalInterval)
  changeSignalInterval = null
}

// 处理退出登录
const handleLogout = () => {
  emit('logout')
}

// 修改用户信息相关
const showPasswordModal = ref(false)
const changingPassword = ref(false)
const passwordError = ref('')
const userForm = ref({
  username: '',
  newPassword: '',
  confirmPassword: ''
})

const openUserInfoModal = () => {
  // 初始化表单，使用当前用户名
  userForm.value = {
    username: authStore.user?.username || '',
    newPassword: '',
    confirmPassword: ''
  }
  showPasswordModal.value = true
}

const closePasswordModal = () => {
  showPasswordModal.value = false
  userForm.value = {
    username: '',
    newPassword: '',
    confirmPassword: ''
  }
  passwordError.value = ''
}

const handleChangeUserInfo = async () => {
  // 验证：至少需要修改用户名或密码中的一项
  const hasUsernameChange = userForm.value.username && userForm.value.username !== authStore.user?.username
  const hasPasswordChange = userForm.value.newPassword || userForm.value.confirmPassword

  if (!hasUsernameChange && !hasPasswordChange) {
    passwordError.value = '请至少修改用户名或密码中的一项'
    return
  }

  // 验证用户名
  if (hasUsernameChange) {
    const username = userForm.value.username.trim()
    if (username.length < 3 || username.length > 50) {
      passwordError.value = '用户名长度必须在3-50个字符之间'
      return
    }
  }

  // 验证密码（如果填写了密码）
  if (hasPasswordChange) {
    if (!userForm.value.newPassword || !userForm.value.confirmPassword) {
      passwordError.value = '修改密码时，新密码和确认密码都需要填写'
      return
    }

    if (userForm.value.newPassword.length < 6) {
      passwordError.value = '密码长度至少为6位'
      return
    }

    if (userForm.value.newPassword !== userForm.value.confirmPassword) {
      passwordError.value = '两次输入的密码不一致'
      return
    }
  }

  changingPassword.value = true
  passwordError.value = ''

  try {
    const updateData: any = {}

    // 如果修改了用户名，添加到更新数据
    if (hasUsernameChange) {
      updateData.username = userForm.value.username.trim()
    }

    // 如果修改了密码，添加到更新数据
    if (hasPasswordChange) {
      updateData.password = userForm.value.newPassword
      updateData.password_confirm = userForm.value.confirmPassword
    }

    const response = await userApiService.updateUserSettings(updateData)

    if (response.success) {
      // 如果修改了用户名，刷新用户信息
      if (hasUsernameChange) {
        await authStore.fetchCurrentUser()
      }
      toast.success('用户信息修改成功')
      closePasswordModal()
    } else {
      passwordError.value = response.message || '用户信息修改失败'
    }
  } catch (error: any) {
    console.error('修改用户信息失败:', error)
    passwordError.value = error.response?.data?.message || error.message || '用户信息修改失败'
  } finally {
    changingPassword.value = false
  }
}

// 初始化
onMounted(async () => {
  // 获取系统配置（包括调试模式设置）
  // fetchSystemHealth 无需认证，适合在后台布局中使用
  await systemStore.fetchSystemHealth()
  startChangeSignalPolling()

  // 强制触发响应式更新
  nextTick(() => {
    if (systemStore.systemConfig) {
      // 触发计算属性重新计算
      systemStore.systemConfig = { ...systemStore.systemConfig }
    }
  })

  checkScreenSize()
  window.addEventListener('resize', checkScreenSize)
})

onBeforeUnmount(() => {
  stopChangeSignalPolling()
  window.removeEventListener('resize', checkScreenSize)
})
</script>

<style scoped>
/* ===== 主布局样式 ===== */
.main-layout {
  display: flex;
  width: 100%;
  height: 100vh;
  overflow: hidden;
  background:
    radial-gradient(circle at top left, rgba(43, 103, 246, 0.10), transparent 30%),
    linear-gradient(180deg, #eef4fa 0%, #f7fafc 38%, #eef4ed 100%);
}

/* ===== 侧边栏样式 ===== */
.sidebar {
  position: fixed;
  left: 0;
  top: 0;
  /* width: clamp(184px, 16vw, 204px); */
  height: 100vh;
  background: rgba(255, 255, 255, 0.86);
  border-right: 1px solid rgba(15, 23, 42, 0.08);
  box-shadow: 0 26px 42px -34px rgba(15, 23, 42, 0.65);
  color: black;
  z-index: 1000;
  transition: transform 0.3s ease;
  /* 使用flex布局，让header在顶部、footer在底部，中间区域可滚动 */
  display: flex;
  flex-direction: column;
  overflow: hidden;
  backdrop-filter: blur(14px);
  box-sizing: border-box;
}

.sidebar.hidden {
  transform: translateX(-100%);
}

.sidebar-header {
  width: 100%;
  box-sizing: border-box;
  padding: 24px 20px 18px;
  border-bottom: 1px solid rgba(15, 23, 42, 0.08);
}

.sidebar-header h2 {
  margin: 0;
  font-size: 20px;
  font-weight: 700;
  color: #163047;
  line-height: 1.2;
  letter-spacing: -0.04em;
}

.sidebar-menu {
  width: 100%;
  box-sizing: border-box;
  padding: 10px 0;
  /* 占据中间可用空间并单独滚动 */
  flex: 1;
  overflow-y: auto;
  min-height: 0;
  /* 隐藏滚动条但保留滚动功能 */
  scrollbar-width: none;
  /* Firefox */
  -ms-overflow-style: none;
  /* IE 和 Edge */
}

/* Chrome, Safari 和 Opera 隐藏滚动条 */
.sidebar-menu::-webkit-scrollbar {
  display: none;
}

.sidebar-menu .active {
  background: rgba(43, 103, 246, 0.10);
  color: #215de0;
  border-right-color: #215de0;
}

.sidebar-item {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 12px 20px;
  text-decoration: none;
  transition: all 0.3s ease;
  border-right: 3px solid transparent;
  cursor: pointer;
  color: #2e475d;
  font-weight: 500;
}

.sidebar-item:hover {
  background: rgba(21, 52, 82, 0.06);
  color: #215de0;
  border-right-color: #8cb2ff;
}

.sidebar-item.active {
  background: linear-gradient(90deg, rgba(43, 103, 246, 0.12), rgba(43, 103, 246, 0.03));
  color: #1746af;
  border-right-color: #2b67f6;
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
  color: #708090;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  padding: 8px 20px 4px;
  margin-top: 10px;
  border-bottom: 1px solid rgba(15, 23, 42, 0.08);
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
  /* 不再绝对定位，交给flex布局，将footer推到底部 */
  width: 100%;
  box-sizing: border-box;
  padding: 15px;
  border-top: 1px solid rgba(15, 23, 42, 0.08);
  flex-shrink: 0;
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
  width: 100%;
  min-width: 0;
  margin-left: 0;
  transition: margin-left 0.3s ease;
  min-height: 98vh;
  position: relative;
}

.main-content.sidebar-open {
  margin-left: clamp(184px, 16vw, 204px);
}

/* ===== 顶部栏样式 ===== */
.top-bar {
  background: rgba(255, 255, 255, 0.75);
  padding: 16px 22px;
  border-bottom: 1px solid rgba(15, 23, 42, 0.08);
  backdrop-filter: blur(14px);
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 12px 18px;
  z-index: 1001;
  position: sticky;
  top: 0;
  min-height: 72px;
  flex-shrink: 0;
}

.left-section {
  display: flex;
  gap: 10px;
  flex-wrap: wrap;
  align-items: center;
  flex: 1;
  min-width: 0;
}

.left-section :deep(.btn) {
  white-space: nowrap;
}

.btn-emoji {
  display: inline-flex;
  margin-right: 4px;
}

.user-info {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 8px 10px;
  border-radius: 18px;
  border: 1px solid transparent;
  flex-shrink: 0;
}

.user-info.clickable {
  cursor: pointer;
  transition: background-color 0.2s;
}

.user-info.clickable:hover {
  background-color: rgba(21, 52, 82, 0.05);
  border-color: rgba(21, 52, 82, 0.08);
}

.user-avatar {
  width: 44px;
  height: 44px;
  border-radius: 50%;
  background: linear-gradient(135deg, #2b67f6 0%, #5aa9ff 100%);
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
  min-width: 0;
}

.user-name {
  font-size: 0.92rem;
  font-weight: 600;
  color: #17324a;
}

.user-type {
  font-size: 0.78rem;
  color: #607286;
}

/* AppLayout 特有的样式在下面的 <style scoped> 块中 */

.sidebar-backdrop {
  position: fixed;
  inset: 0;
  background: rgba(14, 24, 37, 0.34);
  backdrop-filter: blur(4px);
  z-index: 999;
  display: none;
}

/* ===== 响应式设计 ===== */
@media (max-width: 768px) {
  .sidebar {
    /* width: clamp(216px, 70vw, 252px); */
    /* max-width: clamp(216px, 70vw, 252px); */
  }

  .main-content.sidebar-open {
    margin-left: 0;
  }

  .top-bar {
    padding: 14px 16px;
    min-height: 64px;
    align-items: center;
    gap: 10px;
    flex-wrap: nowrap;
  }

  .left-section {
    width: auto;
    flex: 0 1 auto;
    display: flex;
    flex-wrap: nowrap;
    gap: 8px;
  }

  .user-info {
    width: fit-content;
    padding: 6px 10px;
    margin-left: auto;
  }

  .sidebar-backdrop {
    display: block;
  }
}

@media (max-width: 480px) {
  .top-bar {
    padding: 12px;
    align-items: center;
  }

  .left-section {
    width: auto;
    flex: 0 1 auto;
    display: flex;
    gap: 6px;
  }

  .user-info {
    width: auto;
    justify-content: flex-start;
    margin-left: 0;
  }
}

@media (max-width: 560px) {
  .btn-emoji {
    display: none;
  }

  .left-section :deep(.btn.btn-sm) {
    padding-inline: 10px;
  }

  .top-bar {
    gap: 8px;
  }

  .user-info {
    padding: 6px 8px;
    gap: 8px;
  }

  .user-avatar {
    width: 38px;
    height: 38px;
    font-size: 14px;
  }
}

.error-message {
  color: #e74c3c;
  font-size: 14px;
  margin-top: 10px;
  padding: 8px;
  background: #fee;
  border-radius: 4px;
  border: 1px solid #fcc;
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
  padding: 28px;
  overflow-y: auto;
  background: transparent;
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
    padding: 18px 14px 28px;
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
    padding: 14px 12px 24px;
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
