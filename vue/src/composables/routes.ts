import { createRouter, createWebHistory } from 'vue-router'

// 动态导入组件
const LoginView = () => import('@/layouts/LoginView.vue')
const MainLayoutView = () => import('@/layouts/MainLayoutView.vue')
const DashboardView = () => import('@/layouts/Admin/DashboardView.vue')
const EmailsView = () => import('@/layouts/Admin/EmailsView.vue')
const MailboxesView = () => import('@/layouts/Admin/MailboxesView.vue')
const ApplicationsView = () => import('@/layouts/Admin/ApplicationsView.vue')
const SettingsView = () => import('@/layouts/Admin/SettingsView.vue')
const UsersView = () => import('@/layouts/Admin/UsersView.vue')
const ForwardRulesView = () => import('@/layouts/Admin/ForwardRulesView.vue')
const SecurityOverviewView = () => import('@/layouts/Admin/SecurityOverviewView.vue')
const DebugView = () => import('@/layouts/Admin/DebugView.vue')

const router = createRouter({
  history: createWebHistory(),
  routes: [
    {
      path: '/login',
      name: 'Login',
      component: LoginView,
      meta: { requiresAuth: false }
    },
    {
      path: '/',
      component: MainLayoutView,
      meta: { requiresAuth: true },
      children: [
        {
          path: '',
          name: 'dashboard',
          component: DashboardView
        },
        {
          path: 'emails',
          name: 'emails',
          component: EmailsView
        },
        {
          path: 'mailboxes',
          name: 'mailboxes',
          component: MailboxesView
        },
        {
          path: 'forward-rules',
          name: 'forward-rules',
          component: ForwardRulesView
        },
        {
          path: 'mailbox-applications',
          name: 'mailbox-applications',
          component: ApplicationsView
        },
        {
          path: 'settings',
          name: 'settings',
          component: SettingsView
        },
        {
          path: 'debug',
          name: 'debug',
          component: DebugView,
          meta: { requiresDebug: true }
        },
        {
          path: 'admin-users',
          name: 'admin-users',
          component: UsersView
        },
        {
          path: 'admin-rules',
          name: 'admin-rules',
          component: ForwardRulesView
        },
        {
          path: 'admin-emails',
          name: 'admin-emails',
          component: EmailsView
        },
        {
          path: 'admin-mailboxes',
          name: 'admin-mailboxes',
          component: MailboxesView
        },
        {
          path: 'admin-applications',
          name: 'admin-applications',
          component: ApplicationsView
        },
        {
          path: 'admin-security-overview',
          name: 'admin-security-overview',
          component: SecurityOverviewView
        },
        {
          path: 'admin-settings',
          name: 'admin-settings',
          component: SettingsView
        }
      ]
    }
  ]
})

// 路由守卫 - 简化版本，避免在路由守卫中使用 store
router.beforeEach((to, _from, next) => {
  // 检查是否需要认证
  if (to.meta.requiresAuth) {
    // 检查 localStorage 中是否有用户信息
    const userInfo = localStorage.getItem('user_info')
    if (!userInfo) {
      next('/login')
      return
    }
  }

  // 如果已经在登录页且有用户信息，重定向到首页
  if (to.path === '/login') {
    const userInfo = localStorage.getItem('user_info')
    if (userInfo) {
      next('/')
      return
    }
  }

  // 检查调试模式权限
  if (to.meta.requiresDebug) {
    const isDebugMode = import.meta.env.DEV || import.meta.env.VITE_DEBUG === 'true'
    if (!isDebugMode) {
      next('/')
      return
    }
  }

  next()
})

export default router
