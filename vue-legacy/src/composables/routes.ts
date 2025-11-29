import { createRouter, createWebHistory } from 'vue-router'
import { useSystemStore } from './system'

// 动态导入组件
const LoginView = () => import('@/views/auth/LoginView.vue')
const MainLayout = () => import('@/views/shared/layouts/MainLayout.vue')

// 共享视图
const DashboardView = () => import('@/views/shared/dashboard/DashboardView.vue')

// 用户视图
const UserMyEmailsView = () => import('@/views/user/emails/MyEmailsView.vue')
const UserMyMailboxesView = () => import('@/views/user/mailboxes/MyMailboxesView.vue')
const UserPersonalSettingsView = () => import('@/views/user/settings/PersonalSettingsView.vue')

// 管理员视图
const AdminAllEmailsView = () => import('@/views/admin/emails/AllEmailsView.vue')
const AdminMailboxManagementView = () => import('@/views/admin/mailboxes/MailboxManagementView.vue')
const AdminSystemSettingsView = () => import('@/views/admin/settings/SystemSettingsView.vue')
const AdminUsersView = () => import('@/views/admin/users/UsersView.vue')
const AdminForwardRulesView = () => import('@/views/admin/mailboxes/ForwardRulesView.vue')
const AdminSecurityOverviewView = () => import('@/views/admin/security/SecurityOverviewView.vue')
const AdminDebugView = () => import('@/views/admin/settings/DebugView.vue')

// 错误页面
const NotFoundView = () => import('@/views/shared/error/NotFoundView.vue')

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
      component: MainLayout,
      meta: { requiresAuth: true },
      children: [
        // 仪表板
        {
          path: '',
          name: 'dashboard',
          component: DashboardView
        },

        // 用户页面
        {
          path: 'my-emails',
          name: 'my-emails',
          component: UserMyEmailsView
        },
        {
          path: 'my-mailboxes',
          name: 'my-mailboxes',
          component: UserMyMailboxesView
        },
        {
          path: 'forward-rules',
          name: 'forward-rules',
          component: AdminForwardRulesView
        },
        {
          path: 'personal-settings',
          name: 'personal-settings',
          component: UserPersonalSettingsView
        },

        // 管理员页面
        {
          path: 'all-emails',
          name: 'all-emails',
          component: AdminAllEmailsView
        },
        {
          path: 'mailbox-management',
          name: 'mailbox-management',
          component: AdminMailboxManagementView
        },
        {
          path: 'admin-users',
          name: 'admin-users',
          component: AdminUsersView
        },
        {
          path: 'admin-rules',
          name: 'admin-rules',
          component: AdminForwardRulesView
        },
        {
          path: 'admin-security-overview',
          name: 'admin-security-overview',
          component: AdminSecurityOverviewView
        },
        {
          path: 'system-settings',
          name: 'system-settings',
          component: AdminSystemSettingsView
        },
        {
          path: 'debug',
          name: 'debug',
          component: AdminDebugView,
          meta: { requiresDebug: true }
        }
      ]
    },
    // 404 错误页面
    {
      path: '/:pathMatch(.*)*',
      name: 'NotFound',
      component: NotFoundView,
      meta: { requiresAuth: false }
    }
  ]
})

// 路由守卫 - 简化版本，避免在路由守卫中使用 store
router.beforeEach(async (to, _from, next) => {
  // 检查是否需要认证
  if (to.meta.requiresAuth) {
    // 检查 localStorage 中是否有用户信息
    const userInfo = localStorage.getItem('user_info')
    if (!userInfo) {
      // 如果是根路径，直接跳转到登录页（避免 redirect=%2F）
      if (to.path === '/') {
        next('/login')
      } else {
        // 其他路径，携带重定向参数
        const redirectUrl = encodeURIComponent(to.fullPath)
        next(`/login?redirect=${redirectUrl}`)
      }
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
    const systemStore = useSystemStore()

    // 总是获取最新的系统健康状态（包含调试模式配置）
    // health 接口无需认证，适合在路由守卫中使用
    if (!systemStore.systemConfig) {
      await systemStore.fetchSystemHealth()
    }

    if (systemStore.systemConfig?.debug_mode !== 1) {
      next('/')
      return
    }
  }

  next()
})

export default router
