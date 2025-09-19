import { createRouter, createWebHistory } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import { useSystemStore } from '@/stores/system'

const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes: [
    {
      path: '/login',
      name: 'login',
      component: () => import('@/views/LoginView.vue'),
      meta: { requiresAuth: false }
    },
    {
      path: '/',
      component: () => import('@/views/MainLayoutView.vue'),
      meta: { requiresAuth: true },
      children: [
        {
          path: '',
          name: 'dashboard',
          component: () => import('@/views/DashboardView.vue')
        },
        {
          path: '/emails',
          name: 'emails',
          component: () => import('@/views/EmailsView.vue')
        },
        {
          path: '/mailboxes',
          name: 'mailboxes',
          component: () => import('@/views/MailboxView.vue')
        },
        {
          path: '/mailboxes/applications',
          name: 'mailbox-applications',
          component: () => import('@/views/ApplicationsView.vue')
        },
        {
          path: 'settings',
          name: 'settings',
          component: () => import('@/views/SettingsView.vue')
        },
        {
          path: 'debug',
          name: 'debug',
          component: () => import('@/views/DebugView.vue'),
          meta: { requiresDebug: true }
        },
        {
          path: 'test-antd',
          name: 'test-antd',
          component: () => import('@/views/TestAntd.vue'),
          meta: { requiresAuth: false }
        },
        // 管理员路由
        {
          path: 'admin-users',
          name: 'admin-users',
          component: () => import('@/views/admin/UsersView.vue'),
          meta: { requiresAdmin: true }
        },
        {
          path: 'admin-rules',
          name: 'admin-rules',
          component: () => import('@/views/admin/ForwardRulesView.vue'),
          meta: { requiresAdmin: true }
        },
        {
          path: 'admin-emails',
          name: 'admin-emails',
          component: () => import('@/views/admin/EmailsView.vue'),
          meta: { requiresAdmin: true }
        },
        {
          path: 'admin-mailboxes',
          name: 'admin-mailboxes',
          component: () => import('@/views/admin/MailboxesView.vue'),
          meta: { requiresAdmin: true }
        },
        {
          path: 'admin-applications',
          name: 'admin-applications',
          component: () => import('@/views/admin/ApplicationsView.vue'),
          meta: { requiresAdmin: true }
        },
        {
          path: 'admin-settings',
          name: 'admin-settings',
          component: () => import('@/views/admin/SettingsView.vue'),
          meta: { requiresAdmin: true }
        },
        {
          path: 'admin-security-overview',
          name: 'admin-security-overview',
          component: () => import('@/views/admin/SecurityOverview.vue'),
          meta: { requiresAdmin: true }
        }
      ]
    },
    {
      path: '/:pathMatch(.*)*',
      name: 'not-found',
      component: () => import('@/views/NotFoundView.vue'),
      meta: { requiresAuth: false }
    }
  ],
})

// 路由守卫
router.beforeEach(async (to, from, next) => {
  const authStore = useAuthStore()
  const { useGlobalLoading } = await import('@/composables/useLoading')
  const globalLoading = useGlobalLoading()

  // 如果页面需要认证，先初始化认证状态
  if (to.meta.requiresAuth) {
    // 如果用户信息为空，尝试初始化认证状态
    if (!authStore.user) {
      globalLoading.setLoading(true, '验证用户身份...')
      try {
        await authStore.initAuth()
      } finally {
        globalLoading.setLoading(false)
      }
    }
  }

  // 如果用户未登录且需要认证，重定向到登录页
  if (to.meta.requiresAuth && !authStore.isAuthenticated) {
    // 将当前页面URL作为重定向参数
    const redirectUrl = encodeURIComponent(to.fullPath)
    next(`/login?redirect=${redirectUrl}`)
    return
  }

  // 如果用户已登录且访问登录页，重定向到首页
  if (to.name === 'login' && authStore.isAuthenticated) {
    next('/')
    return
  }

  // 如果访问管理员页面但用户不是管理员，重定向到首页
  if (to.meta.requiresAdmin && !authStore.isAdmin) {
    next('/')
    return
  }

  // 如果访问调试页面但不在调试模式，重定向到首页
  if (to.meta.requiresDebug) {
    // 检查系统配置中的debug模式
    const systemStore = useSystemStore()
    if (!systemStore.isDebugMode) {
      next('/')
      return
    }
  }

  next()
})

export default router
