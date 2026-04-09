import { createRouter, createWebHistory, type RouteLocationRaw } from 'vue-router'

// 动态导入组件
const LoginPage = () => import('@/pages/auth/LoginPage.vue')
const AppLayout = () => import('@/pages/app/AppLayout.vue')
const DashboardPage = () => import('@/pages/app/DashboardPage.vue')
const EmailsPage = () => import('@/pages/app/emails/EmailsPage.vue')
const RoutingPage = () => import('@/pages/app/routing/RoutingPage.vue')
const SystemSettingsPage = () => import('@/pages/app/settings/SystemSettingsPage.vue')
const ToolsPage = () => import('@/pages/app/tools/ToolsPage.vue')
const NotFoundPage = () => import('@/pages/system/NotFoundPage.vue')

const router = createRouter({
  history: createWebHistory(),
  routes: [
    {
      path: '/login',
      name: 'Login',
      component: LoginPage,
      meta: { requiresAuth: false }
    },
    {
      path: '/',
      component: AppLayout,
      meta: { requiresAuth: true },
      children: [
        {
          path: '',
          name: 'dashboard',
          component: DashboardPage
        },
        {
          path: 'all-emails',
          name: 'all-emails',
          component: EmailsPage
        },
        {
          path: 'routing',
          name: 'routing',
          component: RoutingPage
        },
        {
          path: 'system-settings',
          name: 'system-settings',
          component: SystemSettingsPage
        },
        {
          path: 'tools',
          name: 'tools',
          component: ToolsPage
        }
      ]
    },
    {
      path: '/:pathMatch(.*)*',
      name: 'NotFound',
      component: NotFoundPage,
      meta: { requiresAuth: false }
    }
  ]
})

type LazyRouteComponent = () => Promise<unknown>

const isLazyRouteComponent = (component: unknown): component is LazyRouteComponent => {
  return typeof component === 'function'
}

export const preloadLoginPage = async () => {
  return LoginPage()
}

export const preloadRouteComponents = async (target: RouteLocationRaw) => {
  const resolved = router.resolve(target)
  const componentLoaders = resolved.matched.flatMap((record) => {
    return Object.values(record.components || {}).filter(isLazyRouteComponent)
  })
  const uniqueLoaders = Array.from(new Set(componentLoaders))

  if (uniqueLoaders.length === 0) {
    return
  }

  await Promise.all(uniqueLoaders.map((loader) => loader()))
}

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

  // 工具页面不再要求调试模式（已移除 requiresDebug 限制）

  next()
})

export default router
