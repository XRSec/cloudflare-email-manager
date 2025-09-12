import { createRouter, createWebHistory } from 'vue-router'
import { useAuthStore } from '@/stores/auth'

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
      component: () => import('@/components/Layout/MainLayout.vue'),
      meta: { requiresAuth: true },
      children: [
        {
          path: '',
          name: 'dashboard',
          component: () => import('@/views/DashboardView.vue')
        },
        {
          path: 'emails',
          name: 'emails',
          component: () => import('@/views/EmailsView.vue')
        },
        {
          path: 'mailboxes',
          name: 'mailboxes',
          component: () => import('@/views/MailboxView.vue')
        },
        {
          path: 'applications',
          name: 'applications',
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
        }
      ]
    }
  ],
})

// 路由守卫
router.beforeEach(async (to, from, next) => {
  const authStore = useAuthStore()

  // 如果用户未登录且需要认证，重定向到登录页
  if (to.meta.requiresAuth && !authStore.isAuthenticated) {
    next('/login')
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
    // 这里可以根据系统配置判断是否允许调试模式
    // 暂时允许所有用户访问调试页面
    // next('/')
    // return
  }

  next()
})

export default router
