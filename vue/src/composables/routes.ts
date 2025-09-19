import { createRouter, createWebHistory } from 'vue-router'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    {
      path: '/login',
      name: 'Login',
      component: () => import('@/layouts/LoginView.vue'),
      meta: { requiresAuth: false }
    },
    {
      path: '/',
      component: () => import('@/layouts/MainLayoutView.vue'),
      meta: { requiresAuth: true },
      children: [
        {
          path: '',
          name: 'dashboard',
          component: () => import('@/layouts/Admin/DashboardView.vue')
        },
        {
          path: 'emails',
          name: 'emails',
          component: () => import('@/layouts/Admin/EmailsView.vue')
        },
        {
          path: 'mailboxes',
          name: 'mailboxes',
          component: () => import('@/layouts/Admin/MailboxesView.vue')
        },
        {
          path: 'mailbox-applications',
          name: 'mailbox-applications',
          component: () => import('@/layouts/Admin/ApplicationsView.vue')
        },
        {
          path: 'settings',
          name: 'settings',
          component: () => import('@/layouts/Admin/SettingsView.vue')
        },
        {
          path: 'admin-users',
          name: 'admin-users',
          component: () => import('@/layouts/Admin/UsersView.vue')
        },
        {
          path: 'admin-rules',
          name: 'admin-rules',
          component: () => import('@/layouts/Admin/ForwardRulesView.vue')
        },
        {
          path: 'admin-emails',
          name: 'admin-emails',
          component: () => import('@/layouts/Admin/AllEmailsView.vue')
        },
        {
          path: 'admin-mailboxes',
          name: 'admin-mailboxes',
          component: () => import('@/layouts/Admin/MailboxesView.vue')
        },
        {
          path: 'admin-applications',
          name: 'admin-applications',
          component: () => import('@/layouts/Admin/ApplicationsView.vue')
        },
        {
          path: 'admin-security-overview',
          name: 'admin-security-overview',
          component: () => import('@/layouts/Admin/SecurityOverviewView.vue')
        },
        {
          path: 'admin-settings',
          name: 'admin-settings',
          component: () => import('@/layouts/Admin/SettingsView.vue')
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

  next()
})

export default router