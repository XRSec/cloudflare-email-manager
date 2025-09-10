/**
 * Vue Router 配置
 */
import { createRouter, createWebHistory } from 'vue-router'
import type { RouteRecordRaw } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import { RouteNames } from '@/types'

// 路由组件懒加载
const Login = () => import('@/views/Login.vue')
const Dashboard = () => import('@/views/Dashboard.vue')
const Emails = () => import('@/views/Emails.vue')
const Settings = () => import('@/views/Settings.vue')
const AdminUsers = () => import('@/views/admin/Users.vue')
const AdminRules = () => import('@/views/admin/Rules.vue')
const AdminEmails = () => import('@/views/admin/Emails.vue')
const AdminSettings = () => import('@/views/admin/Settings.vue')
const Debug = () => import('@/views/Debug.vue')

const routes: RouteRecordRaw[] = [
  {
    path: '/',
    redirect: '/dashboard'
  },
  {
    path: '/login',
    name: RouteNames.LOGIN,
    component: Login,
    meta: {
      requiresAuth: false,
      title: '登录'
    }
  },
  {
    path: '/dashboard',
    name: RouteNames.DASHBOARD,
    component: Dashboard,
    meta: {
      requiresAuth: true,
      title: '仪表盘'
    },
    children: [
      {
        path: '',
        redirect: '/dashboard/emails'
      },
      {
        path: 'emails',
        name: RouteNames.EMAILS,
        component: Emails,
        meta: {
          requiresAuth: true,
          title: '邮件列表'
        }
      },
      {
        path: 'settings',
        name: RouteNames.SETTINGS,
        component: Settings,
        meta: {
          requiresAuth: true,
          title: '个人设置'
        }
      },
      {
        path: 'admin/users',
        name: RouteNames.ADMIN_USERS,
        component: AdminUsers,
        meta: {
          requiresAuth: true,
          requiresAdmin: true,
          title: '用户管理'
        }
      },
      {
        path: 'admin/rules',
        name: RouteNames.ADMIN_RULES,
        component: AdminRules,
        meta: {
          requiresAuth: true,
          requiresAdmin: true,
          title: '转发规则'
        }
      },
      {
        path: 'admin/emails',
        name: RouteNames.ADMIN_EMAILS,
        component: AdminEmails,
        meta: {
          requiresAuth: true,
          requiresAdmin: true,
          title: '所有邮件'
        }
      },
      {
        path: 'admin/settings',
        name: RouteNames.ADMIN_SETTINGS,
        component: AdminSettings,
        meta: {
          requiresAuth: true,
          requiresAdmin: true,
          title: '系统设置'
        }
      },
      {
        path: 'debug',
        name: RouteNames.DEBUG,
        component: Debug,
        meta: {
          requiresAuth: true,
          requiresDebug: true,
          title: '调试工具'
        }
      }
    ]
  },
  {
    path: '/:pathMatch(.*)*',
    redirect: '/dashboard'
  }
]

const router = createRouter({
  history: createWebHistory(),
  routes
})

// 路由守卫
router.beforeEach(async (to, from, next) => {
  const authStore = useAuthStore()
  
  // 设置页面标题
  if (to.meta.title) {
    document.title = `${to.meta.title} - 临时邮箱管理系统`
  }

  // 不需要认证的路由直接通过
  if (!to.meta.requiresAuth) {
    // 如果已登录用户访问登录页，重定向到仪表盘
    if (to.name === RouteNames.LOGIN && authStore.isAuthenticated) {
      next('/dashboard')
      return
    }
    next()
    return
  }

  // 检查认证状态
  if (!authStore.isAuthenticated) {
    const isAuthenticated = await authStore.checkAuth()
    if (!isAuthenticated) {
      next('/login')
      return
    }
  }

  // 检查管理员权限
  if (to.meta.requiresAdmin && !authStore.isAdmin) {
    next('/dashboard')
    return
  }

  // 检查调试模式权限
  if (to.meta.requiresDebug) {
    // 这里可以添加调试模式检查逻辑
    // 暂时允许所有已认证用户访问
  }

  next()
})

// 路由错误处理
router.onError((error) => {
  console.error('Router error:', error)
})

export default router