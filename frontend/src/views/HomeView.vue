<template>
  <div class="home-container">
    <n-layout>
      <!-- 顶部导航栏 -->
      <n-layout-header class="header">
        <div class="header-content">
          <div class="logo">
            <h2>临时邮箱管理系统</h2>
          </div>
          
          <div class="user-info">
            <n-dropdown
              :options="userMenuOptions"
              @select="handleUserMenuSelect"
            >
              <n-button quaternary>
                <template #icon>
                  <n-icon>
                    <User />
                  </n-icon>
                </template>
                {{ authStore.user?.username }}
                <template #icon>
                  <n-icon>
                    <ChevronDown />
                  </n-icon>
                </template>
              </n-button>
            </n-dropdown>
          </div>
        </div>
      </n-layout-header>

      <n-layout has-sider>
        <!-- 侧边栏 -->
        <n-layout-sider
          :collapsed="collapsed"
          :collapsed-width="64"
          :width="240"
          show-trigger
          @collapse="collapsed = true"
          @expand="collapsed = false"
        >
          <n-menu
            :collapsed="collapsed"
            :collapsed-width="64"
            :collapsed-icon-size="22"
            :options="menuOptions"
            :value="currentRoute"
            @update:value="handleMenuSelect"
          />
        </n-layout-sider>

        <!-- 主内容区 -->
        <n-layout-content class="content">
          <div class="content-wrapper">
            <router-view />
          </div>
        </n-layout-content>
      </n-layout>
    </n-layout>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, h } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { useMessage, useDialog } from 'naive-ui'
import { 
  User, 
  ChevronDown,
  MailBulk,
  Inbox,
  Cog,
  Users,
  Forward
} from '@vicons/fa'
import { useAuthStore } from '@/stores/auth'

const router = useRouter()
const route = useRoute()
const message = useMessage()
const dialog = useDialog()
const authStore = useAuthStore()

const collapsed = ref(false)

const currentRoute = computed(() => route.name as string)

const menuOptions = computed(() => {
  const baseOptions: any[] = [
    {
      label: '邮箱管理',
      key: 'mailbox',
      icon: () => h(MailBulk)
    },
    {
      label: '邮件列表',
      key: 'emails',
      icon: () => h(Inbox)
    }
  ]

  if (authStore.isAdmin) {
    baseOptions.push(
      {
        label: '管理员',
        key: 'admin',
        icon: () => h(Cog),
        children: [
          {
            label: '用户管理',
            key: 'admin-users',
            icon: () => h(Users)
          },
          {
            label: '邮箱管理',
            key: 'admin-mailboxes',
            icon: () => h(Inbox)
          },
          {
            label: '邮件管理',
            key: 'admin-emails',
            icon: () => h(Inbox)
          },
          {
            label: '转发规则',
            key: 'admin-forward-rules',
            icon: () => h(Forward)
          },
          {
            label: '系统设置',
            key: 'admin-settings',
            icon: () => h(Cog)
          }
        ]
      }
    )
  }

  return baseOptions
})

const userMenuOptions = [
  {
    label: '个人设置',
    key: 'profile'
  },
  {
    label: '退出登录',
    key: 'logout'
  }
]

const handleMenuSelect = (key: string) => {
  router.push({ name: key })
}

const handleUserMenuSelect = (key: string) => {
  if (key === 'logout') {
    dialog.warning({
      title: '确认退出',
      content: '您确定要退出登录吗？',
      positiveText: '确定',
      negativeText: '取消',
      onPositiveClick: async () => {
        await authStore.logout()
        message.success('已退出登录')
        router.push('/login')
      }
    })
  } else if (key === 'profile') {
    // TODO: 实现个人设置页面
    message.info('个人设置功能开发中...')
  }
}
</script>

<style scoped>
.home-container {
  height: 100vh;
  overflow: hidden;
}

.header {
  background: #fff;
  border-bottom: 1px solid #e0e0e6;
  padding: 0 24px;
  height: 64px;
  display: flex;
  align-items: center;
}

.header-content {
  display: flex;
  justify-content: space-between;
  align-items: center;
  width: 100%;
}

.logo h2 {
  margin: 0;
  color: #333;
  font-size: 18px;
  font-weight: 600;
}

.user-info {
  display: flex;
  align-items: center;
  gap: 16px;
}

.content {
  background: #f5f5f5;
  padding: 24px;
  overflow: auto;
}

.content-wrapper {
  max-width: 1200px;
  margin: 0 auto;
}
</style>
