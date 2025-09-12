<template>
  <div class="admin-container">
    <n-card>
      <n-tabs
        type="line"
        :value="currentTab"
        @update:value="handleTabChange"
      >
        <n-tab-pane name="users" tab="用户管理">
          <router-view />
        </n-tab-pane>
        
        <n-tab-pane name="mailboxes" tab="邮箱管理">
          <router-view />
        </n-tab-pane>
        
        <n-tab-pane name="emails" tab="邮件管理">
          <router-view />
        </n-tab-pane>
        
        <n-tab-pane name="forward-rules" tab="转发规则">
          <router-view />
        </n-tab-pane>
        
        <n-tab-pane name="settings" tab="系统设置">
          <router-view />
        </n-tab-pane>
      </n-tabs>
    </n-card>
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'

const route = useRoute()
const router = useRouter()

const currentTab = computed(() => {
  const name = route.name as string
  if (name?.startsWith('admin-')) {
    return name.replace('admin-', '')
  }
  return 'users'
})

const handleTabChange = (tab: string) => {
  router.push({ name: `admin-${tab}` })
}
</script>

<style scoped>
.admin-container {
  height: 100%;
}
</style>
