<template>
  <div class="top-bar">
    <div class="left-section">
      <button class="btn btn-secondary btn-sm" @click="toggleSidebar">☰ 菜单</button>
      <button class="btn btn-success btn-sm" @click="refreshConfig">🔄 刷新配置</button>
    </div>
    <div class="user-info">
      <div class="user-avatar" id="userAvatar">
        {{ userInitials }}
      </div>
      <div class="user-details">
        <div id="userEmail">{{ userEmail }}</div>
        <div id="userType" class="user-type">{{ userType }}</div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useAuthStore } from '@/stores/auth'
import { useSystemStore } from '@/stores/system'

interface Emits {
  (e: 'toggle-sidebar'): void
  (e: 'refresh-config'): void
}

const emit = defineEmits<Emits>()
const authStore = useAuthStore()
const systemStore = useSystemStore()

const userInitials = computed(() => {
  if (authStore.user?.username) {
    return authStore.user.username.charAt(0).toUpperCase()
  }
  return 'U'
})

const userEmail = computed(() => {
  if (authStore.user?.email) {
    return authStore.user.email
  }
  return 'user@example.com'
})

const userType = computed(() => {
  if (authStore.user?.user_type) {
    return authStore.user.user_type === 'admin' ? '管理员' : '普通用户'
  }
  return '用户'
})

const toggleSidebar = () => {
  emit('toggle-sidebar')
}

const refreshConfig = async () => {
  try {
    await systemStore.refreshConfig()
    emit('refresh-config')
  } catch (error) {
    console.error('刷新配置失败:', error)
  }
}
</script>

<style scoped>
.top-bar {
  background: white;
  padding: 15px 20px;
  box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 20px;
}

.left-section {
  display: flex;
  gap: 10px;
}

.user-info {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 10px;
  border-radius: 5px;
}

.user-avatar {
  width: 40px;
  height: 40px;
  border-radius: 50%;
  background: #3498db;
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
}

#userEmail, .user-type {
  font-size: 0.8rem;
  color: #6c757d;
}

.btn {
  padding: 8px 16px;
  border: none;
  border-radius: 5px;
  font-size: 14px;
  cursor: pointer;
  transition: all 0.3s;
  font-weight: 500;
  display: inline-block;
}

.btn-secondary {
  background: #6c757d;
  color: white;
}

.btn-secondary:hover {
  background: #5a6268;
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

.btn-sm {
  padding: 6px 12px;
  font-size: 12px;
}

@media (max-width: 768px) {
  .top-bar {
    padding: 10px 15px;
  }
  
  .user-info {
    gap: 8px;
  }
  
  .user-avatar {
    width: 35px;
    height: 35px;
    font-size: 14px;
  }
}
</style>
