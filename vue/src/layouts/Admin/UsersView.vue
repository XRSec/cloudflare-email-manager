<template>
  <div class="users-page">
    <div class="page-header">
      <h1>👥 用户管理</h1>
    </div>

    <div class="users-content">
      <LoadingOverlay :show="loading" text="加载用户列表..." type="local" />

      <div v-if="!loading && users.length === 0" class="empty-state">
        <div class="empty-icon">👥</div>
        <p>暂无用户</p>
      </div>

      <div v-if="!loading && users.length > 0" class="users-list">
        <div v-for="user in users" :key="user.id" class="user-item">
          <div class="user-info">
            <div class="user-avatar">{{ user.username.charAt(0).toUpperCase() }}</div>
            <div class="user-details">
              <div class="user-name">{{ user.username }}</div>
              <div class="user-email">{{ user.email }}</div>
              <div class="user-type">{{ user.user_type === 'admin' ? '管理员' : '普通用户' }}</div>
            </div>
          </div>
          <div class="user-actions">
            <button class="btn btn-primary btn-sm" @click="editUser(user.id)">编辑</button>
            <button class="btn btn-danger btn-sm" @click="deleteUser(user.id)">删除</button>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import LoadingOverlay from '@/layouts/AppLoadingSpinner.vue'

const users = ref<any[]>([])
const loading = ref(false)

const loadUsers = async () => {
  loading.value = true
  try {
    // 这里可以调用 API 加载用户列表
    // const response = await apiService.getUsers()
    // if (response.success && response.data) {
    //   users.value = response.data.items
    // }
  } catch (error) {
    console.error('加载用户列表失败:', error)
  } finally {
    loading.value = false
  }
}

const editUser = (userId: string) => {
  // 编辑用户逻辑
  console.log('编辑用户:', userId)
}

const deleteUser = (userId: string) => {
  // 删除用户逻辑
  console.log('删除用户:', userId)
}

onMounted(() => {
  loadUsers()
})
</script>

<style scoped>
.users-page {
  padding: 20px;
  background: #f8f9fa;
  min-height: 100%;
}

.page-header {
  margin-bottom: 20px;
}

.page-header h1 {
  margin: 0;
  color: #2c3e50;
  font-size: 24px;
  font-weight: 600;
}

.users-content {
  position: relative;
  min-height: 200px;
}

.empty-state {
  text-align: center;
  padding: 40px;
  color: #6c757d;
}

.empty-icon {
  font-size: 48px;
  margin-bottom: 15px;
}

.users-list {
  display: flex;
  flex-direction: column;
  gap: 15px;
}

.user-item {
  background: white;
  border-radius: 10px;
  padding: 20px;
  box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.user-info {
  display: flex;
  align-items: center;
  gap: 15px;
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
  gap: 5px;
}

.user-name {
  font-weight: 500;
  color: #2c3e50;
  font-size: 16px;
}

.user-email {
  color: #6c757d;
  font-size: 14px;
}

.user-type {
  color: #3498db;
  font-size: 12px;
  font-weight: 500;
}

.user-actions {
  display: flex;
  gap: 10px;
}

.btn {
  padding: 6px 12px;
  border: none;
  border-radius: 5px;
  font-size: 12px;
  cursor: pointer;
  transition: all 0.3s;
  font-weight: 500;
}

.btn-primary {
  background: #3498db;
  color: white;
}

.btn-primary:hover {
  background: #2980b9;
}

.btn-danger {
  background: #e74c3c;
  color: white;
}

.btn-danger:hover {
  background: #c0392b;
}

.btn-sm {
  padding: 4px 8px;
  font-size: 11px;
}
</style>