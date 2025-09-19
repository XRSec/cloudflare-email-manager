<template>
  <div class="admin-users-page">
    <div class="page-header">
      <h1>👥 用户管理</h1>
      <button class="btn btn-primary" @click="showCreateModal">
        + 创建用户
      </button>
    </div>
    
    <div class="users-content">
      <div class="search-section">
        <div class="search-box">
          <input 
            v-model="searchQuery"
            type="text" 
            class="search-input" 
            placeholder="搜索用户..."
            @input="handleSearch"
          >
          <span class="search-icon">🔍</span>
        </div>
      </div>
      
      <div v-if="loading" class="loading">
        <div class="spinner"></div>
        加载中...
      </div>
      
      <div v-else-if="users.length === 0" class="empty-state">
        <div class="empty-icon">👥</div>
        <p>暂无用户</p>
      </div>
      
      <div v-else class="users-list">
        <div 
          v-for="user in users" 
          :key="user.id"
          class="user-item"
        >
          <div class="user-info">
            <div class="user-name">{{ user.username }}</div>
            <div class="user-email">{{ user.email }}</div>
            <div class="user-meta">
              <span class="role-badge" :class="getRoleClass(user.user_type)">
                {{ getRoleText(user.user_type) }}
              </span>
              <span class="status-badge" :class="getStatusClass(user.status)">
                {{ getStatusText(user.status) }}
              </span>
            </div>
          </div>
          <div class="user-actions">
            <button 
              v-if="user.status === 1"
              class="btn btn-warning btn-sm"
              @click="toggleUserStatus(user.id, 'disabled')"
            >
              ⏸️ 停用
            </button>
            <button 
              v-else-if="user.status === 2"
              class="btn btn-success btn-sm"
              @click="toggleUserStatus(user.id, 'active')"
            >
              ▶️ 启用
            </button>
            <button 
              class="btn btn-danger btn-sm"
              @click="deleteUser(user.id)"
            >
              🗑️ 删除
            </button>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { apiService, type UserProfile } from '@/api'

const users = ref<UserProfile[]>([])
const loading = ref(false)
const searchQuery = ref('')

const loadUsers = async () => {
  loading.value = true
  try {
    const response = await apiService.getUsers(1, 20, searchQuery.value)
    if (response.success && response.data) {
      users.value = response.data.items
    }
  } catch (error) {
    console.error('加载用户列表失败:', error)
  } finally {
    loading.value = false
  }
}

const handleSearch = () => {
  loadUsers()
}

const showCreateModal = () => {
  // 这里可以显示创建用户的模态框
  alert('创建用户功能待实现')
}

const deleteUser = async (userId: number) => {
  if (!confirm('确定要删除这个用户吗？')) {
    return
  }
  
  try {
    const response = await apiService.deleteUser(userId)
    if (response.success) {
      alert('用户删除成功')
      await loadUsers()
    } else {
      alert(response.message || '删除失败')
    }
  } catch (error) {
    console.error('删除用户失败:', error)
    alert('删除用户失败')
  }
}

const getRoleClass = (role: string) => {
  return role === 'admin' ? 'role-admin' : 'role-user'
}

const getRoleText = (role: string) => {
  return role === 'admin' ? '管理员' : '普通用户'
}

const getStatusClass = (status: number) => {
  return status === 1 ? 'status-active' : status === 2 ? 'status-disabled' : 'status-deleted'
}

const getStatusText = (status: number) => {
  return status === 1 ? '正常' : status === 2 ? '停用' : '已删除'
}

const toggleUserStatus = async (userId: number, status: 'active' | 'disabled') => {
  const action = status === 'active' ? '启用' : '停用'
  if (!confirm(`确定要${action}这个用户吗？`)) {
    return
  }
  
  try {
    const response = await apiService.toggleUserStatus(userId, status)
    if (response.success) {
      alert(`用户${action}成功`)
      await loadUsers()
    } else {
      alert(response.message || `${action}失败`)
    }
  } catch (error) {
    console.error(`${action}用户失败:`, error)
    alert(`${action}用户失败`)
  }
}

onMounted(() => {
  loadUsers()
})
</script>

<style scoped>
.admin-users-page {
  padding: 20px;
  background: #f8f9fa;
  min-height: 100%;
}

.page-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 20px;
}

.page-header h1 {
  margin: 0;
  color: #2c3e50;
  font-size: 24px;
  font-weight: 600;
}

.search-section {
  margin-bottom: 20px;
}

.search-box {
  position: relative;
  max-width: 400px;
}

.search-input {
  width: 100%;
  padding: 10px 40px 10px 15px;
  border: 1px solid #ddd;
  border-radius: 25px;
  font-size: 14px;
}

.search-icon {
  position: absolute;
  right: 15px;
  top: 50%;
  transform: translateY(-50%);
  color: #7f8c8d;
}

.loading {
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 40px;
  color: #6c757d;
}

.spinner {
  width: 20px;
  height: 20px;
  border: 2px solid #f3f3f3;
  border-top: 2px solid #3498db;
  border-radius: 50%;
  animation: spin 1s linear infinite;
  margin-right: 10px;
}

@keyframes spin {
  0% { transform: rotate(0deg); }
  100% { transform: rotate(360deg); }
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
  flex: 1;
}

.user-name {
  font-weight: 500;
  color: #2c3e50;
  margin-bottom: 5px;
}

.user-email {
  color: #6c757d;
  font-size: 14px;
  margin-bottom: 5px;
}

.role-badge {
  padding: 4px 8px;
  border-radius: 12px;
  font-size: 12px;
  font-weight: 500;
}

.role-admin {
  background: #d4edda;
  color: #155724;
}

.role-user {
  background: #e2e3e5;
  color: #383d41;
}

.user-meta {
  display: flex;
  gap: 10px;
  align-items: center;
}

.status-badge {
  padding: 4px 8px;
  border-radius: 12px;
  font-size: 12px;
  font-weight: 500;
}

.status-active {
  background: #d4edda;
  color: #155724;
}

.status-disabled {
  background: #f8d7da;
  color: #721c24;
}

.status-deleted {
  background: #e2e3e5;
  color: #6c757d;
}

.user-actions {
  display: flex;
  gap: 10px;
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

.btn-primary {
  background: #3498db;
  color: white;
}

.btn-primary:hover {
  background: #2980b9;
}

.btn-danger {
  background: #dc3545;
  color: white;
}

.btn-danger:hover {
  background: #c82333;
}

.btn-warning {
  background: #ffc107;
  color: #212529;
}

.btn-warning:hover {
  background: #e0a800;
}

.btn-success {
  background: #28a745;
  color: white;
}

.btn-success:hover {
  background: #218838;
}

.btn-sm {
  padding: 6px 12px;
  font-size: 12px;
}
</style>