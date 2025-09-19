<template>
  <n-card title="安全概览" hoverable>
    <template #header-extra>
      <n-button @click="loadRecentAttacks" :loading="loading" size="tiny">
        <template #icon>
          <n-icon>
            <Sync />
          </n-icon>
        </template>
      </n-button>
    </template>
    
    <div class="security-widget">
      <!-- 统计信息 -->
      <div class="stats-row">
        <div class="stat-item">
          <div class="stat-value">{{ recentStats.total_attacks }}</div>
          <div class="stat-label">总攻击数</div>
        </div>
        <div class="stat-item">
          <div class="stat-value">{{ recentStats.attacks_by_type.permission_denied || 0 }}</div>
          <div class="stat-label">权限拒绝</div>
        </div>
        <div class="stat-item">
          <div class="stat-value">{{ recentStats.attacks_by_type.suspicious_activity || 0 }}</div>
          <div class="stat-label">可疑操作</div>
        </div>
      </div>

      <!-- 最近攻击记录 -->
      <div class="recent-attacks">
        <div class="section-title">最近安全事件</div>
        <div v-if="loading" class="loading-state">
          <n-spin size="small" />
          <span style="margin-left: 8px;">加载中...</span>
        </div>
        <div v-else-if="recentAttacks.length === 0" class="empty-state">
          <n-empty description="暂无安全事件" size="small" />
        </div>
        <div v-else class="attack-list">
          <div 
            v-for="attack in recentAttacks.slice(0, 5)" 
            :key="attack.id" 
            class="attack-item"
          >
            <div class="attack-time">
              {{ formatTime(attack.created_at) }}
            </div>
            <div class="attack-info">
              <n-tag 
                :type="getAttackTypeColor(attack.attack_type)" 
                size="small"
              >
                {{ getAttackTypeName(attack.attack_type) }}
              </n-tag>
              <span class="attack-description">{{ attack.description || '无描述' }}</span>
            </div>
          </div>
        </div>
      </div>

      <!-- 查看全部按钮 -->
      <div class="view-all">
        <n-button 
          @click="goToSecurityOverview" 
          type="primary" 
          size="small" 
          block
        >
          查看全部安全记录
        </n-button>
      </div>
    </div>
  </n-card>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { useMessage } // 移除 naive-ui 导入
import { Sync } from '@vicons/fa'
import { apiService } from '@/api'

const router = useRouter()
const message = useMessage()
const loading = ref(false)

// 统计数据
const recentStats = ref({
  total_attacks: 0,
  attacks_by_type: {} as Record<string, number>,
  attacks_by_ip: {} as Record<string, number>
})

// 最近攻击记录
const recentAttacks = ref([] as any[])

// 获取攻击类型颜色
const getAttackTypeColor = (type: string) => {
  const colorMap = {
    permission_denied: 'error',
    suspicious_activity: 'warning',
    rate_limit_exceeded: 'info'
  }
  return colorMap[type] || 'default'
}

// 获取攻击类型名称
const getAttackTypeName = (type: string) => {
  const nameMap = {
    permission_denied: '权限拒绝',
    suspicious_activity: '可疑操作',
    rate_limit_exceeded: '频率限制'
  }
  return nameMap[type] || type
}

// 格式化时间
const formatTime = (time: string) => {
  const date = new Date(time)
  const now = new Date()
  const diff = now.getTime() - date.getTime()
  
  if (diff < 60000) { // 1分钟内
    return '刚刚'
  } else if (diff < 3600000) { // 1小时内
    return `${Math.floor(diff / 60000)}分钟前`
  } else if (diff < 86400000) { // 1天内
    return `${Math.floor(diff / 3600000)}小时前`
  } else {
    return date.toLocaleDateString()
  }
}

// 加载最近攻击记录
const loadRecentAttacks = async () => {
  loading.value = true
  try {
    // 加载统计数据
    const statsResponse = await apiService.api.get('/security-audit/attack-stats', {
      params: { days: 7 }
    })
    
    if (statsResponse.data.success) {
      recentStats.value = statsResponse.data.data
    }

    // 加载最近攻击记录
    const attacksResponse = await apiService.api.get('/security-audit/records', {
      params: { 
        page: 1, 
        limit: 5,
        action_type: 'permission_denied'
      }
    })
    
    if (attacksResponse.data.success) {
      recentAttacks.value = attacksResponse.data.data.records
    }
  } catch (error) {
    console.error('加载安全数据失败:', error)
    message.error('加载安全数据失败')
  } finally {
    loading.value = false
  }
}

// 跳转到安全概览页面
const goToSecurityOverview = () => {
  router.push('/admin/security-overview')
}

onMounted(() => {
  loadRecentAttacks()
})
</script>

<style scoped>
.security-widget {
  padding: 8px 0;
}

.stats-row {
  display: flex;
  justify-content: space-around;
  margin-bottom: 16px;
  padding: 12px;
  background: #f5f5f5;
  border-radius: 6px;
}

.stat-item {
  text-align: center;
}

.stat-value {
  font-size: 20px;
  font-weight: bold;
  color: #1890ff;
}

.stat-label {
  font-size: 12px;
  color: #666;
  margin-top: 4px;
}

.section-title {
  font-size: 14px;
  font-weight: bold;
  margin-bottom: 8px;
  color: #333;
}

.loading-state {
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 20px;
  color: #666;
}

.empty-state {
  padding: 20px;
}

.attack-list {
  max-height: 200px;
  overflow-y: auto;
}

.attack-item {
  display: flex;
  align-items: flex-start;
  gap: 8px;
  padding: 8px 0;
  border-bottom: 1px solid #f0f0f0;
}

.attack-item:last-child {
  border-bottom: none;
}

.attack-time {
  font-size: 12px;
  color: #999;
  min-width: 60px;
  flex-shrink: 0;
}

.attack-info {
  flex: 1;
  display: flex;
  align-items: center;
  gap: 8px;
}

.attack-description {
  font-size: 12px;
  color: #666;
  flex: 1;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.view-all {
  margin-top: 16px;
  padding-top: 12px;
  border-top: 1px solid #f0f0f0;
}
</style>
