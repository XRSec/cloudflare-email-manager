<template>
  <div class="security-overview">
    <n-grid :cols="24" :x-gap="16" :y-gap="16">
      <!-- 安全统计卡片 -->
      <n-grid-item :span="6">
        <n-card title="总攻击数" hoverable>
          <n-statistic :value="securityStats.total_attacks" />
          <template #footer>
            <n-text depth="3">最近7天</n-text>
          </template>
        </n-card>
      </n-grid-item>
      
      <n-grid-item :span="6">
        <n-card title="权限拒绝" hoverable>
          <n-statistic :value="securityStats.attacks_by_type.permission_denied || 0" />
          <template #footer>
            <n-text depth="3">越权尝试</n-text>
          </template>
        </n-card>
      </n-grid-item>
      
      <n-grid-item :span="6">
        <n-card title="可疑操作" hoverable>
          <n-statistic :value="securityStats.attacks_by_type.suspicious_activity || 0" />
          <template #footer>
            <n-text depth="3">异常行为</n-text>
          </template>
        </n-card>
      </n-grid-item>
      
      <n-grid-item :span="6">
        <n-card title="高频IP" hoverable>
          <n-statistic :value="Object.keys(securityStats.attacks_by_ip).length" />
          <template #footer>
            <n-text depth="3">攻击来源</n-text>
          </template>
        </n-card>
      </n-grid-item>

      <!-- 最近攻击记录 -->
      <n-grid-item :span="24">
        <n-card title="最近安全事件" hoverable>
          <template #header-extra>
            <n-button @click="loadSecurityStats" :loading="loading" size="small">
              <template #icon>
                <n-icon>
                  <Sync />
                </n-icon>
              </template>
              刷新
            </n-button>
          </template>
          
          <n-data-table
            :columns="securityColumns"
            :data="securityStats.recent_attacks"
            :loading="loading"
            :bordered="false"
            striped
            :pagination="false"
          />
        </n-card>
      </n-grid-item>

      <!-- 攻击类型分布 -->
      <n-grid-item :span="12">
        <n-card title="攻击类型分布" hoverable>
          <div class="attack-type-chart">
            <n-space vertical>
              <div v-for="(count, type) in securityStats.attacks_by_type" :key="type" class="attack-type-item">
                <div class="attack-type-label">
                  <n-tag :type="getAttackTypeColor(type)">{{ getAttackTypeName(type) }}</n-tag>
                </div>
                <n-progress 
                  :percentage="(count / securityStats.total_attacks) * 100" 
                  :color="getAttackTypeColor(type)"
                  :show-indicator="false"
                />
                <div class="attack-type-count">{{ count }}</div>
              </div>
            </n-space>
          </div>
        </n-card>
      </n-grid-item>

      <!-- 攻击IP排行 -->
      <n-grid-item :span="12">
        <n-card title="攻击IP排行" hoverable>
          <div class="attack-ip-list">
            <n-space vertical>
              <div v-for="(count, ip) in topAttackIPs" :key="ip" class="attack-ip-item">
                <div class="attack-ip-label">
                  <n-tag type="error">{{ ip }}</n-tag>
                </div>
                <n-progress 
                  :percentage="(count / maxAttackCount) * 100" 
                  color="#ff4d4f"
                  :show-indicator="false"
                />
                <div class="attack-ip-count">{{ count }}次</div>
              </div>
            </n-space>
          </div>
        </n-card>
      </n-grid-item>
    </n-grid>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, computed } from 'vue'
import { useMessage } // 移除 naive-ui 导入
import { Sync, Shield, User, Activity } from '@vicons/fa'
import { apiService } from '@/api'

const message = useMessage()
const loading = ref(false)

// 安全统计数据
const securityStats = ref({
  total_attacks: 0,
  attacks_by_type: {} as Record<string, number>,
  attacks_by_ip: {} as Record<string, number>,
  recent_attacks: [] as any[]
})

// 安全事件列定义
const securityColumns = [
  {
    title: '时间',
    key: 'created_at',
    width: 180,
    render: (row: any) => {
      return new Date(row.created_at).toLocaleString()
    }
  },
  {
    title: '用户',
    key: 'user_id',
    width: 100,
    render: (row: any) => {
      return row.user_id || '未知'
    }
  },
  {
    title: '攻击类型',
    key: 'attack_type',
    width: 120,
    render: (row: any) => {
      const typeMap = {
        permission_denied: { type: 'error', text: '权限拒绝' },
        suspicious_activity: { type: 'warning', text: '可疑操作' },
        rate_limit_exceeded: { type: 'info', text: '频率限制' }
      }
      const attackType = typeMap[row.attack_type] || { type: 'default', text: row.attack_type }
      return h('n-tag', { type: attackType.type }, { default: () => attackType.text })
    }
  },
  {
    title: '资源类型',
    key: 'resource_type',
    width: 100,
    render: (row: any) => {
      return row.resource_type || '-'
    }
  },
  {
    title: 'IP地址',
    key: 'request_ip',
    width: 120,
    render: (row: any) => {
      return h('span', { style: 'font-family: monospace' }, row.request_ip || '-')
    }
  },
  {
    title: '描述',
    key: 'description',
    render: (row: any) => {
      return row.description || '-'
    }
  }
]

// 计算属性
const topAttackIPs = computed(() => {
  const ips = Object.entries(securityStats.value.attacks_by_ip)
    .sort(([, a], [, b]) => b - a)
    .slice(0, 5)
  return Object.fromEntries(ips)
})

const maxAttackCount = computed(() => {
  const counts = Object.values(securityStats.value.attacks_by_ip)
  return Math.max(...counts, 1)
})

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

// 加载安全统计数据
const loadSecurityStats = async () => {
  loading.value = true
  try {
    const response = await apiService.api.get('/security-audit/attack-stats', {
      params: { days: 7 }
    })
    
    if (response.data.success) {
      securityStats.value = response.data.data
    } else {
      message.error('加载安全统计数据失败')
    }
  } catch (error) {
    console.error('加载安全统计数据失败:', error)
    message.error('加载安全统计数据失败')
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  loadSecurityStats()
})
</script>

<style scoped>
.security-overview {
  padding: 16px;
}

.attack-type-chart {
  padding: 16px 0;
}

.attack-type-item {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 12px;
}

.attack-type-label {
  min-width: 80px;
}

.attack-type-count {
  min-width: 40px;
  text-align: right;
  font-weight: bold;
}

.attack-ip-list {
  padding: 16px 0;
}

.attack-ip-item {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 12px;
}

.attack-ip-label {
  min-width: 120px;
}

.attack-ip-count {
  min-width: 60px;
  text-align: right;
  font-weight: bold;
}
</style>
