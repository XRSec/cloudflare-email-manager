<template>
  <div class="admin-page">
    <div class="page-header">
      <h1>{{ pageIcon }} {{ pageTitle }}</h1>
    </div>

    <div class="page-content">
      <LoadingOverlay v-if="loading" text="加载安全数据..." />

      <div v-if="!loading" class="security-container">
        <!-- 安全统计卡片 -->
        <div class="stats-grid">
          <div class="stat-card">
            <div class="stat-icon">🛡️</div>
            <div class="stat-content">
              <div class="stat-number">{{ securityStats.total_attacks || 0 }}</div>
              <div class="stat-label">总攻击次数</div>
            </div>
          </div>

          <div class="stat-card">
            <div class="stat-icon">🚫</div>
            <div class="stat-content">
              <div class="stat-number">{{ securityStats.permission_denied || 0 }}</div>
              <div class="stat-label">权限拒绝</div>
            </div>
          </div>

          <div class="stat-card">
            <div class="stat-icon">⚠️</div>
            <div class="stat-content">
              <div class="stat-number">{{ securityStats.suspicious_activity || 0 }}</div>
              <div class="stat-label">可疑活动</div>
            </div>
          </div>

          <div class="stat-card">
            <div class="stat-icon">🌐</div>
            <div class="stat-content">
              <div class="stat-number">{{ securityStats.high_frequency_ips || 0 }}</div>
              <div class="stat-label">高频IP</div>
            </div>
          </div>
        </div>

        <!-- 最近攻击记录 -->
        <div class="security-section">
          <div class="section-header">
            <h3>最近攻击记录</h3>
          </div>

          <div v-if="securityStats.recent_attacks && securityStats.recent_attacks.length > 0" class="attacks-list">
            <div v-for="attack in securityStats.recent_attacks" :key="attack.id" class="attack-item">
              <div class="attack-info">
                <div class="attack-type">{{ getAttackTypeText(attack.attack_type) }}</div>
                <div class="attack-ip">{{ attack.ip_address }}</div>
                <div class="attack-time">{{ formatTime(attack.created_at) }}</div>
              </div>
              <div class="attack-details">
                <div class="attack-description">{{ attack.description || '无描述' }}</div>
                <div class="attack-severity" :class="`severity-${attack.severity}`">
                  {{ getSeverityText(attack.severity) }}
                </div>
              </div>
            </div>
          </div>

          <div v-else class="empty-state">
            <div class="empty-icon">🛡️</div>
            <p>暂无攻击记录</p>
          </div>
        </div>

        <!-- 攻击类型分布 -->
        <div class="security-section">
          <h3>攻击类型分布</h3>
          <div v-if="securityStats.attack_types && securityStats.attack_types.length > 0" class="attack-types">
            <div v-for="type in securityStats.attack_types" :key="type.type" class="attack-type-item">
              <div class="type-info">
                <span class="type-name">{{ getAttackTypeText(type.type) }}</span>
                <span class="type-count">{{ type.count }}次</span>
              </div>
              <div class="type-bar">
                <div class="type-progress" :style="{ width: getTypePercentage(type.count) + '%' }"></div>
              </div>
            </div>
          </div>
          <div v-else class="empty-state">
            <div class="empty-icon">📊</div>
            <p>暂无数据</p>
          </div>
        </div>

        <!-- 攻击IP排行 -->
        <div class="security-section">
          <h3>攻击IP排行</h3>
          <div v-if="securityStats.top_ips && securityStats.top_ips.length > 0" class="ip-ranking">
            <div v-for="(ip, index) in securityStats.top_ips" :key="ip.ip" class="ip-item">
              <div class="ip-rank">#{{ index + 1 }}</div>
              <div class="ip-address">{{ ip.ip }}</div>
              <div class="ip-count">{{ ip.count }}次</div>
              <div class="ip-location">{{ ip.location || '未知位置' }}</div>
            </div>
          </div>
          <div v-else class="empty-state">
            <div class="empty-icon">🌍</div>
            <p>暂无数据</p>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { apiService } from '@/composables/api'
import { cacheService } from '@/composables/cache'
import LoadingOverlay from '@/layouts/AppLoadingSpinner.vue'

// 定义类型接口
interface AttackRecord {
  id: string
  attack_type: string
  ip_address: string
  created_at: string
  description?: string
  severity: string
}

interface AttackType {
  type: string
  count: number
}

interface TopIP {
  ip: string
  count: number
  location?: string
}

// 直接使用 API 加载数据
const securityStats = ref({
  total_attacks: 0,
  permission_denied: 0,
  suspicious_activity: 0,
  high_frequency_ips: 0,
  recent_attacks: [] as AttackRecord[],
  attack_types: [] as AttackType[],
  top_ips: [] as TopIP[]
})

const loading = ref(false)
const pageTitle = '🛡️ 安全概览'
const pageIcon = '🛡️'

// 加载安全统计数据
const loadSecurityStats = async (forceRefresh = false) => {
  loading.value = true
  try {
    const cacheKey = 'security-stats-7'

    // 检查缓存
    if (!forceRefresh) {
      const cached = cacheService.get<typeof securityStats.value>(cacheKey)
      if (cached) {
        console.log('从缓存加载安全统计数据')
        securityStats.value = cached
        loading.value = false
        return
      }
    }

    // 从API获取
    console.log('从API加载安全统计数据')
    const response = await apiService.getSecurityStats(7)
    if (response.success && response.data) {
      const stats = {
        total_attacks: response.data.total_attacks || 0,
        permission_denied: response.data.permission_denied || 0,
        suspicious_activity: response.data.suspicious_activity || 0,
        high_frequency_ips: response.data.high_frequency_ips || 0,
        recent_attacks: response.data.recent_attacks || [],
        attack_types: response.data.attack_types || [],
        top_ips: response.data.top_ips || []
      }

      securityStats.value = stats

      // 存入缓存（2分钟，安全数据更新较频繁）
      cacheService.set(cacheKey, stats, 2 * 60 * 1000)
    }
  } catch (error) {
    console.error('加载安全统计数据失败:', error)
  } finally {
    loading.value = false
  }
}


// 页面加载时获取数据
onMounted(() => {
  loadSecurityStats()
})

// 获取攻击类型文本
const getAttackTypeText = (type: string) => {
  const typeMap: Record<string, string> = {
    'brute_force': '暴力破解',
    'sql_injection': 'SQL注入',
    'xss': 'XSS攻击',
    'csrf': 'CSRF攻击',
    'ddos': 'DDoS攻击',
    'malware': '恶意软件',
    'phishing': '钓鱼攻击',
    'unauthorized_access': '未授权访问',
    'data_breach': '数据泄露',
    'other': '其他'
  }
  return typeMap[type] || type
}

// 获取严重程度文本
const getSeverityText = (severity: string) => {
  const severityMap: Record<string, string> = {
    'low': '低',
    'medium': '中',
    'high': '高',
    'critical': '严重'
  }
  return severityMap[severity] || severity
}

// 获取攻击类型百分比
const getTypePercentage = (count: number) => {
  if (!securityStats.value.attack_types || securityStats.value.attack_types.length === 0) return 0
  const maxCount = Math.max(...securityStats.value.attack_types.map((t: any) => t.count))
  return maxCount > 0 ? (count / maxCount) * 100 : 0
}

// 时间格式化
const formatTime = (dateString: string) => {
  const date = new Date(dateString)
  const now = new Date()
  const diff = now.getTime() - date.getTime()

  if (diff < 60000) {
    return '刚刚'
  } else if (diff < 3600000) {
    return `${Math.floor(diff / 60000)}分钟前`
  } else if (diff < 86400000) {
    return `${Math.floor(diff / 3600000)}小时前`
  } else {
    return date.toLocaleDateString('zh-CN')
  }
}
</script>

<style scoped>
.security-container {
  max-width: 1200px;
  margin: 0 auto;
}

.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 20px;
  margin-bottom: 30px;
}

.stat-card {
  background: white;
  border-radius: 10px;
  padding: 20px;
  box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
  display: flex;
  align-items: center;
  gap: 15px;
}

.stat-icon {
  font-size: 2rem;
  opacity: 0.8;
}

.stat-content {
  flex: 1;
}

.stat-number {
  font-size: 2rem;
  font-weight: bold;
  color: #2c3e50;
  margin-bottom: 5px;
}

.stat-label {
  color: #7f8c8d;
  font-size: 0.9rem;
}

.security-section {
  background: white;
  border-radius: 10px;
  padding: 20px;
  margin-bottom: 20px;
  box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
}

.section-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 20px;
  border-bottom: 2px solid #ecf0f1;
  padding-bottom: 10px;
}

.section-header h3 {
  margin: 0;
  color: #2c3e50;
  font-size: 1.2rem;
}

.attacks-list {
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.attack-item {
  border: 1px solid #ecf0f1;
  border-radius: 8px;
  padding: 15px;
  margin-bottom: 10px;
  transition: all 0.3s ease;
}

.attack-item:hover {
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
}

.attack-info {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 8px;
}

.attack-type {
  font-weight: 600;
  color: #e74c3c;
}

.attack-ip {
  font-family: monospace;
  background: #f8f9fa;
  padding: 2px 6px;
  border-radius: 4px;
  font-size: 0.9rem;
}

.attack-time {
  color: #7f8c8d;
  font-size: 0.9rem;
}

.attack-details {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.attack-description {
  color: #2c3e50;
  flex: 1;
}

.attack-severity {
  padding: 4px 8px;
  border-radius: 12px;
  font-size: 0.8rem;
  font-weight: 500;
}

.severity-low {
  background: #d4edda;
  color: #155724;
}

.severity-medium {
  background: #fff3cd;
  color: #856404;
}

.severity-high {
  background: #f8d7da;
  color: #721c24;
}

.severity-critical {
  background: #f5c6cb;
  color: #721c24;
  font-weight: bold;
}

.attack-types {
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.attack-type-item {
  margin-bottom: 15px;
}

.type-info {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 5px;
}

.type-name {
  font-weight: 500;
  color: #2c3e50;
}

.type-count {
  color: #7f8c8d;
  font-size: 0.9rem;
}

.type-bar {
  height: 8px;
  background: #ecf0f1;
  border-radius: 4px;
  overflow: hidden;
}

.type-progress {
  height: 100%;
  background: linear-gradient(90deg, #3498db, #2980b9);
  transition: width 0.3s ease;
}

.ip-ranking {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.ip-item {
  display: flex;
  align-items: center;
  padding: 10px;
  border: 1px solid #ecf0f1;
  border-radius: 6px;
  margin-bottom: 8px;
  transition: all 0.3s ease;
}

.ip-item:hover {
  background: #f8f9fa;
}

.ip-rank {
  width: 30px;
  font-weight: bold;
  color: #3498db;
  text-align: center;
}

.ip-address {
  flex: 1;
  font-family: monospace;
  font-weight: 500;
  margin: 0 15px;
}

.ip-count {
  width: 60px;
  text-align: right;
  color: #e74c3c;
  font-weight: 500;
}

.ip-location {
  width: 100px;
  text-align: right;
  color: #7f8c8d;
  font-size: 0.9rem;
}

/* 空状态和按钮样式已移至全局样式，这里只保留SecurityOverviewView特有的样式 */
.empty-icon {
  font-size: 3rem;
  margin-bottom: 10px;
  opacity: 0.5;
}
</style>
