<script setup>
import { ref, reactive, onMounted } from 'vue'
import { useMessage } from 'naive-ui'
import { useGlobalState } from '../store'
import { api } from '../api'

const message = useMessage()
const { jwt, userSettings: globalUserSettings } = useGlobalState()

// 响应式数据
const activeTab = ref('account')
const savingSettings = ref(false)
const changingPassword = ref(false)

// 用户信息
const userInfo = ref({
  email_address: '',
  email_prefix: '',
  user_type: 'user',
  created_at: ''
})

// 用户设置
const userSettings = reactive({
  webhook_url: '',
  webhook_secret: ''
})

// 密码表单
const passwordForm = reactive({
  current_password: '',
  new_password: '',
  confirm_password: ''
})

// 邮件统计
const mailStats = ref({
  total: 0,
  withAttachments: 0,
  today: 0
})

// 最近邮件
const recentMails = ref([])

// 表单验证规则
const settingsRules = {
  webhook_url: [
    { type: 'url', message: '请输入有效的URL地址', trigger: 'blur' }
  ]
}

const passwordRules = {
  current_password: [
    { required: true, message: '请输入当前密码', trigger: 'blur' }
  ],
  new_password: [
    { required: true, message: '请输入新密码', trigger: 'blur' },
    { min: 6, message: '密码长度至少6位', trigger: 'blur' }
  ],
  confirm_password: [
    { required: true, message: '请确认新密码', trigger: 'blur' },
    {
      validator: (rule, value) => {
        if (value !== passwordForm.new_password) {
          return new Error('两次输入的密码不一致')
        }
        return true
      },
      trigger: 'blur'
    }
  ]
}

// 方法
const loadUserInfo = async () => {
  try {
    const response = await api.fetch('/api/user/settings')
    if (response.success) {
      userInfo.value = response.data
      userSettings.webhook_url = response.data.webhook_url || ''
      userSettings.webhook_secret = response.data.webhook_secret || ''
    }
  } catch (error) {
    message.error('加载用户信息失败')
    console.error(error)
  }
}

const loadMailStats = async () => {
  try {
    const response = await api.fetch('/api/mails?limit=5&offset=0')
    if (response.success) {
      const mails = response.data.mails
      recentMails.value = mails
      
      // 计算统计信息
      const totalResponse = await api.fetch('/api/mails?limit=1000&offset=0')
      if (totalResponse.success) {
        const allMails = totalResponse.data.mails
        mailStats.value.total = allMails.length
        mailStats.value.withAttachments = allMails.filter(mail => mail.has_attachments).length
        
        // 计算今日邮件数
        const today = new Date().toDateString()
        mailStats.value.today = allMails.filter(mail => {
          const mailDate = new Date(mail.received_at).toDateString()
          return mailDate === today
        }).length
      }
    }
  } catch (error) {
    message.error('加载邮件统计失败')
    console.error(error)
  }
}

const saveSettings = async () => {
  try {
    savingSettings.value = true
    
    const response = await api.fetch('/api/user/settings', {
      method: 'PUT',
      body: JSON.stringify({
        webhook_url: userSettings.webhook_url,
        webhook_secret: userSettings.webhook_secret
      })
    })
    
    if (response.success) {
      message.success('设置保存成功')
      await loadUserInfo()
    }
  } catch (error) {
    message.error(error.message || '保存设置失败')
    console.error(error)
  } finally {
    savingSettings.value = false
  }
}

const resetSettings = () => {
  loadUserInfo()
}

const changePassword = async () => {
  try {
    changingPassword.value = true
    
    // 验证当前密码
    const loginResponse = await api.fetch('/api/login', {
      method: 'POST',
      body: JSON.stringify({
        email_prefix: userInfo.value.email_prefix,
        email_password: passwordForm.current_password
      })
    })
    
    if (!loginResponse.success) {
      message.error('当前密码错误')
      return
    }
    
    // 修改密码
    const response = await api.fetch('/api/user/settings', {
      method: 'PUT',
      body: JSON.stringify({
        email_password: passwordForm.new_password
      })
    })
    
    if (response.success) {
      message.success('密码修改成功')
      resetPasswordForm()
    }
  } catch (error) {
    message.error(error.message || '修改密码失败')
    console.error(error)
  } finally {
    changingPassword.value = false
  }
}

const resetPasswordForm = () => {
  Object.assign(passwordForm, {
    current_password: '',
    new_password: '',
    confirm_password: ''
  })
}

const formatDate = (dateString) => {
  if (!dateString) return ''
  return new Date(dateString).toLocaleString('zh-CN')
}

// 生命周期
onMounted(async () => {
  if (jwt.value) {
    await Promise.all([
      loadUserInfo(),
      loadMailStats()
    ])
  }
})
</script>

<template>
  <div class="user-container">
    <n-card title="用户设置" class="user-card">
      <n-tabs v-model:value="activeTab" type="line" animated>
        <!-- 账户信息 -->
        <n-tab-pane name="account" tab="账户信息">
          <div class="tab-content">
            <n-descriptions title="账户详情" :column="1" bordered>
              <n-descriptions-item label="邮件地址">
                {{ userInfo.email_address }}
              </n-descriptions-item>
              <n-descriptions-item label="邮件前缀">
                {{ userInfo.email_prefix }}
              </n-descriptions-item>
              <n-descriptions-item label="用户类型">
                <n-tag :type="userInfo.user_type === 'admin' ? 'error' : 'default'">
                  {{ userInfo.user_type === 'admin' ? '管理员' : '普通用户' }}
                </n-tag>
              </n-descriptions-item>
              <n-descriptions-item label="创建时间">
                {{ formatDate(userInfo.created_at) }}
              </n-descriptions-item>
            </n-descriptions>
          </div>
        </n-tab-pane>

        <!-- 设置 -->
        <n-tab-pane name="settings" tab="设置">
          <div class="tab-content">
            <n-form
              ref="settingsFormRef"
              :model="userSettings"
              :rules="settingsRules"
              label-placement="left"
              label-width="150"
            >
              <n-form-item label="Webhook地址" path="webhook_url">
                <n-input
                  v-model:value="userSettings.webhook_url"
                  placeholder="请输入webhook地址"
                  clearable
                />
                <template #help>
                  配置webhook地址后，新邮件将自动转发到该地址
                </template>
              </n-form-item>
              
              <n-form-item label="Webhook密钥" path="webhook_secret">
                <n-input
                  v-model:value="userSettings.webhook_secret"
                  placeholder="请输入webhook密钥（可选）"
                  show-password-on="click"
                  clearable
                />
                <template #help>
                  用于验证webhook请求的签名密钥
                </template>
              </n-form-item>
              
              <n-form-item>
                <n-button type="primary" @click="saveSettings" :loading="savingSettings">
                  保存设置
                </n-button>
                <n-button @click="resetSettings" style="margin-left: 10px;">
                  重置
                </n-button>
              </n-form-item>
            </n-form>
          </div>
        </n-tab-pane>

        <!-- 修改密码 -->
        <n-tab-pane name="password" tab="修改密码">
          <div class="tab-content">
            <n-form
              ref="passwordFormRef"
              :model="passwordForm"
              :rules="passwordRules"
              label-placement="left"
              label-width="150"
            >
              <n-form-item label="当前密码" path="current_password">
                <n-input
                  v-model:value="passwordForm.current_password"
                  type="password"
                  placeholder="请输入当前密码"
                  show-password-on="click"
                />
              </n-form-item>
              
              <n-form-item label="新密码" path="new_password">
                <n-input
                  v-model:value="passwordForm.new_password"
                  type="password"
                  placeholder="请输入新密码"
                  show-password-on="click"
                />
                <template #help>
                  密码长度至少6位
                </template>
              </n-form-item>
              
              <n-form-item label="确认新密码" path="confirm_password">
                <n-input
                  v-model:value="passwordForm.confirm_password"
                  type="password"
                  placeholder="请再次输入新密码"
                  show-password-on="click"
                />
              </n-form-item>
              
              <n-form-item>
                <n-button type="primary" @click="changePassword" :loading="changingPassword">
                  修改密码
                </n-button>
                <n-button @click="resetPasswordForm" style="margin-left: 10px;">
                  重置
                </n-button>
              </n-form-item>
            </n-form>
          </div>
        </n-tab-pane>

        <!-- 邮件统计 -->
        <n-tab-pane name="statistics" tab="邮件统计">
          <div class="tab-content">
            <n-row :gutter="16">
              <n-col :span="8">
                <n-card>
                  <n-statistic label="总邮件数" :value="mailStats.total" />
                </n-card>
              </n-col>
              <n-col :span="8">
                <n-card>
                  <n-statistic label="有附件邮件" :value="mailStats.withAttachments" />
                </n-card>
              </n-col>
              <n-col :span="8">
                <n-card>
                  <n-statistic label="今日邮件" :value="mailStats.today" />
                </n-card>
              </n-col>
            </n-row>
            
            <n-divider />
            
            <n-card title="最近邮件">
              <n-list>
                <n-list-item v-for="mail in recentMails" :key="mail.id">
                  <n-thing>
                    <template #header>
                      <n-space align="center">
                        <span>{{ mail.subject || '无主题' }}</span>
                        <n-tag v-if="mail.has_attachments" size="small" type="info">
                          有附件
                        </n-tag>
                      </n-space>
                    </template>
                    <template #description>
                      <n-space vertical size="small">
                        <span>发件人: {{ mail.sender_email }}</span>
                        <span>时间: {{ formatDate(mail.received_at) }}</span>
                      </n-space>
                    </template>
                  </n-thing>
                </n-list-item>
              </n-list>
            </n-card>
          </div>
        </n-tab-pane>
      </n-tabs>
    </n-card>
  </div>
</template>

<style scoped>
.user-container {
  padding: 20px;
  max-width: 800px;
  margin: 0 auto;
}

.user-card {
  margin-bottom: 20px;
}

.tab-content {
  padding: 20px 0;
}

.n-form-item {
  margin-bottom: 20px;
}

.n-divider {
  margin: 20px 0;
}
</style>
