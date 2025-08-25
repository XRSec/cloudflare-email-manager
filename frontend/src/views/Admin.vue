<script setup>
import { ref, reactive, computed, onMounted, h } from 'vue'
import { useMessage, useDialog } from 'naive-ui'
import { Plus, Search, Edit, Trash, Eye } from '@vicons/ionicons5'
import { api } from '../api'

const message = useMessage()
const dialog = useDialog()

// 响应式数据
const activeTab = ref('users')
const userLoading = ref(false)
const ruleLoading = ref(false)
const logLoading = ref(false)
const savingSettings = ref(false)
const creatingUser = ref(false)
const creatingRule = ref(false)

// 模态框控制
const showCreateUserModal = ref(false)
const showCreateRuleModal = ref(false)

// 搜索关键词
const userSearchKeyword = ref('')

// 数据
const users = ref([])
const forwardRules = ref([])
const forwardLogs = ref([])
const systemSettings = ref({
  allow_registration: true,
  cleanup_days: 7,
  max_attachment_size_mb: 50,
  domain: ''
})

// 表单数据
const createUserForm = reactive({
  email_prefix: '',
  email_password: '',
  user_type: 'user'
})

const createRuleForm = reactive({
  rule_name: '',
  sender_filter: '',
  keyword_filter: '',
  recipient_filter: '',
  webhook_url: '',
  webhook_secret: '',
  webhook_type: 'custom'
})

// 分页
const userPagination = reactive({
  page: 1,
  pageSize: 20,
  total: 0,
  showSizePicker: true,
  pageSizes: [10, 20, 50, 100]
})

const logPagination = reactive({
  page: 1,
  pageSize: 20,
  total: 0,
  showSizePicker: true,
  pageSizes: [10, 20, 50, 100]
})

// 选项
const userTypeOptions = [
  { label: '普通用户', value: 'user' },
  { label: '管理员', value: 'admin' }
]

const webhookTypeOptions = [
  { label: '自定义', value: 'custom' },
  { label: '钉钉', value: 'dingtalk' },
  { label: '飞书', value: 'feishu' }
]

// 计算属性
const filteredUsers = computed(() => {
  if (!userSearchKeyword.value) return users.value
  return users.value.filter(user => 
    user.email_prefix.includes(userSearchKeyword.value) ||
    user.user_type.includes(userSearchKeyword.value)
  )
})

// 表格列定义
const userColumns = [
  { title: 'ID', key: 'id', width: 80 },
  { title: '邮件前缀', key: 'email_prefix', width: 150 },
  { title: '用户类型', key: 'user_type', width: 100 },
  { title: 'Webhook', key: 'webhook_url', width: 200, ellipsis: true },
  { title: '创建时间', key: 'created_at', width: 180 },
  { title: '操作', key: 'actions', width: 150, render: (row) => {
    return h('div', { class: 'action-buttons' }, [
      h('n-button', {
        size: 'small',
        onClick: () => viewUserDetails(row)
      }, { default: () => '查看' }),
      h('n-button', {
        size: 'small',
        type: 'error',
        onClick: () => deleteUser(row)
      }, { default: () => '删除' })
    ])
  }}
]

const ruleColumns = [
  { title: 'ID', key: 'id', width: 80 },
  { title: '规则名称', key: 'rule_name', width: 150 },
  { title: '发件人过滤', key: 'sender_filter', width: 120 },
  { title: '关键字过滤', key: 'keyword_filter', width: 120 },
  { title: '收件人过滤', key: 'recipient_filter', width: 120 },
  { title: 'Webhook类型', key: 'webhook_type', width: 100 },
  { title: '状态', key: 'enabled', width: 80, render: (row) => 
    h('n-tag', { type: row.enabled ? 'success' : 'error' }, 
      { default: () => row.enabled ? '启用' : '禁用' }
    )
  },
  { title: '操作', key: 'actions', width: 150, render: (row) => {
    return h('div', { class: 'action-buttons' }, [
      h('n-button', {
        size: 'small',
        onClick: () => editRule(row)
      }, { default: () => '编辑' }),
      h('n-button', {
        size: 'small',
        type: 'error',
        onClick: () => deleteRule(row)
      }, { default: () => '删除' })
    ])
  }}
]

const logColumns = [
  { title: 'ID', key: 'id', width: 80 },
  { title: '邮件主题', key: 'subject', width: 200, ellipsis: true },
  { title: '发件人', key: 'sender_email', width: 150, ellipsis: true },
  { title: '收件人', key: 'email_prefix', width: 100 },
  { title: '规则名称', key: 'rule_name', width: 120 },
  { title: '状态', key: 'status', width: 80, render: (row) => 
    h('n-tag', { type: row.status === 'success' ? 'success' : 'error' }, 
      { default: () => row.status === 'success' ? '成功' : '失败' }
    )
  },
  { title: '发送时间', key: 'sent_at', width: 180 }
]

// 表单验证规则
const createUserRules = {
  email_prefix: [
    { required: true, message: '请输入邮件前缀', trigger: 'blur' },
    { pattern: /^[a-zA-Z0-9_-]+$/, message: '邮件前缀只能包含字母、数字、下划线和连字符', trigger: 'blur' }
  ],
  email_password: [
    { required: true, message: '请输入密码', trigger: 'blur' },
    { min: 6, message: '密码长度至少6位', trigger: 'blur' }
  ]
}

const createRuleRules = {
  rule_name: [
    { required: true, message: '请输入规则名称', trigger: 'blur' }
  ],
  webhook_url: [
    { required: true, message: '请输入webhook地址', trigger: 'blur' },
    { type: 'url', message: '请输入有效的URL地址', trigger: 'blur' }
  ]
}

const settingsRules = {
  cleanup_days: [
    { required: true, message: '请输入邮件保留天数', trigger: 'blur' },
    { type: 'number', min: 1, max: 365, message: '天数必须在1-365之间', trigger: 'blur' }
  ],
  max_attachment_size_mb: [
    { required: true, message: '请输入最大附件大小', trigger: 'blur' },
    { type: 'number', min: 1, max: 50, message: '大小必须在1-50MB之间', trigger: 'blur' }
  ],
  domain: [
    { required: true, message: '请输入域名', trigger: 'blur' }
  ]
}

// 方法
const loadUsers = async () => {
  try {
    userLoading.value = true
    const response = await api.fetch('/api/admin/users')
    if (response.success) {
      users.value = response.data.users
      userPagination.total = response.data.total
    }
  } catch (error) {
    message.error('加载用户列表失败')
    console.error(error)
  } finally {
    userLoading.value = false
  }
}

const loadForwardRules = async () => {
  try {
    ruleLoading.value = true
    const response = await api.fetch('/api/admin/forward-rules')
    if (response.success) {
      forwardRules.value = response.data
    }
  } catch (error) {
    message.error('加载转发规则失败')
    console.error(error)
  } finally {
    ruleLoading.value = false
  }
}

const loadForwardLogs = async () => {
  try {
    logLoading.value = true
    const response = await api.fetch('/api/admin/forward-logs')
    if (response.success) {
      forwardLogs.value = response.data.logs
      logPagination.total = response.data.total
    }
  } catch (error) {
    message.error('加载转发日志失败')
    console.error(error)
  } finally {
    logLoading.value = false
  }
}

const loadSystemSettings = async () => {
  try {
    const response = await api.fetch('/api/admin/settings')
    if (response.success) {
      const settings = {}
      response.data.forEach(item => {
        if (item.key === 'allow_registration') {
          settings[item.key] = item.value === 'true'
        } else if (item.key === 'cleanup_days') {
          settings[item.key] = parseInt(item.value)
        } else if (item.key === 'max_attachment_size') {
          settings[item.key] = parseInt(item.value) / (1024 * 1024) // 转换为MB
        } else {
          settings[item.key] = item.value
        }
      })
      systemSettings.value = { ...systemSettings.value, ...settings }
    }
  } catch (error) {
    message.error('加载系统设置失败')
    console.error(error)
  }
}

const createUser = async () => {
  try {
    creatingUser.value = true
    const response = await api.fetch('/api/admin/users', {
      method: 'POST',
      body: JSON.stringify(createUserForm)
    })
    
    if (response.success) {
      message.success('用户创建成功')
      showCreateUserModal.value = false
      // 重置表单
      Object.assign(createUserForm, {
        email_prefix: '',
        email_password: '',
        user_type: 'user'
      })
      // 重新加载用户列表
      await loadUsers()
    }
  } catch (error) {
    message.error(error.message || '创建用户失败')
    console.error(error)
  } finally {
    creatingUser.value = false
  }
}

const createForwardRule = async () => {
  try {
    creatingRule.value = true
    const response = await api.fetch('/api/admin/forward-rules', {
      method: 'POST',
      body: JSON.stringify(createRuleForm)
    })
    
    if (response.success) {
      message.success('转发规则创建成功')
      showCreateRuleModal.value = false
      // 重置表单
      Object.assign(createRuleForm, {
        rule_name: '',
        sender_filter: '',
        keyword_filter: '',
        recipient_filter: '',
        webhook_url: '',
        webhook_secret: '',
        webhook_type: 'custom'
      })
      // 重新加载规则列表
      await loadForwardRules()
    }
  } catch (error) {
    message.error(error.message || '创建转发规则失败')
    console.error(error)
  } finally {
    creatingRule.value = false
  }
}

const saveSystemSettings = async () => {
  try {
    savingSettings.value = true
    
    // 转换数据格式
    const settings = {
      allow_registration: systemSettings.value.allow_registration.toString(),
      cleanup_days: systemSettings.value.cleanup_days.toString(),
      max_attachment_size: (systemSettings.value.max_attachment_size_mb * 1024 * 1024).toString(),
      domain: systemSettings.value.domain
    }
    
    const response = await api.fetch('/api/admin/settings', {
      method: 'PUT',
      body: JSON.stringify(settings)
    })
    
    if (response.success) {
      message.success('系统设置保存成功')
    }
  } catch (error) {
    message.error(error.message || '保存系统设置失败')
    console.error(error)
  } finally {
    savingSettings.value = false
  }
}

const deleteUser = (user) => {
  dialog.warning({
    title: '确认删除',
    content: `确定要删除用户 ${user.email_prefix} 吗？此操作不可恢复。`,
    positiveText: '删除',
    negativeText: '取消',
    onPositiveClick: async () => {
      try {
        const response = await api.fetch(`/api/admin/users/${user.id}`, {
          method: 'DELETE'
        })
        
        if (response.success) {
          message.success('用户删除成功')
          await loadUsers()
        }
      } catch (error) {
        message.error(error.message || '删除用户失败')
        console.error(error)
      }
    }
  })
}

const deleteRule = (rule) => {
  dialog.warning({
    title: '确认删除',
    content: `确定要删除转发规则 "${rule.rule_name}" 吗？`,
    positiveText: '删除',
    negativeText: '取消',
    onPositiveClick: async () => {
      try {
        const response = await api.fetch(`/api/admin/forward-rules/${rule.id}`, {
          method: 'DELETE'
        })
        
        if (response.success) {
          message.success('转发规则删除成功')
          await loadForwardRules()
        }
      } catch (error) {
        message.error(error.message || '删除转发规则失败')
        console.error(error)
      }
    }
  })
}

const viewUserDetails = (user) => {
  // 这里可以实现查看用户详情的功能
  message.info(`查看用户: ${user.email_prefix}`)
}

const editRule = (rule) => {
  // 这里可以实现编辑转发规则的功能
  message.info(`编辑规则: ${rule.rule_name}`)
}

const handleUserPageChange = (page) => {
  userPagination.page = page
  loadUsers()
}

const handleLogPageChange = (page) => {
  logPagination.page = page
  loadForwardLogs()
}

// 生命周期
onMounted(async () => {
  await Promise.all([
    loadUsers(),
    loadForwardRules(),
    loadForwardLogs(),
    loadSystemSettings()
  ])
})
</script>

<template>
  <div class="admin-container">
    <n-card title="管理员控制台" class="admin-card">
      <n-tabs v-model:value="activeTab" type="line" animated>
        <!-- 用户管理 -->
        <n-tab-pane name="users" tab="用户管理">
          <div class="tab-content">
            <div class="action-bar">
              <n-button type="primary" @click="showCreateUserModal = true">
                <template #icon>
                  <n-icon><Plus /></n-icon>
                </template>
                创建用户
              </n-button>
              <n-input
                v-model:value="userSearchKeyword"
                placeholder="搜索用户..."
                style="width: 200px;"
                clearable
              >
                <template #prefix>
                  <n-icon><Search /></n-icon>
                </template>
              </n-input>
            </div>
            
            <n-data-table
              :columns="userColumns"
              :data="filteredUsers"
              :pagination="userPagination"
              :loading="userLoading"
              @update:page="handleUserPageChange"
            />
          </div>
        </n-tab-pane>

        <!-- 转发规则管理 -->
        <n-tab-pane name="rules" tab="转发规则">
          <div class="tab-content">
            <div class="action-bar">
              <n-button type="primary" @click="showCreateRuleModal = true">
                <template #icon>
                  <n-icon><Plus /></n-icon>
                </template>
                创建规则
              </n-button>
            </div>
            
            <n-data-table
              :columns="ruleColumns"
              :data="forwardRules"
              :loading="ruleLoading"
            />
          </div>
        </n-tab-pane>

        <!-- 系统设置 -->
        <n-tab-pane name="settings" tab="系统设置">
          <div class="tab-content">
            <n-form
              ref="settingsFormRef"
              :model="systemSettings"
              :rules="settingsRules"
              label-placement="left"
              label-width="200"
            >
              <n-form-item label="允许用户注册" path="allow_registration">
                <n-switch v-model:value="systemSettings.allow_registration" />
              </n-form-item>
              
              <n-form-item label="邮件保留天数" path="cleanup_days">
                <n-input-number
                  v-model:value="systemSettings.cleanup_days"
                  :min="1"
                  :max="365"
                  placeholder="请输入天数"
                />
              </n-form-item>
              
              <n-form-item label="最大附件大小(MB)" path="max_attachment_size">
                <n-input-number
                  v-model:value="systemSettings.max_attachment_size_mb"
                  :min="1"
                  :max="50"
                  placeholder="请输入大小"
                />
              </n-form-item>
              
              <n-form-item label="域名" path="domain">
                <n-input
                  v-model:value="systemSettings.domain"
                  placeholder="请输入域名"
                />
              </n-form-item>
              
              <n-form-item>
                <n-button type="primary" @click="saveSystemSettings" :loading="savingSettings">
                  保存设置
                </n-button>
              </n-form-item>
            </n-form>
          </div>
        </n-tab-pane>

        <!-- 转发日志 -->
        <n-tab-pane name="logs" tab="转发日志">
          <div class="tab-content">
            <n-data-table
              :columns="logColumns"
              :data="forwardLogs"
              :pagination="logPagination"
              :loading="logLoading"
              @update:page="handleLogPageChange"
            />
          </div>
        </n-tab-pane>
      </n-tabs>
    </n-card>

    <!-- 创建用户模态框 -->
    <n-modal v-model:show="showCreateUserModal" preset="card" title="创建用户" style="width: 500px;">
      <n-form
        ref="createUserFormRef"
        :model="createUserForm"
        :rules="createUserRules"
        label-placement="left"
        label-width="100"
      >
        <n-form-item label="邮件前缀" path="email_prefix">
          <n-input
            v-model:value="createUserForm.email_prefix"
            placeholder="请输入邮件前缀"
          />
        </n-form-item>
        
        <n-form-item label="密码" path="email_password">
          <n-input
            v-model:value="createUserForm.email_password"
            type="password"
            placeholder="请输入密码"
            show-password-on="click"
          />
        </n-form-item>
        
        <n-form-item label="用户类型" path="user_type">
          <n-select
            v-model:value="createUserForm.user_type"
            :options="userTypeOptions"
            placeholder="请选择用户类型"
          />
        </n-form-item>
      </n-form>
      
      <template #footer>
        <n-space justify="end">
          <n-button @click="showCreateUserModal = false">取消</n-button>
          <n-button type="primary" @click="createUser" :loading="creatingUser">创建</n-button>
        </n-space>
      </template>
    </n-modal>

    <!-- 创建转发规则模态框 -->
    <n-modal v-model:show="showCreateRuleModal" preset="card" title="创建转发规则" style="width: 600px;">
      <n-form
        ref="createRuleFormRef"
        :model="createRuleForm"
        :rules="createRuleRules"
        label-placement="left"
        label-width="120"
      >
        <n-form-item label="规则名称" path="rule_name">
          <n-input
            v-model:value="createRuleForm.rule_name"
            placeholder="请输入规则名称"
          />
        </n-form-item>
        
        <n-form-item label="发件人过滤" path="sender_filter">
          <n-input
            v-model:value="createRuleForm.sender_filter"
            placeholder="邮箱或域名，留空表示不过滤"
          />
        </n-form-item>
        
        <n-form-item label="关键字过滤" path="keyword_filter">
          <n-input
            v-model:value="createRuleForm.keyword_filter"
            placeholder="邮件主题或内容关键字，留空表示不过滤"
          />
        </n-form-item>
        
        <n-form-item label="收件人过滤" path="recipient_filter">
          <n-input
            v-model:value="createRuleForm.recipient_filter"
            placeholder="收件人前缀，留空表示不过滤"
          />
        </n-form-item>
        
        <n-form-item label="Webhook地址" path="webhook_url">
          <n-input
            v-model:value="createRuleForm.webhook_url"
            placeholder="请输入webhook地址"
          />
        </n-form-item>
        
        <n-form-item label="Webhook密钥" path="webhook_secret">
          <n-input
            v-model:value="createRuleForm.webhook_secret"
            placeholder="请输入webhook密钥（可选）"
            show-password-on="click"
          />
        </n-form-item>
        
        <n-form-item label="Webhook类型" path="webhook_type">
          <n-select
            v-model:value="createRuleForm.webhook_type"
            :options="webhookTypeOptions"
            placeholder="请选择webhook类型"
          />
        </n-form-item>
      </n-form>
      
      <template #footer>
        <n-space justify="end">
          <n-button @click="showCreateRuleModal = false">取消</n-button>
          <n-button type="primary" @click="createForwardRule" :loading="creatingRule">创建</n-button>
        </n-space>
      </template>
    </n-modal>
  </div>
</template>

<style scoped>
.admin-container {
  padding: 20px;
  max-width: 1200px;
  margin: 0 auto;
}

.admin-card {
  margin-bottom: 20px;
}

.tab-content {
  padding: 20px 0;
}

.action-bar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 20px;
}

.action-buttons {
  display: flex;
  gap: 8px;
}

.n-form-item {
  margin-bottom: 20px;
}
</style>
