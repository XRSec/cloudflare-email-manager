<script setup>
import { ref, reactive, computed, onMounted, h } from 'vue'
import { useMessage, useDialog } from 'naive-ui'
import { PersonAdd, LogIn, Refresh, Search, Eye, Trash, Download } from '@vicons/ionicons5'
import { useGlobalState } from '../store'
import { api } from '../api'

const message = useMessage()
const dialog = useDialog()
const { jwt, userSettings } = useGlobalState()

// 响应式数据
const loading = ref(false)
const refreshing = ref(false)
const registering = ref(false)
const loggingIn = ref(false)

// 模态框控制
const showRegisterModal = ref(false)
const showLoginModal = ref(false)
const showMailDetailModal = ref(false)

// 搜索和分页
const searchKeyword = ref('')
const pageSize = ref(20)
const currentPage = ref(1)
const totalMails = ref(0)

// 数据
const mails = ref([])
const selectedMail = ref(null)

// 表单数据
const registerForm = reactive({
  email_password: '',
  confirm_password: ''
})

const loginForm = reactive({
  email_prefix: '',
  email_password: ''
})

// 分页选项
const pageSizeOptions = [
  { label: '10条/页', value: 10 },
  { label: '20条/页', value: 20 },
  { label: '50条/页', value: 50 },
  { label: '100条/页', value: 100 }
]

// 分页配置
const pagination = computed(() => ({
  page: currentPage.value,
  pageSize: pageSize.value,
  total: totalMails.value,
  showSizePicker: true,
  pageSizes: [10, 20, 50, 100],
  onChange: handlePageChange,
  onUpdatePageSize: handlePageSizeChange
}))

// 计算属性
const isLoggedIn = computed(() => !!jwt.value)

// 表格列定义
const mailColumns = [
  { title: 'ID', key: 'id', width: 80 },
  { title: '发件人', key: 'sender_email', width: 200, ellipsis: true },
  { title: '主题', key: 'subject', width: 300, ellipsis: true },
  { title: '时间', key: 'received_at', width: 180 },
  { title: '附件', key: 'has_attachments', width: 80, render: (row) => 
    row.has_attachments ? 
      h('n-tag', { type: 'info', size: 'small' }, { default: () => '有' }) :
      h('n-tag', { type: 'default', size: 'small' }, { default: () => '无' })
  },
  { title: '操作', key: 'actions', width: 150, render: (row) => {
    return h('div', { class: 'action-buttons' }, [
      h('n-button', {
        size: 'small',
        onClick: () => viewMailDetail(row)
      }, { default: () => '查看' }),
      h('n-button', {
        size: 'small',
        type: 'error',
        onClick: () => deleteMailConfirm(row)
      }, { default: () => '删除' })
    ])
  }}
]

// 表单验证规则
const registerRules = {
  email_password: [
    { required: true, message: '请输入密码', trigger: 'blur' },
    { min: 6, message: '密码长度至少6位', trigger: 'blur' }
  ],
  confirm_password: [
    { required: true, message: '请确认密码', trigger: 'blur' },
    {
      validator: (rule, value) => {
        if (value !== registerForm.email_password) {
          return new Error('两次输入的密码不一致')
        }
        return true
      },
      trigger: 'blur'
    }
  ]
}

const loginRules = {
  email_prefix: [
    { required: true, message: '请输入邮件前缀', trigger: 'blur' }
  ],
  email_password: [
    { required: true, message: '请输入密码', trigger: 'blur' }
  ]
}

// 方法
const loadMails = async () => {
  if (!isLoggedIn.value) return
  
  try {
    loading.value = true
    const response = await api.fetch(`/api/mails?limit=${pageSize.value}&offset=${(currentPage.value - 1) * pageSize.value}`)
    if (response.success) {
      mails.value = response.data.mails
      totalMails.value = response.data.total
    }
  } catch (error) {
    message.error('加载邮件列表失败')
    console.error(error)
  } finally {
    loading.value = false
  }
}

const refreshMails = async () => {
  refreshing.value = true
  await loadMails()
  refreshing.value = false
}

const searchMails = async () => {
  if (!searchKeyword.value.trim()) {
    await loadMails()
    return
  }
  
  try {
    loading.value = true
    const response = await api.fetch(`/api/mails?limit=${pageSize.value}&offset=0&keyword=${encodeURIComponent(searchKeyword.value)}`)
    if (response.success) {
      mails.value = response.data.mails
      totalMails.value = response.data.total
      currentPage.value = 1
    }
  } catch (error) {
    message.error('搜索邮件失败')
    console.error(error)
  } finally {
    loading.value = false
  }
}

const clearSearch = () => {
  searchKeyword.value = ''
  loadMails()
}

const handlePageChange = (page) => {
  currentPage.value = page
  loadMails()
}

const handlePageSizeChange = (size) => {
  pageSize.value = size
  currentPage.value = 1
  loadMails()
}

const register = async () => {
  try {
    registering.value = true
    const response = await api.fetch('/api/register', {
      method: 'POST',
      body: JSON.stringify({
        email_password: registerForm.email_password
      })
    })
    
    if (response.success) {
      message.success('注册成功！您的邮箱地址是：' + response.data.email_address)
      showRegisterModal.value = false
      // 重置表单
      Object.assign(registerForm, {
        email_password: '',
        confirm_password: ''
      })
      // 自动登录
      await loginWithCredentials(response.data.email_prefix, registerForm.email_password)
    }
  } catch (error) {
    message.error(error.message || '注册失败')
    console.error(error)
  } finally {
    registering.value = false
  }
}

const login = async () => {
  try {
    loggingIn.value = true
    await loginWithCredentials(loginForm.email_prefix, loginForm.email_password)
  } catch (error) {
    message.error(error.message || '登录失败')
    console.error(error)
  } finally {
    loggingIn.value = false
  }
}

const loginWithCredentials = async (emailPrefix, password) => {
  const response = await api.fetch('/api/login', {
    method: 'POST',
    body: JSON.stringify({
      email_prefix: emailPrefix,
      email_password: password
    })
  })
  
  if (response.success) {
    jwt.value = response.data.token
    message.success('登录成功')
    showLoginModal.value = false
    // 重置表单
    Object.assign(loginForm, {
      email_prefix: '',
      email_password: ''
    })
    // 加载邮件
    await loadMails()
  } else {
    throw new Error(response.message || '登录失败')
  }
}

const viewMailDetail = async (mail) => {
  try {
    const response = await api.fetch(`/api/mails/${mail.id}`)
    if (response.success) {
      selectedMail.value = response.data
      showMailDetailModal.value = true
    }
  } catch (error) {
    message.error('获取邮件详情失败')
    console.error(error)
  }
}

const deleteMailConfirm = (mail) => {
  dialog.warning({
    title: '确认删除',
    content: `确定要删除这封邮件吗？此操作不可恢复。`,
    positiveText: '删除',
    negativeText: '取消',
    onPositiveClick: () => deleteMail(mail.id)
  })
}

const deleteMail = async (mailId) => {
  try {
    const response = await api.fetch(`/api/mails/${mailId}`, {
      method: 'DELETE'
    })
    
    if (response.success) {
      message.success('邮件删除成功')
      showMailDetailModal.value = false
      await loadMails()
    }
  } catch (error) {
    message.error(error.message || '删除邮件失败')
    console.error(error)
  }
}

const downloadAttachment = async (attachment) => {
  try {
    const response = await api.fetch(`/api/attachments/${attachment.id}/download`)
    if (response.ok) {
      const blob = await response.blob()
      const url = window.URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = attachment.filename
      document.body.appendChild(a)
      a.click()
      window.URL.revokeObjectURL(url)
      document.body.removeChild(a)
      message.success('附件下载成功')
    }
  } catch (error) {
    message.error('附件下载失败')
    console.error(error)
  }
}

const formatDate = (dateString) => {
  if (!dateString) return ''
  return new Date(dateString).toLocaleString('zh-CN')
}

const formatFileSize = (bytes) => {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
}

// 生命周期
onMounted(async () => {
  if (isLoggedIn.value) {
    await loadMails()
  }
})
</script>

<template>
  <div class="index-container">
    <!-- 顶部操作栏 -->
    <n-card class="action-card">
      <n-space justify="space-between" align="center">
        <div class="left-actions">
          <n-button type="primary" @click="showRegisterModal = true" v-if="!isLoggedIn">
            <template #icon>
              <n-icon><PersonAdd /></n-icon>
            </template>
            注册账户
          </n-button>
          <n-button @click="showLoginModal = true" v-if="!isLoggedIn">
            <template #icon>
              <n-icon><LogIn /></n-icon>
            </template>
            登录
          </n-button>
          <n-button @click="refreshMails" v-if="isLoggedIn" :loading="refreshing">
            <template #icon>
              <n-icon><Refresh /></n-icon>
            </template>
            刷新
          </n-button>
        </div>
        
        <div class="right-actions" v-if="isLoggedIn">
          <n-space>
            <n-input
              v-model:value="searchKeyword"
              placeholder="搜索邮件..."
              style="width: 200px;"
              clearable
              @keyup.enter="searchMails"
            >
              <template #prefix>
                <n-icon><Search /></n-icon>
              </template>
            </n-input>
            <n-button @click="searchMails" type="primary">
              搜索
            </n-button>
            <n-button @click="clearSearch">
              清除
            </n-button>
          </n-space>
        </div>
      </n-space>
    </n-card>

    <!-- 邮件列表 -->
    <n-card v-if="isLoggedIn" title="邮件列表" class="mail-card">
      <template #header-extra>
        <n-space>
          <n-select
            v-model:value="pageSize"
            :options="pageSizeOptions"
            size="small"
            style="width: 100px;"
          />
          <span>共 {{ totalMails }} 封邮件</span>
        </n-space>
      </template>
      
      <n-data-table
        :columns="mailColumns"
        :data="mails"
        :pagination="pagination"
        :loading="loading"
        @update:page="handlePageChange"
        @update:page-size="handlePageSizeChange"
      />
    </n-card>

    <!-- 未登录提示 -->
    <n-card v-else class="welcome-card">
      <n-result
        status="info"
        title="欢迎使用临时邮箱系统"
        description="请先注册或登录账户以查看邮件"
      >
        <template #footer>
          <n-space>
            <n-button type="primary" @click="showRegisterModal = true">
              立即注册
            </n-button>
            <n-button @click="showLoginModal = true">
              已有账户？登录
            </n-button>
          </n-space>
        </template>
      </n-result>
    </n-card>

    <!-- 注册模态框 -->
    <n-modal v-model:show="showRegisterModal" preset="card" title="注册账户" style="width: 400px;">
      <n-form
        ref="registerFormRef"
        :model="registerForm"
        :rules="registerRules"
        label-placement="left"
        label-width="100"
      >
        <n-form-item label="密码" path="email_password">
          <n-input
            v-model:value="registerForm.email_password"
            type="password"
            placeholder="请输入密码（至少6位）"
            show-password-on="click"
          />
        </n-form-item>
        
        <n-form-item label="确认密码" path="confirm_password">
          <n-input
            v-model:value="registerForm.confirm_password"
            type="password"
            placeholder="请再次输入密码"
            show-password-on="click"
          />
        </n-form-item>
      </n-form>
      
      <template #footer>
        <n-space justify="end">
          <n-button @click="showRegisterModal = false">取消</n-button>
          <n-button type="primary" @click="register" :loading="registering">注册</n-button>
        </n-space>
      </template>
    </n-modal>

    <!-- 登录模态框 -->
    <n-modal v-model:show="showLoginModal" preset="card" title="登录账户" style="width: 400px;">
      <n-form
        ref="loginFormRef"
        :model="loginForm"
        :rules="loginRules"
        label-placement="left"
        label-width="100"
      >
        <n-form-item label="邮件前缀" path="email_prefix">
          <n-input
            v-model:value="loginForm.email_prefix"
            placeholder="请输入邮件前缀"
          />
        </n-form-item>
        
        <n-form-item label="密码" path="email_password">
          <n-input
            v-model:value="loginForm.email_password"
            type="password"
            placeholder="请输入密码"
            show-password-on="click"
          />
        </n-form-item>
      </n-form>
      
      <template #footer>
        <n-space justify="end">
          <n-button @click="showLoginModal = false">取消</n-button>
          <n-button type="primary" @click="login" :loading="loggingIn">登录</n-button>
        </n-space>
      </template>
    </n-modal>

    <!-- 邮件详情模态框 -->
    <n-modal v-model:show="showMailDetailModal" preset="card" title="邮件详情" style="width: 800px;">
      <div v-if="selectedMail" class="mail-detail">
        <n-descriptions title="邮件信息" :column="2" bordered>
          <n-descriptions-item label="发件人">
            {{ selectedMail.sender_email }}
          </n-descriptions-item>
          <n-descriptions-item label="收件人">
            {{ selectedMail.recipient_email }}
          </n-descriptions-item>
          <n-descriptions-item label="主题">
            {{ selectedMail.subject || '无主题' }}
          </n-descriptions-item>
          <n-descriptions-item label="时间">
            {{ formatDate(selectedMail.received_at) }}
          </n-descriptions-item>
        </n-descriptions>
        
        <n-divider />
        
        <n-tabs type="line">
          <n-tab-pane name="text" tab="文本内容">
            <div class="mail-content">
              <pre>{{ selectedMail.text_content || '无文本内容' }}</pre>
            </div>
          </n-tab-pane>
          
          <n-tab-pane name="html" tab="HTML内容" v-if="selectedMail.html_content">
            <div class="mail-content">
              <div v-html="selectedMail.html_content"></div>
            </div>
          </n-tab-pane>
          
          <n-tab-pane name="attachments" tab="附件" v-if="selectedMail.attachments && selectedMail.attachments.length > 0">
            <n-list>
              <n-list-item v-for="attachment in selectedMail.attachments" :key="attachment.id">
                <n-thing>
                  <template #header>
                    <n-space align="center">
                      <span>{{ attachment.filename }}</span>
                      <n-tag size="small" type="info">
                        {{ formatFileSize(attachment.size_bytes) }}
                      </n-tag>
                    </n-space>
                  </template>
                  <template #description>
                    <span>{{ attachment.content_type }}</span>
                  </template>
                  <template #action>
                    <n-button size="small" @click="downloadAttachment(attachment)">
                      下载
                    </n-button>
                  </template>
                </n-thing>
              </n-list-item>
            </n-list>
          </n-tab-pane>
        </n-tabs>
      </div>
      
      <template #footer>
        <n-space justify="end">
          <n-button @click="showMailDetailModal = false">关闭</n-button>
          <n-button type="error" @click="deleteMail" v-if="selectedMail">
            删除邮件
          </n-button>
        </n-space>
      </template>
    </n-modal>
  </div>
</template>

<style scoped>
.index-container {
  padding: 20px;
  max-width: 1200px;
  margin: 0 auto;
}

.action-card {
  margin-bottom: 20px;
}

.mail-card {
  margin-bottom: 20px;
}

.welcome-card {
  text-align: center;
  padding: 40px;
}

.left-actions {
  display: flex;
  gap: 10px;
}

.right-actions {
  display: flex;
  align-items: center;
}

.action-buttons {
  display: flex;
  gap: 8px;
}

.mail-detail {
  max-height: 600px;
  overflow-y: auto;
}

.mail-content {
  background: #f5f5f5;
  padding: 15px;
  border-radius: 4px;
  max-height: 300px;
  overflow-y: auto;
}

.mail-content pre {
  margin: 0;
  white-space: pre-wrap;
  word-wrap: break-word;
}
</style>
