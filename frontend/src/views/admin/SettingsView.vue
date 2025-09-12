<template>
  <div class="settings-container">
    <n-card title="系统设置">
      <n-form
        ref="formRef"
        :model="formData"
        :rules="rules"
        label-placement="left"
        label-width="auto"
        size="large"
      >
        <n-form-item label="调试模式" path="debug_mode">
          <n-switch v-model:value="formData.debug_mode" />
          <div class="form-help">
            启用后将在控制台显示详细的调试信息
          </div>
        </n-form-item>
        
        <n-form-item label="允许用户注册" path="allow_registration">
          <n-switch v-model:value="formData.allow_registration" />
          <div class="form-help">
            关闭后新用户将无法注册账户
          </div>
        </n-form-item>
        
        <n-form-item label="自动审核邮箱" path="auto_approve_mailbox">
          <n-switch v-model:value="formData.auto_approve_mailbox" />
          <div class="form-help">
            启用后用户申请的邮箱将自动通过审核
          </div>
        </n-form-item>
        
        <n-form-item label="支持的域名" path="supported_domains">
          <n-dynamic-tags
            v-model:value="formData.supported_domains"
            placeholder="输入域名后按回车添加"
          />
          <div class="form-help">
            用户只能申请这些域名的邮箱地址
          </div>
        </n-form-item>
        
        <n-form-item label="邮件保留天数" path="mail_retention_days">
          <n-input-number
            v-model:value="formData.mail_retention_days"
            :min="1"
            :max="365"
            placeholder="请输入保留天数"
            style="width: 200px;"
          />
          <div class="form-help">
            邮件将在指定天数后自动删除（0表示永不过期）
          </div>
        </n-form-item>
        
        <n-form-item label="附件最大大小(MB)" path="attachment_max_size">
          <n-input-number
            v-model:value="formData.attachment_max_size"
            :min="1"
            :max="100"
            placeholder="请输入最大大小"
            style="width: 200px;"
          />
          <div class="form-help">
            单个附件的最大大小限制
          </div>
        </n-form-item>
      </n-form>
      
      <template #action>
        <div class="form-actions">
          <n-button @click="handleReset" :disabled="loading">
            重置
          </n-button>
          <n-button
            type="primary"
            @click="handleSave"
            :loading="loading"
          >
            保存设置
          </n-button>
        </div>
      </template>
    </n-card>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue'
import { useMessage } from 'naive-ui'
import { useSystemStore } from '@/stores/system'

const message = useMessage()
const systemStore = useSystemStore()

const loading = ref(false)
const formRef = ref()

const formData = reactive({
  debug_mode: false,
  allow_registration: true,
  auto_approve_mailbox: false,
  supported_domains: [] as string[],
  mail_retention_days: 30,
  attachment_max_size: 50
})

const rules = {
  mail_retention_days: [
    { required: true, message: '请输入邮件保留天数', trigger: 'blur' },
    { type: 'number', min: 0, max: 365, message: '保留天数应在0-365之间', trigger: 'blur' }
  ],
  attachment_max_size: [
    { required: true, message: '请输入附件最大大小', trigger: 'blur' },
    { type: 'number', min: 1, max: 100, message: '附件大小应在1-100MB之间', trigger: 'blur' }
  ]
}

const loadCog = async () => {
  loading.value = true
  const result = await systemStore.fetchConfig()
  if (result.success && 'data' in result && result.data) {
    Object.assign(formData, result.data)
  }
  loading.value = false
}

const handleSave = async () => {
  try {
    await formRef.value?.validate()
    loading.value = true
    
    const result = await systemStore.updateConfig(formData)
    if (result.success) {
      message.success('设置保存成功')
    } else {
      message.error(result.error || '保存失败')
    }
  } catch (error) {
    console.error('保存设置失败:', error)
  } finally {
    loading.value = false
  }
}

const handleReset = async () => {
  await loadCog()
  message.info('已重置为当前设置')
}

onMounted(async () => {
  await loadCog()
})
</script>

<style scoped>
.settings-container {
  height: 100%;
}

.form-help {
  font-size: 12px;
  color: #666;
  margin-top: 4px;
}

.form-actions {
  display: flex;
  justify-content: flex-end;
  gap: 12px;
  margin-top: 24px;
}
</style>
