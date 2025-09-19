<template>
  <div class="forward-rules-container">
    <n-card title="转发规则管理">
      <template #header-extra>
        <n-button type="primary" @click="showCreateModal = true">
          <template #icon>
            <n-icon>
              <Plus />
            </n-icon>
          </template>
          创建规则
        </n-button>
      </template>

      <div class="table-container">
        <LoadingOverlay 
          :show="loading"
          text="加载转发规则..."
          type="local"
        />
        <n-data-table
          :columns="columns"
          :data="systemStore.forwardRules"
          :loading="false"
          :bordered="false"
          striped
        />
      </div>
    </n-card>

    <!-- 创建/编辑规则模态框 -->
    <n-modal
      v-model:show="showCreateModal"
      preset="dialog"
      :title="editingRule ? '编辑转发规则' : '创建转发规则'"
      :mask-closable="false"
    >
      <n-form
        ref="formRef"
        :model="formData"
        :rules="rules"
        label-placement="left"
        label-width="auto"
      >
        <n-form-item label="规则名称" path="name">
          <n-input
            v-model:value="formData.name"
            placeholder="请输入规则名称"
            :disabled="loading"
          />
        </n-form-item>
        
        <n-form-item label="发件人邮箱" path="from_email">
          <n-input
            v-model:value="formData.from_email"
            placeholder="请输入发件人邮箱"
            :disabled="loading"
          />
        </n-form-item>
        
        <n-form-item label="收件人邮箱" path="to_email">
          <n-input
            v-model:value="formData.to_email"
            placeholder="请输入收件人邮箱"
            :disabled="loading"
          />
        </n-form-item>
        
        <n-form-item label="关键字过滤" path="keyword_filter">
          <n-input
            v-model:value="formData.keyword_filter"
            placeholder="可选：输入关键字过滤"
            :disabled="loading"
          />
        </n-form-item>
        
        <n-form-item label="Webhook类型" path="webhook_type">
          <n-select
            v-model:value="formData.webhook_type"
            :options="webhookTypeOptions"
            placeholder="请选择Webhook类型"
            :disabled="loading"
          />
        </n-form-item>
        
        <n-form-item label="Webhook URL" path="webhook_url">
          <n-input
            v-model:value="formData.webhook_url"
            placeholder="请输入Webhook URL"
            :disabled="loading"
          />
        </n-form-item>
        
        <n-form-item label="Webhook密钥" path="webhook_secret">
          <n-input
            v-model:value="formData.webhook_secret"
            placeholder="可选：输入Webhook密钥"
            :disabled="loading"
          />
        </n-form-item>
        
        <n-form-item label="启用状态" path="is_active">
          <n-switch v-model:value="formData.is_active" />
        </n-form-item>
      </n-form>

      <template #action>
        <div class="modal-actions">
          <n-button @click="handleCancel" :disabled="loading">
            取消
          </n-button>
          <n-button
            type="primary"
            @click="handleSubmit"
            :loading="loading"
          >
            {{ editingRule ? '更新' : '创建' }}
          </n-button>
        </div>
      </template>
    </n-modal>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted, h } from 'vue'
import { useSystemStore } from '@/stores/system'
import LoadingOverlay from '@/components/UI/LoadingOverlay.vue'
import type { ForwardRule } from '@/api'
import { message } from 'ant-design-vue'

// 移除 naive-ui 相关导入
const dialog = useDialog()
const systemStore = useSystemStore()

const loading = ref(false)
const showCreateModal = ref(false)
const editingRule = ref<ForwardRule | null>(null)
const formRef = ref()

const formData = reactive({
  name: '',
  from_email: '',
  to_email: '',
  keyword_filter: '',
  webhook_type: 'custom' as 'dingtalk' | 'feishu' | 'custom',
  webhook_url: '',
  webhook_secret: '',
  is_active: true
})

const rules = {
  name: [
    { required: true, message: '请输入规则名称', trigger: 'blur' }
  ],
  from_email: [
    { required: true, message: '请输入发件人邮箱', trigger: 'blur' },
    { type: 'email', message: '请输入有效的邮箱地址', trigger: 'blur' }
  ],
  to_email: [
    { required: true, message: '请输入收件人邮箱', trigger: 'blur' },
    { type: 'email', message: '请输入有效的邮箱地址', trigger: 'blur' }
  ],
  webhook_type: [
    { required: true, message: '请选择Webhook类型', trigger: 'change' }
  ],
  webhook_url: [
    { required: true, message: '请输入Webhook URL', trigger: 'blur' },
    { type: 'url', message: '请输入有效的URL', trigger: 'blur' }
  ]
}

const webhookTypeOptions = [
  { label: '钉钉', value: 'dingtalk' },
  { label: '飞书', value: 'feishu' },
  { label: '自定义', value: 'custom' }
]

const columns: DataTableColumns<ForwardRule> = [
  {
    title: '规则名称',
    key: 'name'
  },
  {
    title: '发件人',
    key: 'from_email',
    render: (row) => {
      return h('span', { style: 'font-family: monospace' }, row.from_email)
    }
  },
  {
    title: '收件人',
    key: 'to_email',
    render: (row) => {
      return h('span', { style: 'font-family: monospace' }, row.to_email)
    }
  },
  {
    title: '关键字过滤',
    key: 'keyword_filter',
    render: (row) => {
      return row.keyword_filter || '-'
    }
  },
  {
    title: 'Webhook类型',
    key: 'webhook_type',
    render: (row) => {
      const typeMap = {
        dingtalk: '钉钉',
        feishu: '飞书',
        custom: '自定义'
      }
      return typeMap[row.webhook_type] || row.webhook_type
    }
  },
  {
    title: '状态',
    key: 'is_active',
    render: (row) => {
      return h('n-tag', { 
        type: row.is_active ? 'success' : 'default' 
      }, { default: () => row.is_active ? '启用' : '禁用' })
    }
  },
  {
    title: '创建时间',
    key: 'created_at',
    render: (row) => {
      return new Date(row.created_at).toLocaleString()
    }
  },
  {
    title: '操作',
    key: 'actions',
    render: (row) => {
      return h('div', { class: 'action-buttons' }, [
        h('n-button', {
          size: 'small',
          type: 'primary',
          onClick: () => handleEdit(row)
        }, {
          icon: () => h(Edit),
          default: () => '编辑'
        }),
        h('n-button', {
          size: 'small',
          type: 'error',
          onClick: () => handleDelete(row)
        }, {
          icon: () => h(Trash),
          default: () => '删除'
        })
      ])
    }
  }
]

const handleCreate = () => {
  editingRule.value = null
  resetForm()
  showCreateModal.value = true
}

const handleEdit = (rule: ForwardRule) => {
  editingRule.value = rule
  Object.assign(formData, rule)
  showCreateModal.value = true
}

const handleDelete = (rule: ForwardRule) => {
  dialog.warning({
    title: '确认删除',
    content: `您确定要删除规则 "${rule.name}" 吗？`,
    positiveText: '确定',
    negativeText: '取消',
    onPositiveClick: async () => {
      const result = await systemStore.deleteForwardRule(rule.id)
      if (result.success) {
        message.success('删除成功')
        await loadRules()
      } else {
        message.error(result.error || '删除失败')
      }
    }
  })
}

const handleSubmit = async () => {
  try {
    await formRef.value?.validate()
    loading.value = true
    
    let result
    if (editingRule.value) {
      result = await systemStore.updateForwardRule(editingRule.value.id, formData)
    } else {
      result = await systemStore.createForwardRule(formData)
    }
    
    if (result.success) {
      message.success(editingRule.value ? '更新成功' : '创建成功')
      showCreateModal.value = false
      resetForm()
      await loadRules()
    } else {
      message.error(result.error || '操作失败')
    }
  } catch (error) {
    console.error('提交失败:', error)
  } finally {
    loading.value = false
  }
}

const handleCancel = () => {
  showCreateModal.value = false
  resetForm()
}

const resetForm = () => {
  Object.assign(formData, {
    name: '',
    from_email: '',
    to_email: '',
    keyword_filter: '',
    webhook_type: 'custom',
    webhook_url: '',
    webhook_secret: '',
    is_active: true
  })
}

const loadRules = async () => {
  loading.value = true
  await systemStore.fetchForwardRules()
  loading.value = false
}

onMounted(async () => {
  await loadRules()
})
</script>

<style scoped>
.forward-rules-container {
  height: 100%;
}

.table-container {
  position: relative;
  min-height: 200px;
}

.action-buttons {
  display: flex;
  gap: 8px;
}

.modal-actions {
  display: flex;
  justify-content: flex-end;
  gap: 12px;
}
</style>
