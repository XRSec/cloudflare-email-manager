<template>
  <div class="test-antd">
    <h2>Ant Design Vue 测试页面</h2>
    
    <a-card title="基础组件测试" style="margin-bottom: 20px;">
      <a-space direction="vertical" style="width: 100%;">
        <a-button type="primary">主要按钮</a-button>
        <a-button type="default">默认按钮</a-button>
        <a-button type="dashed">虚线按钮</a-button>
        <a-button type="link">链接按钮</a-button>
        
        <a-input placeholder="请输入内容" />
        <a-input-password placeholder="请输入密码" />
        
        <a-select placeholder="请选择" style="width: 200px;">
          <a-select-option value="option1">选项1</a-select-option>
          <a-select-option value="option2">选项2</a-select-option>
        </a-select>
        
        <a-checkbox>复选框</a-checkbox>
        <a-radio-group>
          <a-radio value="radio1">单选1</a-radio>
          <a-radio value="radio2">单选2</a-radio>
        </a-radio-group>
      </a-space>
    </a-card>
    
    <a-card title="表单测试">
      <a-form @finish="handleSubmit" layout="vertical">
        <a-form-item label="用户名" name="username">
          <a-input v-model:value="formData.username" placeholder="请输入用户名" />
        </a-form-item>
        <a-form-item label="邮箱" name="email">
          <a-input v-model:value="formData.email" placeholder="请输入邮箱" />
        </a-form-item>
        <a-form-item label="描述" name="description">
          <a-textarea v-model:value="formData.description" placeholder="请输入描述" />
        </a-form-item>
        <a-form-item>
          <a-button type="primary" html-type="submit">提交</a-button>
          <a-button style="margin-left: 10px;">重置</a-button>
        </a-form-item>
      </a-form>
    </a-card>
  </div>
</template>

<script setup lang="ts">
import { reactive } from 'vue'

const formData = reactive({
  username: '',
  email: '',
  description: ''
})

const handleSubmit = (values: any) => {
  console.log('表单提交:', values)
  console.log('当前数据:', formData)
}
</script>

<style scoped>
.test-antd {
  padding: 20px;
  max-width: 800px;
  margin: 0 auto;
}
</style>
