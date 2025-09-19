<template>
  <div class="loading-examples">
    <h2>加载状态使用示例</h2>
    
    <!-- 全局加载示例 -->
    <div class="example-section">
      <h3>全局加载</h3>
      <p>用于页面刷新、路由切换等全局操作</p>
      <n-button @click="showGlobalLoading">显示全局加载</n-button>
    </div>

    <!-- 页面加载示例 -->
    <div class="example-section">
      <h3>页面加载</h3>
      <p>用于整个页面的数据加载</p>
      <n-button @click="showPageLoading">显示页面加载</n-button>
    </div>

    <!-- 局部加载示例 -->
    <div class="example-section">
      <h3>局部加载</h3>
      <p>用于特定组件的加载状态</p>
      <div class="local-loading-demo">
        <LoadingOverlay 
          :show="localLoading.loading.value"
          :text="localLoading.text.value"
          type="local"
        />
        <div class="demo-content">
          <p>这是局部加载的演示内容</p>
          <n-button @click="showLocalLoading">显示局部加载</n-button>
        </div>
      </div>
    </div>

    <!-- 内联加载示例 -->
    <div class="example-section">
      <h3>内联加载</h3>
      <p>用于按钮、文本等内联元素的加载状态</p>
      <div class="inline-loading-demo">
        <LoadingOverlay 
          :show="inlineLoading.loading.value"
          :text="inlineLoading.text.value"
          type="inline"
          size="small"
        />
        <n-button @click="showInlineLoading">显示内联加载</n-button>
      </div>
    </div>

    <!-- 不同尺寸示例 -->
    <div class="example-section">
      <h3>不同尺寸</h3>
      <div class="size-demo">
        <div class="size-item">
          <h4>小尺寸</h4>
          <LoadingOverlay 
            :show="true"
            text="小尺寸加载"
            type="inline"
            size="small"
          />
        </div>
        <div class="size-item">
          <h4>中等尺寸</h4>
          <LoadingOverlay 
            :show="true"
            text="中等尺寸加载"
            type="inline"
            size="medium"
          />
        </div>
        <div class="size-item">
          <h4>大尺寸</h4>
          <LoadingOverlay 
            :show="true"
            text="大尺寸加载"
            type="inline"
            size="large"
          />
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { useGlobalLoading, usePageLoading, useLoading } from '@/composables/useLoading'
import LoadingOverlay from './LoadingOverlay.vue'

const globalLoading = useGlobalLoading()
const pageLoading = usePageLoading()
const localLoading = useLoading('demo-local')
const inlineLoading = useLoading('demo-inline')

const showGlobalLoading = () => {
  globalLoading.setLoading(true, '全局加载中...')
  setTimeout(() => {
    globalLoading.setLoading(false)
  }, 3000)
}

const showPageLoading = () => {
  pageLoading.setLoading(true, '页面数据加载中...')
  setTimeout(() => {
    pageLoading.setLoading(false)
  }, 3000)
}

const showLocalLoading = () => {
  localLoading.setLoading(true, '局部数据加载中...')
  setTimeout(() => {
    localLoading.setLoading(false)
  }, 3000)
}

const showInlineLoading = () => {
  inlineLoading.setLoading(true, '处理中...')
  setTimeout(() => {
    inlineLoading.setLoading(false)
  }, 2000)
}
</script>

<style scoped>
.loading-examples {
  padding: 20px;
  max-width: 800px;
  margin: 0 auto;
}

.example-section {
  margin-bottom: 30px;
  padding: 20px;
  border: 1px solid #e0e0e0;
  border-radius: 8px;
  background: #f9f9f9;
}

.example-section h3 {
  margin-top: 0;
  color: #333;
}

.local-loading-demo {
  position: relative;
  min-height: 100px;
  padding: 20px;
  background: white;
  border-radius: 4px;
  border: 1px solid #ddd;
}

.demo-content {
  text-align: center;
}

.inline-loading-demo {
  display: flex;
  align-items: center;
  gap: 10px;
}

.size-demo {
  display: flex;
  gap: 20px;
  flex-wrap: wrap;
}

.size-item {
  flex: 1;
  min-width: 150px;
  text-align: center;
  padding: 15px;
  background: white;
  border-radius: 4px;
  border: 1px solid #ddd;
}

.size-item h4 {
  margin-top: 0;
  margin-bottom: 10px;
}
</style>
