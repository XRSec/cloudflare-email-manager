<template>
  <Teleport to="body">
    <Transition name="modal">
      <div v-if="visible" class="modal-overlay" @click="handleOverlayClick">
        <div class="modal-container" :class="modalClass" @click.stop>
          <!-- 模态框头部 -->
          <div class="modal-header" v-if="!hideHeader">
            <h3 class="modal-title">
              <slot name="title">{{ title }}</slot>
            </h3>
            <button v-if="closable" class="modal-close" @click="handleClose" :disabled="loading">
              ✕
            </button>
          </div>

          <!-- 模态框内容 -->
          <div class="modal-body" :class="{ 'has-footer': hasFooter }">
            <div v-if="loading" class="modal-loading">
              <div class="loading-spinner"></div>
              <p>{{ loadingText }}</p>
            </div>
            <slot v-else />
          </div>

          <!-- 模态框底部 -->
          <div class="modal-footer" v-if="hasFooter">
            <slot name="footer">
              <button v-if="showCancel" class="btn btn-secondary" @click="handleCancel" :disabled="loading">
                {{ cancelText }}
              </button>
              <button v-if="showConfirm" class="btn btn-primary" @click="handleConfirm"
                :disabled="loading || confirmDisabled">
                {{ confirmText }}
              </button>
            </slot>
          </div>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>

<script setup lang="ts">
import { computed, watch, nextTick } from 'vue'

interface Props {
  visible: boolean
  title?: string
  width?: string | number
  maxWidth?: string | number
  height?: string | number
  closable?: boolean
  maskClosable?: boolean
  hideHeader?: boolean
  loading?: boolean
  loadingText?: string
  showCancel?: boolean
  showConfirm?: boolean
  cancelText?: string
  confirmText?: string
  confirmDisabled?: boolean
  size?: 'small' | 'medium' | 'large' | 'xlarge'
  centered?: boolean
}

const props = withDefaults(defineProps<Props>(), {
  title: '',
  width: 'auto',
  maxWidth: '90vw',
  height: 'auto',
  closable: true,
  maskClosable: true,
  hideHeader: false,
  loading: false,
  loadingText: '加载中...',
  showCancel: false,
  showConfirm: false,
  cancelText: '取消',
  confirmText: '确认',
  confirmDisabled: false,
  size: 'medium',
  centered: true
})

const emit = defineEmits<{
  'update:visible': [value: boolean]
  'close': []
  'cancel': []
  'confirm': []
  'opened': []
  'closed': []
}>()

// 计算属性
const hasFooter = computed(() => {
  return props.showCancel || props.showConfirm || !!document.querySelector('.modal-footer slot')
})

const modalClass = computed(() => [
  `modal-${props.size}`,
  {
    'modal-centered': props.centered,
    'modal-loading': props.loading
  }
])

// 事件处理
const handleClose = () => {
  emit('update:visible', false)
  emit('close')
}

const handleCancel = () => {
  emit('cancel')
}

const handleConfirm = () => {
  emit('confirm')
}

const handleOverlayClick = () => {
  if (props.maskClosable && !props.loading) {
    handleClose()
  }
}

// 监听可见性变化
watch(() => props.visible, async (newVisible) => {
  if (newVisible) {
    await nextTick()
    emit('opened')

    // 防止页面滚动
    document.body.style.overflow = 'hidden'
  } else {
    emit('closed')

    // 恢复页面滚动
    document.body.style.overflow = 'auto'
  }
})

// 键盘事件
const handleKeydown = (event: KeyboardEvent) => {
  if (event.key === 'Escape' && props.closable && !props.loading) {
    handleClose()
  }
}

// 添加键盘监听
watch(() => props.visible, (newVisible) => {
  if (newVisible) {
    document.addEventListener('keydown', handleKeydown)
  } else {
    document.removeEventListener('keydown', handleKeydown)
  }
})
</script>

<style scoped>
.modal-overlay {
  position: fixed;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  background: rgba(0, 0, 0, 0.5);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 2000;
  padding: 20px;
  box-sizing: border-box;
}

.modal-container {
  background: white;
  border-radius: 12px;
  box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
  display: flex;
  flex-direction: column;
  max-height: 90vh;
  overflow: hidden;
  position: relative;
}

/* 尺寸变化 */
.modal-small {
  width: 400px;
  max-width: 90vw;
}

.modal-medium {
  width: 600px;
  max-width: 90vw;
}

.modal-large {
  width: 800px;
  max-width: 95vw;
}

.modal-xlarge {
  width: 1200px;
  max-width: 95vw;
}

.modal-centered {
  margin: auto;
}

/* 头部样式 */
.modal-header {
  padding: 24px 24px 16px;
  border-bottom: 1px solid #e0e0e0;
  display: flex;
  justify-content: space-between;
  align-items: center;
  flex-shrink: 0;
}

.modal-title {
  margin: 0;
  font-size: 18px;
  font-weight: 600;
  color: #2c3e50;
}

.modal-close {
  background: none;
  border: none;
  font-size: 20px;
  cursor: pointer;
  padding: 8px;
  border-radius: 50%;
  width: 36px;
  height: 36px;
  display: flex;
  align-items: center;
  justify-content: center;
  transition: all 0.2s;
  color: #6c757d;
}

.modal-close:hover {
  background: #f8f9fa;
  color: #2c3e50;
}

.modal-close:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

/* 内容样式 */
.modal-body {
  padding: 24px;
  flex: 1;
  overflow-y: auto;
  position: relative;
}

.modal-body.has-footer {
  padding-bottom: 16px;
}

/* 加载状态 */
.modal-loading .modal-body {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  min-height: 200px;
  color: #6c757d;
}

.loading-spinner {
  width: 40px;
  height: 40px;
  border: 3px solid #f3f3f3;
  border-top: 3px solid #007bff;
  border-radius: 50%;
  animation: spin 1s linear infinite;
  margin-bottom: 16px;
}

/* 底部样式 */
.modal-footer {
  padding: 16px 24px 24px;
  border-top: 1px solid #e0e0e0;
  display: flex;
  justify-content: flex-end;
  gap: 12px;
  flex-shrink: 0;
}

/* 动画效果 */
.modal-enter-active,
.modal-leave-active {
  transition: all 0.3s ease;
}

.modal-enter-from,
.modal-leave-to {
  opacity: 0;
}

.modal-enter-from .modal-container {
  transform: scale(0.9) translateY(-20px);
}

.modal-leave-to .modal-container {
  transform: scale(0.9) translateY(20px);
}

/* 响应式设计 */
@media (max-width: 768px) {
  .modal-overlay {
    padding: 10px;
  }

  .modal-small,
  .modal-medium,
  .modal-large,
  .modal-xlarge {
    width: 100%;
    max-width: 100vw;
    margin: 0;
  }

  .modal-header {
    padding: 20px 20px 12px;
  }

  .modal-body {
    padding: 20px;
  }

  .modal-footer {
    padding: 12px 20px 20px;
    flex-direction: column;
  }

  .modal-footer .btn {
    width: 100%;
  }
}

@keyframes spin {
  0% {
    transform: rotate(0deg);
  }

  100% {
    transform: rotate(360deg);
  }
}
</style>
