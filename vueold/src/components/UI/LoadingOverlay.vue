<template>
  <div v-if="show" class="loading-overlay" :class="overlayClass">
    <div class="loading-content" :class="contentClass">
      <div class="loading-spinner" :class="spinnerClass">
        <div class="spinner"></div>
      </div>
      <div v-if="text" class="loading-text" :class="textClass">
        {{ text }}
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'

interface Props {
  show: boolean
  text?: string
  type?: 'global' | 'page' | 'local' | 'inline'
  size?: 'small' | 'medium' | 'large'
  overlay?: boolean
  center?: boolean
}

const props = withDefaults(defineProps<Props>(), {
  text: '加载中...',
  type: 'local',
  size: 'medium',
  overlay: true,
  center: true
})

const overlayClass = computed(() => {
  const classes = ['loading-overlay']
  
  if (props.type === 'global') {
    classes.push('loading-overlay--global')
  } else if (props.type === 'page') {
    classes.push('loading-overlay--page')
  } else if (props.type === 'local') {
    classes.push('loading-overlay--local')
  } else if (props.type === 'inline') {
    classes.push('loading-overlay--inline')
  }

  if (props.overlay) {
    classes.push('loading-overlay--with-overlay')
  }

  return classes
})

const contentClass = computed(() => {
  const classes = ['loading-content']
  
  if (props.center) {
    classes.push('loading-content--center')
  }

  if (props.size === 'small') {
    classes.push('loading-content--small')
  } else if (props.size === 'large') {
    classes.push('loading-content--large')
  }

  return classes
})

const spinnerClass = computed(() => {
  const classes = ['loading-spinner']
  
  if (props.size === 'small') {
    classes.push('loading-spinner--small')
  } else if (props.size === 'large') {
    classes.push('loading-spinner--large')
  }

  return classes
})

const textClass = computed(() => {
  const classes = ['loading-text']
  
  if (props.size === 'small') {
    classes.push('loading-text--small')
  } else if (props.size === 'large') {
    classes.push('loading-text--large')
  }

  return classes
})
</script>

<style scoped>
.loading-overlay {
  position: relative;
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: 60px;
}

.loading-overlay--global {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  z-index: 9999;
  background: rgba(255, 255, 255, 0.9);
  backdrop-filter: blur(2px);
}

.loading-overlay--page {
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  z-index: 100;
  background: rgba(255, 255, 255, 0.8);
}

.loading-overlay--local {
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  z-index: 10;
  background: rgba(255, 255, 255, 0.7);
}

.loading-overlay--inline {
  position: static;
  background: transparent;
  min-height: 40px;
}

.loading-overlay--with-overlay {
  background: rgba(255, 255, 255, 0.8);
}

.loading-content {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 12px;
}

.loading-content--center {
  justify-content: center;
}

.loading-content--small {
  gap: 8px;
}

.loading-content--large {
  gap: 16px;
}

.loading-spinner {
  position: relative;
}

.loading-spinner--small .spinner {
  width: 20px;
  height: 20px;
}

.loading-spinner--small .spinner-ring {
  border-width: 2px;
}

.loading-spinner--large .spinner {
  width: 40px;
  height: 40px;
}

.loading-spinner--large .spinner-ring {
  border-width: 4px;
}

.spinner {
  position: relative;
  width: 30px;
  height: 30px;
}

.spinner-ring {
  position: absolute;
  width: 100%;
  height: 100%;
  border: 3px solid transparent;
  border-top: 3px solid #3498db;
  border-radius: 50%;
  animation: spin 1.2s cubic-bezier(0.5, 0, 0.5, 1) infinite;
}

.spinner-ring:nth-child(1) {
  animation-delay: -0.45s;
}

.spinner-ring:nth-child(2) {
  animation-delay: -0.3s;
  border-top-color: #2ecc71;
}

.spinner-ring:nth-child(3) {
  animation-delay: -0.15s;
  border-top-color: #e74c3c;
}

.loading-text {
  color: #666;
  font-size: 14px;
  font-weight: 500;
  text-align: center;
}

.loading-text--small {
  font-size: 12px;
}

.loading-text--large {
  font-size: 16px;
}

@keyframes spin {
  0% { transform: rotate(0deg); }
  100% { transform: rotate(360deg); }
}

/* 暗色主题支持 */
@media (prefers-color-scheme: dark) {
  .loading-overlay--global,
  .loading-overlay--page,
  .loading-overlay--local {
    background: rgba(0, 0, 0, 0.8);
  }
  
  .loading-text {
    color: #ccc;
  }
  
  .spinner-ring {
    border-color: transparent;
  }
  
  .spinner-ring:nth-child(1) {
    border-top-color: #3498db;
  }
  
  .spinner-ring:nth-child(2) {
    border-top-color: #2ecc71;
  }
  
  .spinner-ring:nth-child(3) {
    border-top-color: #e74c3c;
  }
}
</style>
