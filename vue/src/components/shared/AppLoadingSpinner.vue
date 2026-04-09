<template>
  <div class="app-loading-spinner">
    <div class="spinner">
      <div class="spinner-ring"></div>
      <div class="spinner-ring"></div>
      <div class="spinner-ring"></div>
    </div>
    <div v-if="text" class="loading-text">{{ text }}</div>
  </div>
</template>

<script setup lang="ts">
interface Props {
  text?: string
}

defineProps<Props>()
</script>

<style scoped>
.app-loading-spinner {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 12px;
  height: 100vh;
}

.spinner {
  position: relative;
  width: 66px;
  height: 66px;
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
  font-size: 16px;
  font-weight: 500;
  color: #2c3e50;
  text-align: center;
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
