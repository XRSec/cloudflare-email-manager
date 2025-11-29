<template>
  <div class="not-found-view">
    <div class="error-container">
      <div class="error-content">
        <!-- 404 数字动画 -->
        <div class="error-number">
          <span class="digit">4</span>
          <span class="digit">0</span>
          <span class="digit">4</span>
        </div>

        <!-- 错误图标 -->
        <div class="error-icon">
          <div class="icon-container">
            <svg viewBox="0 0 100 100" class="error-svg">
              <circle cx="50" cy="50" r="45" fill="none" stroke="#409eff" stroke-width="2" opacity="0.3" />
              <path d="M30 30 L70 70 M70 30 L30 70" stroke="#409eff" stroke-width="3" stroke-linecap="round" />
            </svg>
          </div>
        </div>

        <!-- 建议链接 -->
        <div class="suggestions">
          <p class="suggestions-title">您可能想要：</p>
          <div class="suggestion-links">
            <a href="/" class="suggestion-link">查看仪表板</a>
            <a href="/my-emails" class="suggestion-link">我的邮件</a>
            <a href="/my-mailboxes" class="suggestion-link">我的邮箱</a>
          </div>
        </div>

        <!-- 调试信息 -->
        <div class="error-debug" v-if="!isDebugMode">
          <details>
            <summary>🔧 调试信息</summary>
            <pre>{{ debugInfo }}</pre>
          </details>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { useSystemStore } from '@/composables/system'
import { House, ArrowLeft } from '@element-plus/icons-vue'

const router = useRouter()
const route = useRoute()
const systemStore = useSystemStore()

const isDebugMode = computed(() => systemStore.isDebugMode)

const debugInfo = computed(() => ({
  path: route.path,
  fullPath: route.fullPath,
  name: route.name,
  params: route.params,
  query: route.query,
  matched: route.matched.map(m => m.path),
  timestamp: new Date().toISOString()
}))

const goHome = () => {
  router.push('/')
}

const goBack = () => {
  if (window.history.length > 1) {
    router.go(-1)
  } else {
    router.push('/')
  }
}
</script>

<style scoped>
.not-found-view {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 20px;
  min-width: 350px;
  position: relative;
  overflow: hidden;
}

/* 背景装饰 */
.background-decoration {
  position: absolute;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  pointer-events: none;
  z-index: 1;
}

.shape {
  position: absolute;
  border-radius: 50%;
  background: rgba(255, 255, 255, 0.1);
  animation: float 6s ease-in-out infinite;
}

.shape-1 {
  width: 80px;
  height: 80px;
  top: 20%;
  left: 10%;
  animation-delay: 0s;
}

.shape-2 {
  width: 120px;
  height: 120px;
  top: 60%;
  right: 15%;
  animation-delay: 2s;
}

.shape-3 {
  width: 60px;
  height: 60px;
  top: 80%;
  left: 20%;
  animation-delay: 4s;
}

.shape-4 {
  width: 100px;
  height: 100px;
  top: 10%;
  right: 30%;
  animation-delay: 1s;
}

.shape-5 {
  width: 40px;
  height: 40px;
  top: 40%;
  left: 5%;
  animation-delay: 3s;
}

@keyframes float {

  0%,
  100% {
    transform: translateY(0px) rotate(0deg);
    opacity: 0.7;
  }

  50% {
    transform: translateY(-20px) rotate(180deg);
    opacity: 1;
  }
}

.error-container {
  text-align: center;
  position: relative;
  z-index: 2;
}

.error-content {
  background: rgba(255, 255, 255, 0.95);
  backdrop-filter: blur(20px);
  border-radius: 24px;
  padding: 40px;
  box-shadow: 0 0 40px rgba(0, 0, 0, 0.1);
  border: 1px solid rgba(255, 255, 255, 0.2);
  animation: slideUp 0.8s ease-out;
}

@keyframes slideUp {
  from {
    opacity: 0;
    transform: translateY(50px);
  }

  to {
    opacity: 1;
    transform: translateY(0);
  }
}

/* 404 数字动画 */
.error-number {
  display: flex;
  justify-content: center;
  align-items: center;
  gap: 10px;
}

.digit {
  font-size: 120px;
  font-weight: 900;
  color: #409eff;
  text-shadow: 0 0 20px rgba(64, 158, 255, 0.3);
  animation: bounce 2s ease-in-out infinite;
  display: inline-block;
}

.digit:nth-child(1) {
  animation-delay: 0s;
}

.digit:nth-child(2) {
  animation-delay: 0.2s;
}

.digit:nth-child(3) {
  animation-delay: 0.4s;
}

@keyframes bounce {

  0%,
  20%,
  50%,
  80%,
  100% {
    transform: translateY(0);
  }

  40% {
    transform: translateY(-10px);
  }

  60% {
    transform: translateY(-5px);
  }
}

/* 错误图标 */
.error-icon {
  /* margin-bottom: 30px; */
}

.icon-container {
  display: inline-block;
  animation: pulse 2s ease-in-out infinite;
}

.error-svg {
  width: 80px;
  height: 80px;
  animation: rotate 3s linear infinite;
}

@keyframes pulse {

  0%,
  100% {
    transform: scale(1);
  }

  50% {
    transform: scale(1.1);
  }
}

@keyframes rotate {
  from {
    transform: rotate(0deg);
  }

  to {
    transform: rotate(360deg);
  }
}

/* 建议链接 */
.suggestions {
  margin-top: 20px;
  padding-top: 20px;
  border-top: 1px solid rgba(0, 0, 0, 0.1);
}

.suggestions-title {
  font-size: 16px;
  color: #7f8c8d;
  margin: 0 0 20px 0;
  font-weight: 500;
}

.suggestion-links {
  display: flex;
  gap: 20px;
  justify-content: center;
  flex-wrap: wrap;
}

.suggestion-link {
  color: #409eff;
  text-decoration: none;
  padding: 8px 16px;
  border-radius: 20px;
  background: rgba(64, 158, 255, 0.1);
  transition: all 0.3s ease;
  font-weight: 500;
}

.suggestion-link:hover {
  background: #409eff;
  color: white;
  transform: translateY(-2px);
  box-shadow: 0 4px 12px rgba(64, 158, 255, 0.3);
}

/* 调试信息 */
.error-debug {
  margin-top: 40px;
  text-align: left;
}

.error-debug details {
  background: rgba(245, 247, 250, 0.8);
  border: 1px solid rgba(228, 231, 237, 0.5);
  border-radius: 12px;
  padding: 20px;
  backdrop-filter: blur(10px);
}

.error-debug summary {
  cursor: pointer;
  font-weight: 600;
  color: #409eff;
  margin-bottom: 15px;
  font-size: 16px;
}

.error-debug pre {
  background: #2c3e50;
  color: #ecf0f1;
  padding: 20px;
  border-radius: 8px;
  font-size: 13px;
  overflow-x: auto;
  margin: 0;
  line-height: 1.5;
}

/* 响应式设计 */
@media (max-width: 768px) {}

@media (max-width: 480px) {
  .not-found-view {
    padding: 0;
  }

  .error-content {
    padding: 30px;
    padding-top: 0;
    box-shadow: 0 0 20px rgba(0, 0, 0, 0.1);
  }

  .suggestions {
    margin-top: 10px;
    padding-top: 10px;
  }

  .suggestions-title {
    font-size: 14px;
    margin: 0 0 10px 0;
  }

  .suggestion-link {
    padding: 6px 12px;
    font-size: 12px;
  }
}
</style>
