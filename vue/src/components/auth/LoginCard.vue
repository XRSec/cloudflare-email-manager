<template>
  <div class="login-page">
    <div id="loginSection" class="card">
      <div class="header">
        <h1>CEM 邮箱管理系统</h1>
        <p>现代化的邮件管理解决方案</p>
      </div>

      <div class="status-banner" :class="{ open: allowRegistration, closed: !allowRegistration }">
        <span>
          {{ allowRegistration ? '注册配置为开放（前端禁用，未来可能启用）' : '注册已关闭，仅管理员可登录' }}
        </span>
      </div>

      <div class="tab-content active">
        <div v-if="errorMessage" class="alert alert-error">
          {{ errorMessage }}
        </div>

        <form @submit.prevent="$emit('submit')">
          <div class="form-group">
            <label class="form-label">用户名</label>
            <input
                :value="username"
                type="text"
                class="form-control"
                placeholder="请输入用户名"
                required
                @input="$emit('update:username', ($event.target as HTMLInputElement).value)"
            >
          </div>
          <div class="form-group">
            <label class="form-label">密码</label>
            <input
                :value="password"
                type="password"
                class="form-control"
                placeholder="请输入密码"
                required
                @input="$emit('update:password', ($event.target as HTMLInputElement).value)"
            >
          </div>
          <button type="submit" class="btn btn-primary" :disabled="loading">
            {{ loading ? '登录中...' : '登录' }}
          </button>
        </form>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
defineProps<{
  username: string
  password: string
  loading: boolean
  errorMessage: string
  allowRegistration: boolean
}>()

defineEmits<{
  submit: []
  'update:username': [value: string]
  'update:password': [value: string]
}>()
</script>

<style scoped>
.login-page {
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 24px;
  min-height: 100vh;
  min-height: 100svh;
  min-height: 100dvh;
  z-index: 1000;
}

.card {
  width: min(100%, 430px);
  padding: 32px;
  background: rgba(255, 255, 255, 0.94);
  border: 1px solid rgba(15, 23, 42, 0.08);
  border-radius: 24px;
  box-shadow: 0 28px 60px -34px rgba(15, 23, 42, 0.45);
  backdrop-filter: blur(16px);
  overflow: hidden;
  position: relative;
  display: flex;
  flex-direction: column;
  max-height: min(760px, calc(100dvh - 48px));
}

.card::before {
  content: '';
  position: absolute;
  inset: 0 auto auto 0;
  width: 100%;
  height: 6px;
  background: linear-gradient(90deg, #2b67f6 0%, #5aa9ff 45%, #f5a043 100%);
}

.header {
  text-align: center;
  margin-bottom: 28px;
}

.header h1 {
  margin-bottom: 10px;
  color: #163047;
  font-size: clamp(26px, 4vw, 30px);
  line-height: 1.08;
  letter-spacing: -0.03em;
}

.header p {
  color: #5d6b7b;
  font-size: 14px;
  line-height: 1.6;
}

.status-banner {
  display: flex;
  justify-content: center;
  align-items: center;
  padding: 10px 14px;
  border-radius: 999px;
  font-size: 13px;
  margin-bottom: 22px;
  font-weight: 500;
}

.status-banner.open {
  background: #e8f5e9;
  color: #2e7d32;
  border: 1px solid #a5d6a7;
}

.status-banner.closed {
  background: #fff3e0;
  color: #ef6c00;
  border: 1px solid #ffcc80;
}

.form-group {
  margin-bottom: 18px;
}

.form-label {
  display: block;
  margin-bottom: 8px;
  font-weight: 500;
  color: #28435a;
  font-size: 14px;
}

.form-control {
  width: 100%;
  padding: 13px 15px;
  border: 1px solid rgba(52, 84, 117, 0.18);
  border-radius: 14px;
  font-size: 14px;
  transition: border-color 0.25s ease, box-shadow 0.25s ease, transform 0.25s ease;
  box-sizing: border-box;
  background: rgba(247, 250, 252, 0.88);
}

.form-control:focus {
  outline: none;
  border-color: #2b67f6;
  box-shadow: 0 0 0 4px rgba(43, 103, 246, 0.12);
  transform: translateY(-1px);
}

.form-control:invalid:not(:placeholder-shown) {
  border-color: #e74c3c;
}

.form-control:valid:not(:placeholder-shown) {
  border-color: #27ae60;
}

.btn {
  width: 100%;
  padding: 13px 24px;
  border: none;
  border-radius: 14px;
  font-size: 16px;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.3s ease;
  display: inline-block;
  text-decoration: none;
  text-align: center;
}

.btn-primary {
  background: linear-gradient(135deg, #2058df 0%, #468cff 100%);
  color: white;
}

.btn-primary:hover:not(:disabled) {
  background: linear-gradient(135deg, #184cc6 0%, #377df7 100%);
  transform: translateY(-2px);
  box-shadow: 0 18px 30px -18px rgba(32, 88, 223, 0.8);
}

.btn:disabled {
  opacity: 0.6;
  cursor: not-allowed;
  transform: none;
}

.alert {
  padding: 12px 16px;
  margin-bottom: 20px;
  border-radius: 14px;
  font-size: 14px;
  font-weight: 500;
}

.alert-error {
  background: rgba(255, 238, 238, 0.92);
  color: #c33;
  border: 1px solid rgba(204, 51, 51, 0.18);
}

@media (max-width: 640px) {
  .login-page {
    padding:
        max(16px, env(safe-area-inset-top))
        14px
        max(16px, env(safe-area-inset-bottom));
    min-height: 95dvh;
  }

  .card {
    width: 92vw;
    min-width: 0;
    min-height: auto;
    max-height: none;
    padding: 24px 18px 20px;
    border-radius: 22px;
    margin: 10px auto 20px;
    overflow: visible;
  }

  .header {
    margin-bottom: 22px;
  }

  .header h1 {
    font-size: 24px;
  }

  .header p {
    font-size: 13px;
  }

  .status-banner {
    align-items: flex-start;
    text-align: left;
    border-radius: 16px;
  }

  .btn {
    font-size: 15px;
  }
}
</style>
