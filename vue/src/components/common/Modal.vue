<template>
  <div v-if="show" class="modal-overlay" @click="handleOverlayClick">
    <div class="modal-content" :data-size="size" @click.stop>
      <div class="modal-header">
        <h3>{{ title }}</h3>
        <button v-if="showClose" class="modal-close" @click="$emit('close')">×</button>
      </div>
      <div class="modal-body">
        <slot></slot>
      </div>
      <div v-if="$slots.footer" class="modal-footer">
        <slot name="footer"></slot>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
interface Props {
  show: boolean
  title: string
  showClose?: boolean
  closeOnOverlay?: boolean
  size?: 'small' | 'medium' | 'large'
}

const props = withDefaults(defineProps<Props>(), {
  showClose: true,
  closeOnOverlay: true,
  size: 'medium'
})

const emit = defineEmits<{
  close: []
}>()

const handleOverlayClick = () => {
  if (props.closeOnOverlay) {
    emit('close')
  }
}
</script>

<style scoped>
.modal-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(0, 0, 0, 0.5);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 2000;
}

.modal-content {
  background: white;
  border-radius: 8px;
  width: 90%;
  max-height: 90vh;
  overflow-y: auto;
}

.modal-content[data-size="small"] {
  max-width: 400px;
}

.modal-content[data-size="medium"] {
  max-width: 600px;
}

.modal-content[data-size="large"] {
  max-width: 900px;
}

.modal-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 20px 20px 0 20px;
  border-bottom: 1px solid #e0e0e0;
  margin-bottom: 20px;
}

.modal-header h3 {
  margin: 0;
  color: #333;
}

.modal-close {
  background: none;
  border: none;
  font-size: 24px;
  cursor: pointer;
  color: #666;
  padding: 0;
  width: 30px;
  height: 30px;
  display: flex;
  align-items: center;
  justify-content: center;
}

.modal-close:hover {
  color: #333;
}

.modal-body {
  padding: 0 20px;
}

.modal-footer {
  padding: 20px;
  border-top: 1px solid #e0e0e0;
  margin-top: 20px;
  display: flex;
  gap: 10px;
  justify-content: flex-end;
}
</style>
