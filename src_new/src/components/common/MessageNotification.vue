<template>
  <Transition name="message" appear>
    <div
      v-if="visible"
      :class="['message', `message-${type}`]"
      @click="hide"
    >
      {{ message }}
    </div>
  </Transition>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted } from 'vue'
import type { MessageType } from '@/types'

// Props
interface Props {
  message: string
  type?: MessageType
  duration?: number
}

const props = withDefaults(defineProps<Props>(), {
  type: 'info' as MessageType,
  duration: 3000
})

// Emits
const emit = defineEmits<{
  close: []
}>()

// State
const visible = ref(false)
let timer: NodeJS.Timeout | null = null

// Methods
const show = () => {
  visible.value = true
  if (props.duration > 0) {
    timer = setTimeout(hide, props.duration)
  }
}

const hide = () => {
  visible.value = false
  emit('close')
}

// Lifecycle
onMounted(() => {
  show()
})

onUnmounted(() => {
  if (timer) {
    clearTimeout(timer)
  }
})
</script>

<style scoped>
.message-enter-active,
.message-leave-active {
  transition: all 0.3s ease;
}

.message-enter-from {
  opacity: 0;
  transform: translateX(100%);
}

.message-leave-to {
  opacity: 0;
  transform: translateX(100%);
}

.message {
  cursor: pointer;
}

.message:hover {
  transform: translateY(-2px);
  box-shadow: 0 8px 25px rgba(0, 0, 0, 0.15);
}
</style>