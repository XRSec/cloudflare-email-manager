/**
 * 全局加载状态管理
 */

import { createGlobalState } from '@vueuse/core'
import { ref } from 'vue'

export const useLoadingStore = createGlobalState('loading', () => {
  // 全局加载状态
  const globalLoading = ref(false)
  const globalLoadingText = ref('加载中...')

  // 页面级加载状态
  const pageLoading = ref(false)
  const pageLoadingText = ref('页面加载中...')

  // 局部加载状态 (按 key 管理)
  const localLoadings = ref<Record<string, boolean>>({})
  const localLoadingTexts = ref<Record<string, string>>({})

  // 全局加载控制
  const setGlobalLoading = (loading: boolean, text = '加载中...') => {
    globalLoading.value = loading
    globalLoadingText.value = text
  }

  // 页面加载控制
  const setPageLoading = (loading: boolean, text = '页面加载中...') => {
    pageLoading.value = loading
    pageLoadingText.value = text
  }

  // 局部加载控制
  const setLocalLoading = (key: string, loading: boolean, text = '加载中...') => {
    localLoadings.value[key] = loading
    if (loading) {
      localLoadingTexts.value[key] = text
    } else {
      delete localLoadingTexts.value[key]
    }
  }

  // 获取局部加载状态
  const getLocalLoading = (key: string) => {
    return localLoadings.value[key] || false
  }

  // 获取局部加载文本
  const getLocalLoadingText = (key: string) => {
    return localLoadingTexts.value[key] || '加载中...'
  }

  // 清除所有加载状态
  const clearAllLoading = () => {
    globalLoading.value = false
    pageLoading.value = false
    localLoadings.value = {}
    localLoadingTexts.value = {}
  }

  return {
    // 状态
    globalLoading,
    globalLoadingText,
    pageLoading,
    pageLoadingText,
    localLoadings,
    localLoadingTexts,

    // 方法
    setGlobalLoading,
    setPageLoading,
    setLocalLoading,
    getLocalLoading,
    getLocalLoadingText,
    clearAllLoading
  }
})
