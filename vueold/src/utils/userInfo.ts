/**
 * 用户信息查询工具
 */

import { api } from '../api'

// 用户名缓存
const usernameCache = new Map<number, { username: string; user_type: string; timestamp: number }>()
const CACHE_DURATION = 5 * 60 * 1000 // 5分钟缓存

/**
 * 根据用户ID获取用户名
 */
export async function getUsername(userId: number): Promise<string | null> {
  try {
    // 检查缓存
    const cached = usernameCache.get(userId)
    if (cached && Date.now() - cached.timestamp < CACHE_DURATION) {
      return cached.username
    }

    // 从API获取
    const response = await api.get(`/user-info/username/${userId}`)
    if (response.data.success) {
      const userInfo = response.data.data
      // 更新缓存
      usernameCache.set(userId, {
        username: userInfo.username,
        user_type: userInfo.user_type,
        timestamp: Date.now()
      })
      return userInfo.username
    }
    return null
  } catch (error) {
    console.error('获取用户名失败:', error)
    return null
  }
}

/**
 * 批量获取用户名
 */
export async function getUsernames(userIds: number[]): Promise<Map<number, string>> {
  try {
    const result = new Map<number, string>()
    const uncachedIds: number[] = []

    // 检查缓存
    for (const userId of userIds) {
      const cached = usernameCache.get(userId)
      if (cached && Date.now() - cached.timestamp < CACHE_DURATION) {
        result.set(userId, cached.username)
      } else {
        uncachedIds.push(userId)
      }
    }

    // 批量获取未缓存的用户名
    if (uncachedIds.length > 0) {
      const response = await api.post('/user-info/usernames', {
        user_ids: uncachedIds
      })

      if (response.data.success) {
        const userMap = response.data.data
        for (const [userIdStr, userInfo] of Object.entries(userMap)) {
          const userId = parseInt(userIdStr)
          const info = userInfo as { username: string; user_type: string }
          result.set(userId, info.username)
          // 更新缓存
          usernameCache.set(userId, {
            username: info.username,
            user_type: info.user_type,
            timestamp: Date.now()
          })
        }
      }
    }

    return result
  } catch (error) {
    console.error('批量获取用户名失败:', error)
    return new Map()
  }
}

/**
 * 清除用户名缓存
 */
export function clearUsernameCache(): void {
  usernameCache.clear()
}

/**
 * 清除特定用户的缓存
 */
export function clearUserCache(userId: number): void {
  usernameCache.delete(userId)
}
