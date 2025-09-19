/**
 * 缓存管理 API 路由
 */

import { Hono } from 'hono'
import { KVCacheService, CacheStrategyService } from '../services/kvCache'
import { adminAuthMiddleware } from '../middleware/auth'
import type { Env } from '../types'

const cache = new Hono<{ Bindings: Env }>()

// 缓存服务实例
let kvCache: KVCacheService
let cacheStrategy: CacheStrategyService

// 初始化缓存服务
cache.use('*', async (c, next) => {
  if (!kvCache) {
    kvCache = new KVCacheService(c.env.KV)
    cacheStrategy = new CacheStrategyService(kvCache, c.env.DB)
  }
  await next()
})

/**
 * 获取缓存状态
 * GET /api/cache/status
 */
cache.get('/status', async (c) => {
  try {
    const kvInfo = kvCache.getCacheInfo()

    return c.json({
      success: true,
      data: {
        kv_status: {
          total_keys: kvInfo.totalKeys,
          hit_rate: kvInfo.hitRate,
          hits: kvInfo.hits,
          misses: kvInfo.misses,
          errors: kvInfo.errors
        },
        last_update: kvInfo.lastUpdate
      }
    })
  } catch (error) {
    return c.json({
      success: false,
      error: '获取缓存状态失败'
    }, 500)
  }
})

/**
 * 清理缓存
 * POST /api/cache/clear
 */
cache.post('/clear', adminAuthMiddleware, async (c) => {
  try {
    const body = await c.req.json()
    const { type, user_id } = body

    let clearedKeys: string[] = []
    let success = false

    switch (type) {
      case 'all':
        success = await kvCache.clearAll()
        clearedKeys = ['all']
        break

      case 'system':
        success = await kvCache.clearSystemCache()
        clearedKeys = [
          KVCacheService.KEYS.SYSTEM_CONFIG,
          KVCacheService.KEYS.REGISTRATION_STATUS,
          KVCacheService.KEYS.DEBUG_MODE
        ]
        break

      case 'user':
        if (!user_id) {
          return c.json({
            success: false,
            error: '清理用户缓存需要提供 user_id'
          }, 400)
        }
        success = await kvCache.clearUserCache(user_id)
        clearedKeys = [
          `user:${user_id}`,
          `user:${user_id}:settings`,
          `user:${user_id}:emails`,
          `user:${user_id}:mailboxes`
        ]
        break

      case 'config':
        success = await kvCache.clearSystemCache()
        clearedKeys = [
          KVCacheService.KEYS.SYSTEM_CONFIG,
          KVCacheService.KEYS.REGISTRATION_STATUS
        ]
        break

      default:
        return c.json({
          success: false,
          error: '无效的清理类型'
        }, 400)
    }

    if (success) {
      return c.json({
        success: true,
        message: `成功清理 ${type} 缓存`,
        cleared_keys: clearedKeys
      })
    } else {
      return c.json({
        success: false,
        error: '清理缓存失败'
      }, 500)
    }
  } catch (error) {
    return c.json({
      success: false,
      error: '清理缓存失败'
    }, 500)
  }
})

/**
 * 缓存预热
 * POST /api/cache/warmup
 */
cache.post('/warmup', adminAuthMiddleware, async (c) => {
  try {
    const body = await c.req.json()
    const { types = ['system_config'] } = body

    let warmedItems = 0

    for (const type of types) {
      switch (type) {
        case 'system_config':
          await cacheStrategy.getSystemConfig()
          warmedItems++
          break

        case 'user_data':
          // 预热所有用户数据（这里简化处理）
          const { getAllUsers } = await import('../services/user')
          const users = await getAllUsers(c.env.DB)
          for (const user of users.users) {
            await kvCache.setUserInfo(user.id, user)
          }
          warmedItems += users.users.length
          break

        case 'email_list':
          // 预热邮件列表（这里简化处理）
          await kvCache.set(KVCacheService.KEYS.EMAIL_LIST, [], 1800)
          warmedItems++
          break

        default:
          console.warn(`未知的预热类型: ${type}`)
      }
    }

    return c.json({
      success: true,
      message: '缓存预热完成',
      warmed_items: warmedItems
    })
  } catch (error) {
    return c.json({
      success: false,
      error: '缓存预热失败'
    }, 500)
  }
})

/**
 * 获取特定缓存项
 * GET /api/cache/get/:key
 */
cache.get('/get/:key', adminAuthMiddleware, async (c) => {
  try {
    const key = c.req.param('key')
    const data = await kvCache.get(key)

    return c.json({
      success: true,
      data: {
        key,
        data,
        exists: data !== null
      }
    })
  } catch (error) {
    return c.json({
      success: false,
      error: '获取缓存项失败'
    }, 500)
  }
})

/**
 * 设置特定缓存项
 * POST /api/cache/set
 */
cache.post('/set', adminAuthMiddleware, async (c) => {
  try {
    const body = await c.req.json()
    const { key, data, ttl } = body

    if (!key || data === undefined) {
      return c.json({
        success: false,
        error: '缺少必要参数 key 或 data'
      }, 400)
    }

    const success = await kvCache.set(key, data, ttl)

    if (success) {
      return c.json({
        success: true,
        message: '缓存设置成功'
      })
    } else {
      return c.json({
        success: false,
        error: '缓存设置失败'
      }, 500)
    }
  } catch (error) {
    return c.json({
      success: false,
      error: '缓存设置失败'
    }, 500)
  }
})

/**
 * 删除特定缓存项
 * DELETE /api/cache/delete/:key
 */
cache.delete('/delete/:key', adminAuthMiddleware, async (c) => {
  try {
    const key = c.req.param('key')
    const success = await kvCache.delete(key)

    if (success) {
      return c.json({
        success: true,
        message: '缓存删除成功'
      })
    } else {
      return c.json({
        success: false,
        error: '缓存删除失败'
      }, 500)
    }
  } catch (error) {
    return c.json({
      success: false,
      error: '缓存删除失败'
    }, 500)
  }
})

/**
 * 获取缓存统计信息
 * GET /api/cache/stats
 */
cache.get('/stats', adminAuthMiddleware, async (c) => {
  try {
    const info = kvCache.getCacheInfo()

    return c.json({
      success: true,
      data: {
        metrics: info,
        performance: {
          hit_rate: info.hitRate,
          miss_rate: 1 - info.hitRate,
          error_rate: info.errors / (info.hits + info.misses + info.errors) || 0
        },
        recommendations: generateRecommendations(info)
      }
    })
  } catch (error) {
    return c.json({
      success: false,
      error: '获取缓存统计失败'
    }, 500)
  }
})

/**
 * 生成缓存优化建议
 */
function generateRecommendations(info: any): string[] {
  const recommendations: string[] = []

  if (info.hitRate < 0.7) {
    recommendations.push('缓存命中率较低，建议增加缓存时间或优化缓存策略')
  }

  if (info.errors > 0) {
    recommendations.push('存在缓存错误，建议检查 KV 配置和网络连接')
  }

  if (info.hits + info.misses < 100) {
    recommendations.push('缓存使用量较少，建议增加缓存预热')
  }

  return recommendations
}

export { cache }
