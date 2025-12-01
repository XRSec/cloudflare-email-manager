/**
 * KV 缓存管理 API 路由
 */

import { Hono } from 'hono'
import { KVCacheService, CacheStrategyService } from '../services/kvCache'
import { jwtAuthMiddleware } from '../middleware/auth'
import type { Env } from '../types'

const kvCacheRouter = new Hono<{ Bindings: Env }>()

// 缓存服务实例
let kvCache: KVCacheService
let cacheStrategy: CacheStrategyService

// 初始化缓存服务
kvCacheRouter.use('*', async (c, next) => {
  if (!kvCache) {
    kvCache = new KVCacheService(c.env.KV)
    cacheStrategy = new CacheStrategyService(kvCache, c.env.DB)
  }
  await next()
})

// 应用认证中间件
kvCacheRouter.use('*', jwtAuthMiddleware)

/**
 * 获取缓存状态
 * GET /api/kv-cache/status
 */
kvCacheRouter.get('/status', async (c) => {
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
 * POST /api/kv-cache/clear
 */
kvCacheRouter.post('/clear', async (c) => {
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
 * POST /api/kv-cache/warmup
 */
kvCacheRouter.post('/warmup', async (c) => {
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
          const { debugLog } = await import('../utils/debug');
          debugLog('缓存预热', `未知的预热类型: ${type}`);
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
 * GET /api/kv-cache/get/:key
 */
kvCacheRouter.get('/get/:key', async (c) => {
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
 * POST /api/kv-cache/set
 */
kvCacheRouter.post('/set', async (c) => {
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
 * DELETE /api/kv-cache/delete/:key
 */
kvCacheRouter.delete('/delete/:key', async (c) => {
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
 * GET /api/kv-cache/stats
 */
kvCacheRouter.get('/stats', async (c) => {
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
 * 列出已知的缓存键（尝试获取值）
 * GET /api/kv-cache/list
 * 
 * 注意：Cloudflare Workers KV 不支持直接列出所有键
 * 这里返回已知的缓存键模式，并尝试获取它们的值
 */
kvCacheRouter.get('/list', async (c) => {
  try {
    const prefix = c.req.query('prefix') || ''
    const limit = parseInt(c.req.query('limit') || '50')

    // 已知的缓存键模式
    const knownKeys = [
      KVCacheService.KEYS.SYSTEM_CONFIG,
      KVCacheService.KEYS.REGISTRATION_STATUS,
      KVCacheService.KEYS.DEBUG_MODE,
      KVCacheService.KEYS.USER_INFO,
      KVCacheService.KEYS.USER_SETTINGS,
      KVCacheService.KEYS.EMAIL_LIST,
      KVCacheService.KEYS.MAILBOX_LIST
    ]

    // 如果提供了前缀，过滤键
    const filteredKeys = prefix
      ? knownKeys.filter(key => key.startsWith(prefix))
      : knownKeys

    // 尝试获取每个键的信息
    const cacheItems: Array<{
      key: string
      exists: boolean
      size?: number
      type?: string
      value?: any
      preview?: string
      ttl?: number
    }> = []

    for (const key of filteredKeys.slice(0, limit)) {
      try {
        const value = await kvCache.get(key)
        const exists = value !== null

        if (exists) {
          const serialized = JSON.stringify(value)
          const size = new Blob([serialized]).size

          // 生成值预览
          let preview = ''
          if (value === null || value === undefined) {
            preview = 'null'
          } else if (typeof value === 'object') {
            const keys = Object.keys(value)
            if (Array.isArray(value)) {
              preview = `Array(${value.length})`
            } else {
              preview = `Object(${keys.length} keys)`
            }
          } else if (typeof value === 'string') {
            preview = value.length > 50 ? value.substring(0, 50) + '...' : value
          } else {
            preview = String(value)
          }

          cacheItems.push({
            key,
            exists: true,
            size,
            type: typeof value,
            value,
            preview,
            ttl: undefined // KV 的 TTL 无法直接获取
          })
        } else {
          cacheItems.push({
            key,
            exists: false
          })
        }
      } catch (error) {
        cacheItems.push({
          key,
          exists: false
        })
      }
    }

    return c.json({
      success: true,
      data: {
        items: cacheItems,
        total: cacheItems.length,
        note: '注意：Cloudflare Workers KV 不支持直接列出所有键。这里只显示已知的缓存键模式。'
      }
    })
  } catch (error) {
    return c.json({
      success: false,
      error: '获取缓存列表失败'
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

export { kvCacheRouter }

