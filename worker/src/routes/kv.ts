/**
 * KV 缓存管理 API 路由（挂载在 /api/tools/kv/* 下）
 */

import { Hono } from 'hono'
import { KVCacheService, CacheStrategyService } from '../services/kvCache'
import { jwtAuthMiddleware } from '../middleware/auth'
import type { Env } from '../types'

const kvRouter = new Hono<{ Bindings: Env }>()

// 缓存服务实例
let kvCache: KVCacheService
let cacheStrategy: CacheStrategyService

// 初始化缓存服务
kvRouter.use('*', async (c, next) => {
  if (!kvCache) {
    kvCache = new KVCacheService(c.env.KV)
    cacheStrategy = new CacheStrategyService(kvCache, c.env.DB)
  }
  await next()
})

// 应用认证中间件
kvRouter.use('*', jwtAuthMiddleware)

/**
 * 获取缓存状态
 * GET /api/tools/kv/status
 */
kvRouter.get('/status', async (c) => {
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
 * POST /api/tools/kv/clear
 */
kvRouter.post('/clear', async (c) => {
  try {
    const body = await c.req.json()
    const { type } = body

    let clearedKeys: string[] = []
    let success = false

    switch (type) {
      case 'all':
        success = await kvCache.clearAll()
        clearedKeys = ['all']
        break

      case 'system':
        // 单管理员模式下，系统相关配置统一走 clearSystemCache
        success = await kvCache.clearSystemCache()
        clearedKeys = [
          KVCacheService.KEYS.SYSTEM_CONFIG
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
 * POST /api/tools/kv/warmup
 */
kvRouter.post('/warmup', async (c) => {
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
 * GET /api/tools/kv/get/:key
 */
kvRouter.get('/get/:key', async (c) => {
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
 * POST /api/tools/kv/set
 */
kvRouter.post('/set', async (c) => {
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
 * DELETE /api/tools/kv/delete/:key
 */
kvRouter.delete('/delete/:key', async (c) => {
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
 * GET /api/tools/kv/stats
 */
kvRouter.get('/stats', async (c) => {
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
 * GET /api/tools/kv/list
 * 
 * 注意：Cloudflare Workers KV 不支持直接列出所有键
 * 这里返回已知的缓存键模式，并尝试获取它们的值
 */
kvRouter.get('/list', async (c) => {
  try {
    const prefix = c.req.query('prefix') || ''
    const limit = parseInt(c.req.query('limit') || '50')

    // 已知的缓存键模式
    const knownKeys = [
      KVCacheService.KEYS.SYSTEM_CONFIG,
      KVCacheService.KEYS.EMAIL_LIST
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

export { kvRouter }

