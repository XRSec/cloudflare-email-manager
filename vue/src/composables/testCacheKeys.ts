/**
 * 缓存键测试工具
 * 用于验证不同路由和参数组合的缓存键生成
 */

import { ROUTE_CONFIGS } from './routeApiManager'

// 模拟用户信息
const mockUser = { id: 123, user_type: 1 } // 管理员用户

// 测试缓存键生成
export function testCacheKeyGeneration() {
  console.log('🧪 开始测试缓存键生成...')

  // 测试邮件页面的缓存键
  const emailRoutes = ['all-emails']

  emailRoutes.forEach(routeName => {
    const config = ROUTE_CONFIGS[routeName]
    if (config && config.apis.length > 0) {
      const apiConfig = config.apis[0]
      console.log(`\n📧 测试路由: ${routeName}`)
      console.log('配置:', {
        routeName: config.routeName,
        keyPrefix: apiConfig.cacheKeyPrefix,
        defaultParams: apiConfig.defaultParams
      })

      // 测试不同的参数组合
      // 注意：单用户模式下，scope 参数已移除
      const testParams = [
        {}, // 无额外参数
        { page: 2 }, // 分页参数
        { search: 'test' }, // 搜索参数
      ]

      testParams.forEach(params => {
        const finalParams = { ...apiConfig.defaultParams, ...params }
        const paramString = Object.entries(finalParams)
          .filter(([_, value]) => value !== undefined && value !== null)
          .sort(([a], [b]) => a.localeCompare(b))
          .map(([key, value]) => `${key}_${value}`)
          .join('_')

        const cacheKey = `${apiConfig.cacheKeyPrefix}_${mockUser.id}_${config.routeName}_${paramString}`

        console.log(`  参数:`, params)
        console.log(`  最终参数:`, finalParams)
        console.log(`  缓存键: ${cacheKey}`)
      })
    }
  })

  // 测试潜在冲突
  console.log('\n⚠️ 测试潜在缓存冲突:')

  // 模拟不同路由的缓存键
  const allEmailsConfig = ROUTE_CONFIGS['all-emails']

  if (allEmailsConfig && allEmailsConfig.apis.length > 0) {
    const apiConfig = allEmailsConfig.apis[0]
    const paramString = Object.entries(apiConfig.defaultParams || {})
      .filter(([_, value]) => value !== undefined && value !== null)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([key, value]) => `${key}_${value}`)
      .join('_')
    const cacheKey = `${apiConfig.cacheKeyPrefix}_${mockUser.id}_${allEmailsConfig.routeName}_${paramString}`

    console.log('全部邮件页面:')
    console.log(`  缓存键: ${cacheKey}`)
  }

  console.log('\n✅ 缓存键生成测试完成')
}

// 在开发模式下自动运行测试
if (import.meta.env.DEV) {
  console.log('🔧 开发模式：运行缓存键测试')
  testCacheKeyGeneration()
}
