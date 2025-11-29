/**
 * 缓存键测试工具
 * 用于验证不同路由和参数组合的缓存键生成
 */

import { ROUTE_API_CACHE_MAP } from './routeApiCacheMapper'

// 模拟用户信息
const mockUser = { id: 123, user_type: 1 } // 管理员用户

// 测试缓存键生成
export function testCacheKeyGeneration() {
  console.log('🧪 开始测试缓存键生成...')

  // 测试邮件页面的缓存键
  const emailRoutes = ['emails', 'admin-emails']

  emailRoutes.forEach(routeName => {
    const config = ROUTE_API_CACHE_MAP[routeName]
    if (config) {
      console.log(`\n📧 测试路由: ${routeName}`)
      console.log('配置:', {
        routeName: config.routeName,
        keyPrefix: config.cacheStrategy.keyPrefix,
        defaultParams: config.apiParams
      })

      // 测试不同的参数组合
      const testParams = [
        {}, // 无额外参数
        { page: 2 }, // 分页参数
        { scope: 'all' }, // scope参数
        { page: 2, scope: 'all' }, // 组合参数
        { search: 'test' }, // 搜索参数
      ]

      testParams.forEach(params => {
        const finalParams = { ...config.apiParams, ...params }
        const paramString = Object.entries(finalParams)
          .filter(([_, value]) => value !== undefined && value !== null)
          .sort(([a], [b]) => a.localeCompare(b))
          .map(([key, value]) => `${key}_${value}`)
          .join('_')

        const cacheKey = `${config.cacheStrategy.keyPrefix}_${mockUser.id}_${config.routeName}_${paramString}`

        console.log(`  参数:`, params)
        console.log(`  最终参数:`, finalParams)
        console.log(`  缓存键: ${cacheKey}`)
      })
    }
  })

  // 测试潜在冲突
  console.log('\n⚠️ 测试潜在缓存冲突:')

  // 模拟用户在emails页面切换showAllEmails的情况
  const emailsConfig = ROUTE_API_CACHE_MAP['emails']
  const adminEmailsConfig = ROUTE_API_CACHE_MAP['admin-emails']

  if (emailsConfig && adminEmailsConfig) {
    // 用户在emails页面，showAllEmails = true
    const userEmailsWithAllScope = { ...emailsConfig.apiParams, scope: 'all' }
    const userEmailsParamString = Object.entries(userEmailsWithAllScope)
      .filter(([_, value]) => value !== undefined && value !== null)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([key, value]) => `${key}_${value}`)
      .join('_')
    const userEmailsCacheKey = `${emailsConfig.cacheStrategy.keyPrefix}_${mockUser.id}_${emailsConfig.routeName}_${userEmailsParamString}`

    // 管理员在admin-emails页面
    const adminEmailsParamString = Object.entries(adminEmailsConfig.apiParams)
      .filter(([_, value]) => value !== undefined && value !== null)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([key, value]) => `${key}_${value}`)
      .join('_')
    const adminEmailsCacheKey = `${adminEmailsConfig.cacheStrategy.keyPrefix}_${mockUser.id}_${adminEmailsConfig.routeName}_${adminEmailsParamString}`

    console.log('用户在emails页面，showAllEmails=true:')
    console.log(`  缓存键: ${userEmailsCacheKey}`)
    console.log('管理员在admin-emails页面:')
    console.log(`  缓存键: ${adminEmailsCacheKey}`)
    console.log(`  是否冲突: ${userEmailsCacheKey === adminEmailsCacheKey ? '❌ 是' : '✅ 否'}`)
  }

  console.log('\n✅ 缓存键生成测试完成')
}

// 在开发模式下自动运行测试
if (import.meta.env.DEV) {
  console.log('🔧 开发模式：运行缓存键测试')
  testCacheKeyGeneration()
}
