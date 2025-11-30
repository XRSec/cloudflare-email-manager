/**
 * 测试路由API映射器
 * 用于验证API服务选择是否正确
 */

import { ROUTE_CONFIGS } from './routeApiManager'
import { emailApiService, adminApiService, userApiService } from './api'

// 测试API服务选择
export function testApiServiceSelection() {
  console.log('🧪 开始测试API服务选择...')

  // 测试邮件相关路由
  const emailRoutes = ['emails', 'admin-emails']
  emailRoutes.forEach(routeName => {
    const config = ROUTE_CONFIGS[routeName]
    if (config && config.apis.length > 0) {
      const apiMethod = config.apis[0].method
      console.log(`📧 路由 ${routeName}:`, {
        apiMethod,
        hasGetEmails: typeof emailApiService.getEmails === 'function',
        hasAdminGetEmails: typeof adminApiService.getEmails === 'function'
      })
    }
  })

  // 测试邮箱相关路由（已移除，使用转发规则替代）
  // const mailboxRoutes = ['mailboxes', 'admin-mailboxes']
  // 邮箱功能已移除，不再测试

  // 测试用户相关路由
  const userRoutes = ['admin-users']
  userRoutes.forEach(routeName => {
    const config = ROUTE_CONFIGS[routeName]
    if (config && config.apis.length > 0) {
      const apiMethod = config.apis[0].method
      console.log(`👤 路由 ${routeName}:`, {
        apiMethod,
        hasGetUsers: typeof adminApiService.getAllUsers === 'function'
      })
    }
  })

  console.log('✅ API服务选择测试完成')
}

// 测试API方法是否存在
export function testApiMethods() {
  console.log('🧪 开始测试API方法...')

  const apiServices = {
    emailApiService,
    adminApiService,
    userApiService
  }

  Object.entries(apiServices).forEach(([serviceName, service]) => {
    console.log(`📋 ${serviceName} 可用方法:`, Object.getOwnPropertyNames(service).filter(name => typeof (service as any)[name] === 'function'))
  })

  console.log('✅ API方法测试完成')
}

// 测试新的API服务映射系统
export function testNewApiServiceMapping() {
  console.log('🧪 开始测试新的API服务映射系统...')

  // 测试每个路由的API服务选择
  Object.entries(ROUTE_CONFIGS).forEach(([routeName, config]) => {
    console.log(`\n📋 测试路由: ${routeName}`)
    const apiMethods = config.apis.map(api => api.method).join(', ')
    console.log('配置:', {
      apiMethods,
      description: config.description,
      adminOnly: config.adminOnly
    })

    // 这里可以添加更详细的测试逻辑
    // 由于 useRouteApiCacheMapper 需要在组件上下文中使用，
    // 这里只是展示配置信息
  })

  console.log('\n✅ 新的API服务映射系统测试完成')
}

// 在开发模式下自动运行测试
if (import.meta.env.DEV) {
  console.log('🔧 开发模式：运行API服务测试')
  testApiMethods()
  testApiServiceSelection()
  testNewApiServiceMapping()
}
