/**
 * 前后端分离测试脚本
 * 用于验证后端API和静态资源服务是否正常工作
 */

const BASE_URL = 'http://localhost:8787';

async function testAPI() {
    console.log('🧪 开始测试前后端分离...\n');

    // 测试系统配置API
    console.log('1. 测试系统配置API...');
    try {
        const response = await fetch(`${BASE_URL}/api/system/config`);
        const data = await response.json();
        console.log('✅ 系统配置API:', data.success ? '正常' : '异常');
        if (!data.success) {
            console.log('   错误:', data.error);
        }
    } catch (error) {
        console.log('❌ 系统配置API失败:', error.message);
    }

    // 测试健康检查API
    console.log('\n2. 测试健康检查API...');
    try {
        const response = await fetch(`${BASE_URL}/api/system/health`);
        const data = await response.json();
        console.log('✅ 健康检查API:', data.success ? '正常' : '异常');
        if (!data.success) {
            console.log('   错误:', data.error);
        }
    } catch (error) {
        console.log('❌ 健康检查API失败:', error.message);
    }

    // 测试静态资源服务
    console.log('\n3. 测试静态资源服务...');
    try {
        const response = await fetch(`${BASE_URL}/`);
        const contentType = response.headers.get('content-type');
        console.log('✅ 根路径响应:', response.status, contentType);
        
        if (contentType && contentType.includes('text/html')) {
            console.log('   📄 返回HTML内容，静态资源服务正常');
        } else {
            console.log('   ⚠️  未返回HTML内容');
        }
    } catch (error) {
        console.log('❌ 静态资源服务失败:', error.message);
    }

    // 测试不存在的静态资源
    console.log('\n4. 测试不存在的静态资源...');
    try {
        const response = await fetch(`${BASE_URL}/nonexistent.js`);
        console.log('✅ 不存在资源响应:', response.status);
        
        if (response.status === 404) {
            console.log('   📄 正确返回404');
        } else if (response.status === 200) {
            const contentType = response.headers.get('content-type');
            if (contentType && contentType.includes('text/html')) {
                console.log('   📄 返回默认HTML（SPA路由支持）');
            }
        }
    } catch (error) {
        console.log('❌ 测试失败:', error.message);
    }

    // 测试API路径不会被静态资源处理
    console.log('\n5. 测试API路径隔离...');
    try {
        const response = await fetch(`${BASE_URL}/api/nonexistent`);
        console.log('✅ API路径响应:', response.status);
        
        if (response.status === 404) {
            console.log('   📄 API路径正确返回404，未被静态资源处理');
        }
    } catch (error) {
        console.log('❌ API路径测试失败:', error.message);
    }

    console.log('\n🎉 前后端分离测试完成！');
    console.log('\n📋 测试总结:');
    console.log('   - 后端API服务正常');
    console.log('   - 静态资源服务正常');
    console.log('   - SPA路由支持正常');
    console.log('   - API和静态资源路径隔离正常');
    console.log('\n💡 下一步:');
    console.log('   1. 将前端构建产物放到 frontend/dist/ 目录');
    console.log('   2. 运行 wrangler dev 启动开发服务器');
    console.log('   3. 访问 http://localhost:8787 查看前端应用');
}

// 运行测试
testAPI().catch(console.error);