/**
 * 管理员安全相关路由
 * 包括 JWT Secret 轮换等安全功能
 */

import { Hono } from 'hono';
import { rotateJWTSecret, cleanupOldJWTSecrets } from '../utils/jwt-secret';
import { refreshSystemSettings } from '../services/settings';
import { debugLog, errorLog } from '../utils/debug';
import type { Env, ApiResponse } from '../types';

const adminSecurityRoutes = new Hono<{ Bindings: Env }>();

/**
 * 轮换 JWT Secret
 * POST /api/admin/security/rotate-jwt
 */
adminSecurityRoutes.post('/rotate-jwt', async (c) => {
    try {
        debugLog('[Admin Security] 开始轮换 JWT Secret...');
        
        const keepOldForDays = parseInt(c.req.query('keep_days') || '7');
        
        // 执行轮换
        const result = await rotateJWTSecret(c.env.DB, keepOldForDays);
        
        // 清除缓存，强制重新加载
        await refreshSystemSettings(c.env.DB);
        
        debugLog('[Admin Security] JWT Secret 轮换成功');
        
        const response: ApiResponse = {
            success: true,
            message: 'JWT Secret 已成功轮换',
            data: {
                message: '新的 JWT Secret 已生成并保存',
                keep_old_for_days: keepOldForDays,
                note: `旧密钥将保留 ${keepOldForDays} 天用于验证现有 token`
            }
        };
        
        return c.json(response);
    } catch (error) {
        errorLog('[Admin Security] JWT Secret 轮换失败:', error);
        
        const response: ApiResponse = {
            success: false,
            error: error instanceof Error ? error.message : 'JWT Secret 轮换失败'
        };
        
        return c.json(response, 500);
    }
});

/**
 * 清理过期的旧 JWT Secret
 * POST /api/admin/security/cleanup-old-secrets
 */
adminSecurityRoutes.post('/cleanup-old-secrets', async (c) => {
    try {
        debugLog('[Admin Security] 清理过期的 JWT Secret...');
        
        await cleanupOldJWTSecrets(c.env.DB);
        
        const response: ApiResponse = {
            success: true,
            message: '过期的 JWT Secret 已清理'
        };
        
        return c.json(response);
    } catch (error) {
        errorLog('[Admin Security] 清理失败:', error);
        
        const response: ApiResponse = {
            success: false,
            error: error instanceof Error ? error.message : '清理失败'
        };
        
        return c.json(response, 500);
    }
});

/**
 * 获取安全状态
 * GET /api/admin/security/status
 */
adminSecurityRoutes.get('/status', async (c) => {
    try {
        // 检查是否有旧的 JWT Secret
        const oldSecretResult = await c.env.DB.prepare(
            'SELECT value, description, updated_at FROM system_settings WHERE key = ?'
        ).bind('jwt_secret_old').first();
        
        // 检查当前 JWT Secret
        const currentSecretResult = await c.env.DB.prepare(
            'SELECT updated_at FROM system_settings WHERE key = ?'
        ).bind('jwt_secret').first();
        
        const status = {
            has_old_secret: !!oldSecretResult,
            old_secret_info: oldSecretResult ? {
                description: oldSecretResult.description,
                updated_at: oldSecretResult.updated_at
            } : null,
            current_secret_updated_at: currentSecretResult?.updated_at || 'unknown',
            recommendation: !oldSecretResult ? 
                '系统安全状态良好' : 
                '存在旧的 JWT Secret，建议在确认所有用户已重新登录后清理'
        };
        
        const response: ApiResponse = {
            success: true,
            data: status
        };
        
        return c.json(response);
    } catch (error) {
        errorLog('[Admin Security] 获取安全状态失败:', error);
        
        const response: ApiResponse = {
            success: false,
            error: error instanceof Error ? error.message : '获取状态失败'
        };
        
        return c.json(response, 500);
    }
});

export { adminSecurityRoutes };