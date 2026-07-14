/**
 * JWT Secret 管理工具
 * 用于生成、验证和管理 JWT 密钥
 */

/**
 * 生成安全的随机 JWT Secret
 * 在 Cloudflare Workers 环境中使用 Web Crypto API
 */
export function generateJWTSecret(): string {
    // 在 Cloudflare Workers 中使用 crypto.getRandomValues
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);

    // 转换为 base64 字符串
    return btoa(String.fromCharCode.apply(null, Array.from(array)));
}

/**
 * 验证 JWT Secret 是否有效
 * @param secret JWT 密钥
 * @returns 是否有效
 */
export function isValidJWTSecret(secret: string | null | undefined): boolean {
    if (!secret) return false;

    // 检查是否是默认的不安全密钥
    const insecureSecrets = [
        'your-jwt-secret-change-this-in-production',
        'your-jwt-secret',
        'change-this',
        'secret',
        'default',
        ''
    ];

    if (insecureSecrets.includes(secret)) {
        console.warn('⚠️ 检测到不安全的 JWT Secret！');
        return false;
    }

    // 检查密钥长度（至少 32 个字符）
    if (secret.length < 32) {
        console.warn('⚠️ JWT Secret 长度不足（建议至少 32 个字符）');
        return false;
    }

    return true;
}

/**
 * 获取或生成 JWT Secret
 * 优先级：环境变量 > 数据库 > 自动生成
 */
export async function getOrGenerateJWTSecret(
    env: any,
    db: D1Database | null = null
): Promise<string> {
    // 1. 首先尝试从环境变量获取
    if (env.JWT_SECRET && isValidJWTSecret(env.JWT_SECRET)) {
        return env.JWT_SECRET;
    }

    // 2. 尝试从数据库获取
    if (db) {
        try {
            const result = await db.prepare(
                'SELECT value FROM system_settings WHERE key = ?'
            ).bind('jwt_secret').first();

            if (result && isValidJWTSecret(result.value as string)) {
                return result.value as string;
            }
        } catch (error) {
            console.error('从数据库获取 JWT Secret 失败:', error);
        }
    }

    // 3. 生成新的 JWT Secret
    const newSecret = generateJWTSecret();

    // 4. 尝试保存到数据库
    if (db) {
        try {
            await db.prepare(`
                INSERT OR REPLACE INTO system_settings (key, value, description, updated_at)
                VALUES ('jwt_secret', ?, 'JWT签名密钥（自动生成）', CURRENT_TIMESTAMP)
            `).bind(newSecret).run();
        } catch (error) {
            console.error('保存 JWT Secret 到数据库失败:', error);
        }
    }

    return newSecret;
}

/**
 * 轮换 JWT Secret
 * 生成新的密钥并保存，同时保留旧密钥用于验证
 */
export async function rotateJWTSecret(
    db: D1Database,
    keepOldForDays: number = 7
): Promise<{ newSecret: string; oldSecret: string | null }> {
    let oldSecret: string | null = null;

    try {
        // 获取当前的 JWT Secret
        const currentResult = await db.prepare(
            'SELECT value FROM system_settings WHERE key = ?'
        ).bind('jwt_secret').first();

        if (currentResult) {
            oldSecret = currentResult.value as string;

            // 保存旧密钥（带过期时间）
            const expiresAt = new Date();
            expiresAt.setDate(expiresAt.getDate() + keepOldForDays);

            await db.prepare(`
                INSERT OR REPLACE INTO system_settings (key, value, description, updated_at)
                VALUES ('jwt_secret_old', ?, ?, CURRENT_TIMESTAMP)
            `).bind(
                oldSecret,
                `旧的JWT密钥，过期时间：${expiresAt.toISOString()}`
            ).run();
        }
    } catch (error) {
        console.error('保存旧 JWT Secret 失败:', error);
    }

    // 生成新密钥
    const newSecret = generateJWTSecret();

    // 保存新密钥
    await db.prepare(`
        INSERT OR REPLACE INTO system_settings (key, value, description, updated_at)
        VALUES ('jwt_secret', ?, 'JWT签名密钥（轮换于 ' || CURRENT_TIMESTAMP || '）', CURRENT_TIMESTAMP)
    `).bind(newSecret).run();

    return { newSecret, oldSecret };
}

/**
 * 验证 JWT 时支持新旧密钥
 * 用于密钥轮换期间的平滑过渡
 */
export async function getJWTSecretsForVerification(
    env: any,
    db: D1Database | null = null
): Promise<string[]> {
    const secrets: string[] = [];

    // 获取当前密钥
    const currentSecret = await getOrGenerateJWTSecret(env, db);
    secrets.push(currentSecret);

    // 尝试获取旧密钥（如果存在）
    if (db) {
        try {
            const oldResult = await db.prepare(
                'SELECT value FROM system_settings WHERE key = ?'
            ).bind('jwt_secret_old').first();

            if (oldResult && oldResult.value) {
                secrets.push(oldResult.value as string);
            }
        } catch (error) {
            console.error('获取旧 JWT Secret 失败:', error);
        }
    }

    return secrets;
}

/**
 * 清理过期的旧 JWT Secret
 */
export async function cleanupOldJWTSecrets(db: D1Database): Promise<void> {
    try {
        // 检查旧密钥的描述中是否包含过期时间
        const result = await db.prepare(
            'SELECT value, description FROM system_settings WHERE key = ?'
        ).bind('jwt_secret_old').first();

        if (result && result.description) {
            const description = result.description as string;
            const expiryMatch = description.match(/过期时间：(\d{4}-\d{2}-\d{2}T[\d:]+\.?\d*Z?)/);

            if (expiryMatch) {
                const expiryDate = new Date(expiryMatch[1]);
                if (new Date() > expiryDate) {
                    await db.prepare(
                        'DELETE FROM system_settings WHERE key = ?'
                    ).bind('jwt_secret_old').run();
                }
            }
        }
    } catch (error) {
        console.error('清理旧 JWT Secret 失败:', error);
    }
}
