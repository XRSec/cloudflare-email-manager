/**
 * 加密相关工具函数
 */

/**
 * 生成随机字符串
 */
export function generateRandomString(length: number = 8): string {
    const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
        result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
}

/**
 * 哈希密码
 */
export async function hashPassword(password: string): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    const hash = await crypto.subtle.digest('SHA-256', data);
    return Array.from(new Uint8Array(hash))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

/**
 * 验证密码
 */
export async function verifyPassword(password: string, hashedPassword: string): Promise<boolean> {
    const hash = await hashPassword(password);
    return hash === hashedPassword;
}

/**
 * 生成 JWT Token
 */
export async function generateJWT(payload: any, secret: string, expiryHours: number = 24 * 7): Promise<string> {
    const now = Math.floor(Date.now() / 1000);
    const exp = now + (expiryHours * 60 * 60);

    const jwtPayload = {...payload, iat: now, exp: exp};

    const header = btoa(JSON.stringify({alg: 'HS256', typ: 'JWT'}));
    const payloadStr = btoa(JSON.stringify(jwtPayload));
    const signature = await signJWT(`${header}.${payloadStr}`, secret);
    return `${header}.${payloadStr}.${signature}`;
}

/**
 * JWT 签名
 */
export async function signJWT(data: string, secret: string): Promise<string> {
    const encoder = new TextEncoder();
    const keyData = encoder.encode(secret);
    const dataToSign = encoder.encode(data);

    const key = await crypto.subtle.importKey(
        'raw', keyData, {name: 'HMAC', hash: 'SHA-256'}, false, ['sign']
    );

    const signature = await crypto.subtle.sign('HMAC', key, dataToSign);
    const uint8Array = new Uint8Array(signature);
    return btoa(String.fromCharCode.apply(null, Array.from(uint8Array)))
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

/**
 * 验证 JWT Token
 */
export async function verifyJWT(token: string, secret: string): Promise<any> {
    try {
        const [header, payload, signature] = token.split('.');
        const expectedSignature = await signJWT(`${header}.${payload}`, secret);

        if (signature !== expectedSignature) {
            throw new Error('Invalid signature');
        }

        const decodedPayload = JSON.parse(atob(payload));

        if (decodedPayload.exp < Math.floor(Date.now() / 1000)) {
            throw new Error('Token expired');
        }

        return decodedPayload;
    } catch (error) {
        throw new Error('Invalid token');
    }
}
