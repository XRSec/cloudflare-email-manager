// 通用工具：时间、加密、响应等

export const nowEpochMs = (): number => Date.now();

// 简单 JSON 解析辅助（避免异常抛出）
export async function readJsonSafe<T = unknown>(request: Request): Promise<T | null> {
	try {
		return (await request.json()) as T;
	} catch (_err) {
		return null;
	}
}

// 计算 SHA-256（返回 hex）
export async function sha256Hex(input: string | ArrayBuffer): Promise<string> {
	const data = typeof input === 'string' ? new TextEncoder().encode(input) : new Uint8Array(input as ArrayBuffer);
	const digest = (await crypto.subtle.digest('SHA-256', data)) as ArrayBuffer;
	const bytes = new Uint8Array(digest);
	let out = '';
	for (const b of bytes) out += b.toString(16).padStart(2, '0');
	return out;
}

// 简易口令散列：SHA-256(prefix + ':' + password)
// 生产中推荐 PBKDF2/ARGON2，这里为简化示例
export async function hashPassword(emailPrefix: string, password: string): Promise<string> {
	return sha256Hex(`${emailPrefix}:${password}`);
}

// HMAC-SHA256 签名（用于 webhook）返回 hex
export async function hmacSha256Hex(secret: string, payload: string): Promise<string> {
	const key = await crypto.subtle.importKey(
		'raw',
		new TextEncoder().encode(secret),
		{ name: 'HMAC', hash: 'SHA-256' },
		false,
		['sign']
	);
	const sig = (await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payload))) as ArrayBuffer;
	const bytes = new Uint8Array(sig);
	let out = '';
	for (const b of bytes) out += b.toString(16).padStart(2, '0');
	return out;
}

export function parseQuery(request: Request): URLSearchParams {
	return new URL(request.url).searchParams;
}