import { Router } from 'itty-router';
import { v4 as uuidv4 } from 'uuid';
import mime from 'mime';
import { nowEpochMs, readJsonSafe, hashPassword } from './utils';

// 环境类型定义
export interface Env {
	DB: D1Database;
	R2: R2Bucket;
	ATTACHMENT_MAX_MB: number;
	EMAIL_RETENTION_DAYS: number;
	// 机密：在 Dashboard 中配置
	ADMIN_API_KEY: string; // 管理员 API 密钥
	SIGNING_SECRET: string; // Webhook 统一签名密钥（也可每用户单独）
}

// 简易 JSON 响应辅助
const json = (data: unknown, init: ResponseInit = {}) => new Response(JSON.stringify(data), {
	...init,
	headers: { 'content-type': 'application/json; charset=utf-8', ...(init.headers || {}) },
});

// 全局路由
const router = Router();

// 健康检测
router.get('/api/health', () => json({ ok: true }));

// 初始化数据库（管理员）
router.post('/api/admin/init', async (request, env: Env) => {
	const adminKey = request.headers.get('x-admin-key');
	if (!adminKey || adminKey !== env.ADMIN_API_KEY) return json({ error: 'unauthorized' }, { status: 401 });
	// 执行 schema.sql
	const schema = await (await fetch(new URL('./schema.sql', import.meta.url))).text();
	await env.DB.exec(schema);
	return json({ ok: true });
});

// 创建管理员账号（仅首次）
router.post('/api/admin/bootstrap', async (request, env: Env) => {
	const adminKey = request.headers.get('x-admin-key');
	if (!adminKey || adminKey !== env.ADMIN_API_KEY) return json({ error: 'unauthorized' }, { status: 401 });
	const body = await readJsonSafe<{ email_prefix: string; password: string }>(request);
	if (!body?.email_prefix || !body?.password) return json({ error: 'bad_request' }, { status: 400 });
	const id = uuidv4();
	const password_hash = await hashPassword(body.email_prefix, body.password);
	const now = nowEpochMs();
	await env.DB.prepare(
		`INSERT INTO users(id, email_prefix, password_hash, role, created_at, updated_at)
		 VALUES(?, ?, ?, 'admin', ?, ?)`
	).bind(id, body.email_prefix, password_hash, now, now).run();
	return json({ ok: true, id });
});

// 用户登录（返回简化 token=user.id）
router.post('/api/session', async (request, env: Env) => {
	const body = await readJsonSafe<{ email_prefix: string; password: string }>(request);
	if (!body?.email_prefix || !body?.password) return json({ error: 'bad_request' }, { status: 400 });
	const user = await env.DB.prepare('SELECT id, password_hash, role FROM users WHERE email_prefix = ?')
		.bind(body.email_prefix).first<{ id: string; password_hash: string; role: string }>();
	if (!user) return json({ error: 'not_found' }, { status: 404 });
	const hash = await hashPassword(body.email_prefix, body.password);
	if (hash !== user.password_hash) return json({ error: 'unauthorized' }, { status: 401 });
	return json({ token: user.id, role: user.role });
});

// 邮件列表与过滤（管理员/用户均可，权限在中间件中区分）
router.get('/api/emails', async (request, env: Env) => {
	const params = new URL(request.url).searchParams;
	const token = request.headers.get('authorization')?.replace('Bearer ', '') || '';
	const isAdmin = request.headers.get('x-admin-key') === env.ADMIN_API_KEY;
	const limit = Math.min(Number(params.get('limit') || '50'), 200);
	const offset = Math.max(Number(params.get('offset') || '0'), 0);
	const timeFrom = Number(params.get('from') || '0');
	const timeTo = Number(params.get('to') || `${Date.now()}`);
	const sender = params.get('sender') || '';
	let where = ' WHERE received_at BETWEEN ? AND ? ';
	const binds: unknown[] = [timeFrom, timeTo];
	if (!isAdmin) {
		where += ' AND user_id = ? ';
		binds.push(token);
	}
	if (sender) {
		where += ' AND from_address LIKE ? ';
		binds.push(`%${sender}%`);
	}
	const rows = await env.DB.prepare(`SELECT id, user_id, from_address, to_address, subject, received_at, size_bytes FROM emails ${where} ORDER BY received_at DESC LIMIT ? OFFSET ?`)
		.bind(...binds, limit, offset).all();
	const totalRow = await env.DB.prepare(`SELECT COUNT(1) as c FROM emails ${where}`)
		.bind(...binds).first<{ c: number }>();
	return json({ items: rows.results || [], total: totalRow?.c || 0 });
});

// 邮件详情
router.get('/api/emails/:id', async (request, env: Env) => {
	const { id } = request.params as { id: string };
	const isAdmin = request.headers.get('x-admin-key') === env.ADMIN_API_KEY;
	const token = request.headers.get('authorization')?.replace('Bearer ', '') || '';
	const email = await env.DB.prepare('SELECT * FROM emails WHERE id = ?')
		.bind(id).first<Record<string, unknown> & { user_id: string }>();
	if (!email) return json({ error: 'not_found' }, { status: 404 });
	if (!isAdmin && email.user_id !== token) return json({ error: 'forbidden' }, { status: 403 });
	const atts = await env.DB.prepare('SELECT id, file_name, content_type, size_bytes FROM attachments WHERE email_id = ?')
		.bind(id).all();
	return json({ email, attachments: atts.results || [] });
});

// 删除邮件（含附件）
router.delete('/api/emails/:id', async (request, env: Env) => {
	const { id } = request.params as { id: string };
	const isAdmin = request.headers.get('x-admin-key') === env.ADMIN_API_KEY;
	const token = request.headers.get('authorization')?.replace('Bearer ', '') || '';
	const email = await env.DB.prepare('SELECT user_id FROM emails WHERE id = ?').bind(id).first<{ user_id: string }>();
	if (!email) return json({ error: 'not_found' }, { status: 404 });
	if (!isAdmin && email.user_id !== token) return json({ error: 'forbidden' }, { status: 403 });
	// 删除附件对象
	const attRows = await env.DB.prepare('SELECT id, r2_key FROM attachments WHERE email_id = ?').bind(id).all<{ id: string; r2_key: string }>();
	for (const row of attRows.results || []) {
		await env.R2.delete(row.r2_key);
	}
	await env.DB.prepare('DELETE FROM emails WHERE id = ?').bind(id).run();
	return json({ ok: true });
});

// 附件下载（带鉴权）
router.get('/api/attachments/:id', async (request, env: Env) => {
	const { id } = request.params as { id: string };
	const isAdmin = request.headers.get('x-admin-key') === env.ADMIN_API_KEY;
	const token = request.headers.get('authorization')?.replace('Bearer ', '') || '';
	const att = await env.DB.prepare('SELECT a.r2_key, a.file_name, a.content_type, a.email_id, e.user_id FROM attachments a JOIN emails e ON a.email_id = e.id WHERE a.id = ?')
		.bind(id).first<{ r2_key: string; file_name: string; content_type: string; email_id: string; user_id: string }>();
	if (!att) return json({ error: 'not_found' }, { status: 404 });
	if (!isAdmin && att.user_id !== token) return json({ error: 'forbidden' }, { status: 403 });
	const obj = await env.R2.get(att.r2_key);
	if (!obj) return json({ error: 'gone' }, { status: 410 });
	return new Response(obj.body, { headers: { 'content-type': att.content_type || 'application/octet-stream', 'content-disposition': `inline; filename="${att.file_name || 'file'}"` } });
});

// 管理员：用户与转发规则管理占位
router.get('/api/admin/users', async () => json({ items: [] }));
router.post('/api/admin/users', async () => json({ created: true }));
router.put('/api/admin/users/:id', async () => json({ updated: true }));
router.delete('/api/admin/users/:id', async () => json({ deleted: true }));
router.get('/api/admin/rules', async () => json({ items: [] }));
router.post('/api/admin/rules', async () => json({ created: true }));
router.put('/api/admin/rules/:id', async () => json({ updated: true }));
router.delete('/api/admin/rules/:id', async () => json({ deleted: true }));

// 静态页面服务（从 bundle 内部读取）
async function serveFile(path: string): Promise<Response> {
	const url = new URL(path, import.meta.url);
	const res = await fetch(url);
	if (!res.ok) return new Response('Not found', { status: 404 });
	return new Response(await res.arrayBuffer(), { headers: { 'content-type': path.endsWith('.html') ? 'text/html; charset=utf-8' : 'text/plain; charset=utf-8' } });
}
router.get('/', () => serveFile('../public/user.html'));
router.get('/admin', () => serveFile('../public/admin.html'));
router.get('/user', () => serveFile('../public/user.html'));

// 邮件接收入口 —— Cloudflare Email Routing 触发
export default {
	async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
		return router.handle(request, env, ctx);
	},
	// 计划任务：清理旧数据
	async scheduled(event: ScheduledEvent, env: Env, ctx: ExecutionContext) {
		// 删除超过保留期的邮件及附件
		const cutoff = Date.now() - env.EMAIL_RETENTION_DAYS * 24 * 3600 * 1000;
		const old = await env.DB.prepare('SELECT id FROM emails WHERE received_at < ?').bind(cutoff).all<{ id: string }>();
		for (const row of old.results || []) {
			const attRows = await env.DB.prepare('SELECT r2_key FROM attachments WHERE email_id = ?').bind(row.id).all<{ r2_key: string }>();
			for (const a of attRows.results || []) await env.R2.delete(a.r2_key);
			await env.DB.prepare('DELETE FROM emails WHERE id = ?').bind(row.id).run();
		}
	},
	// 邮件接收处理器
	async email(message: ForwardableEmailMessage, env: Env, ctx: ExecutionContext) {
		// 1) 基础字段
		const to = message.to;
		const from = message.from;
		const subject = message.headers.get('subject') || '';
		const receivedAt = Date.now();
		const rawSize = message.rawSize || 0;
		// 从收件地址提取 email prefix（形如 prefix@domain）
		const emailPrefix = (to || '').split('@')[0] || '';
		const user = await env.DB.prepare('SELECT id FROM users WHERE email_prefix = ?').bind(emailPrefix).first<{ id: string }>();
		if (!user) {
			// 未注册用户，忽略
			return;
		}
		const emailId = uuidv4();
		// 2) 保存原始 EML 到 R2，便于后续重新解析
		const r2KeyRaw = `raw/${emailId}.eml`;
		await env.R2.put(r2KeyRaw, message.raw, { httpMetadata: { contentType: 'message/rfc822', contentDisposition: `attachment; filename="${emailId}.eml"` } });
		// 3) 先写 emails 记录
		await env.DB.prepare(
			`INSERT INTO emails(id, user_id, from_address, to_address, subject, text_body, html_body, message_id, received_at, size_bytes)
			 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
		).bind(emailId, user.id, from, to, subject, null, null, message.headers.get('message-id') || null, receivedAt, rawSize).run();
		// 4) TODO: 解析 MIME 并将附件保存到 R2（大小限制 50MB）
		// 5) TODO: 匹配规则并转发到飞书/钉钉 webhook
	}
};