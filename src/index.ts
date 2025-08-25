import { Hono } from 'hono';
import { Bindings } from './bindings';
import { bearerAuth } from 'hono/bearer-auth';
import { send } from './email';
import { activation } from './template';
import PostalMime from 'postal-mime';
import { sendFeishu, sendDingTalk, sendGeneric } from './webhooks';
import { ADMIN_HTML } from './admin_html';

const app = new Hono<{ Bindings: Bindings }>().basePath('/v1');

// 仅保护 /v1/admin/* 与发送接口，避免影响 Email 事件
app.use(
	['/admin/*', '/send', '/send/*'],
	bearerAuth({
		verifyToken: async (token, c) => {
			return token === c.env.ACCESS_TOKEN;
		},
	})
);

app.post('/send', async (c) => {
	const body = await c.req.json();
	const resp = await send(c.env, body.to, body.title, body.content, body.type);
	return resp;
});

app.post('/send/activation', async (c) => {
	const body = await c.req.json();
	const resp = await send(
		c.env,
		body.to,
		body.title,
		activation(body.site_name, `${body.name}`, `${body.url}`)
	);
	return resp;
});

export default {
	fetch: app.fetch,
	// Email Worker 入口：当 Cloudflare Email Routing 将邮件投递到该 Worker 时触发
	async email(message: EmailMessage, env: Bindings, ctx: ExecutionContext) {
		// 中文注释：解析 MIME 邮件内容
		const raw = await message.raw();
		const parser = new PostalMime();
		const parsed = await parser.parse(raw);

		const emailId = crypto.randomUUID();
		const createdAt = Date.now();
		const hasAttachments = Array.isArray(parsed.attachments) && parsed.attachments.length > 0 ? 1 : 0;

		// 存储正文
		await env.DB.prepare(
			`INSERT INTO emails(id, message_id, from_addr, to_addr, subject, text, html, has_attachments, created_at)
			 VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)`
		).bind(
			emailId,
			parsed.messageId ?? null,
			parsed.from?.address ?? message.from,
			message.to,
			parsed.subject ?? null,
			parsed.text ?? null,
			parsed.html ?? null,
			hasAttachments,
			createdAt
		).run();

		// 存储附件到 R2（不超过 50MB）
		if (hasAttachments) {
			for (const att of parsed.attachments ?? []) {
				const data = att.content as ArrayBuffer;
				const size = data.byteLength;
				if (size > 50 * 1024 * 1024) continue; // 超过 50MB 跳过存储
				const key = `emails/${emailId}/${crypto.randomUUID()}-${att.filename ?? 'attachment'}`;
				await env.R2.put(key, data, {
					httpMetadata: { contentType: att.mimeType ?? 'application/octet-stream', contentDisposition: `inline; filename="${att.filename ?? 'att'}"` }
				});
				await env.DB.prepare(
					`INSERT INTO attachments(id, email_id, filename, content_type, size_bytes, r2_key, created_at)
					 VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)`
				).bind(crypto.randomUUID(), emailId, att.filename ?? null, att.mimeType ?? null, size, key, createdAt).run();
			}
		}

		// 查找转发规则
		const { results: rules } = await env.DB.prepare(
			`SELECT * FROM forward_rules WHERE source_addr=?1 AND enabled=1`
		).bind(message.to).all();

		if (rules && rules.length > 0) {
			const rule = rules[0] as any;
			if (rule.target_addr) {
				try {
					// 使用 Resend 进行转发（简单策略：将解析后的 HTML 或 TEXT 重新发送）
					const contentType = parsed.html ? 'text/html' : 'text/plain';
					const bodyContent = parsed.html ?? parsed.text ?? '(no content)';
					await send(env, rule.target_addr, parsed.subject ?? '(no subject)', bodyContent, contentType);
				} catch (err) {
					// 失败回退到 webhook（支持飞书/钉钉/通用）
					if (rule.fallback_webhook) {
						const title = '邮件转发失败';
						const text = `收件地址: ${message.to}\n目标地址: ${rule.target_addr}\n主题: ${parsed.subject ?? ''}\n错误: ${(err as Error)?.message ?? err}`;
						ctx.waitUntil((async () => {
							if (rule.fallback_platform === 'feishu') {
								await sendFeishu(rule.fallback_webhook, title, text);
							} else if (rule.fallback_platform === 'dingtalk') {
								await sendDingTalk(rule.fallback_webhook, title, text);
							} else {
								await sendGeneric(rule.fallback_webhook, { event: 'forward_failed', to: rule.target_addr, from: parsed.from?.address ?? message.from, subject: parsed.subject, email_id: emailId, error: (err as Error)?.message ?? String(err) });
							}
						})());
					}
				}
			}
		}
	},
};

// 规则与邮件管理接口（受 Bearer 保护）

// 简单静态页面：管理后台
app.get('/admin', async (c) => {
    return new Response(ADMIN_HTML, { headers: { 'content-type': 'text/html; charset=utf-8' } });
});

app.post('/admin/rules', async (c) => {
	const { id, source_addr, target_addr, fallback_webhook, fallback_platform, enabled } = await c.req.json();
	const ruleId = id ?? crypto.randomUUID();
	const now = Date.now();
	await c.env.DB.prepare(
		`INSERT INTO forward_rules(id, source_addr, target_addr, fallback_webhook, fallback_platform, enabled, created_at)
		 VALUES(?1, ?2, ?3, ?4, ?5, COALESCE(?6,1), ?7)
		 ON CONFLICT(id) DO UPDATE SET source_addr=excluded.source_addr, target_addr=excluded.target_addr, fallback_webhook=excluded.fallback_webhook, fallback_platform=excluded.fallback_platform, enabled=excluded.enabled`
	).bind(ruleId, source_addr, target_addr, fallback_webhook, fallback_platform, enabled, now).run();
	return c.json({ ok: true, id: ruleId });
});

app.get('/admin/rules', async (c) => {
	const { results } = await c.env.DB.prepare(`SELECT * FROM forward_rules ORDER BY created_at DESC`).all();
	return c.json({ ok: true, data: results });
});

app.delete('/admin/rules/:id', async (c) => {
	const id = c.req.param('id');
	await c.env.DB.prepare(`DELETE FROM forward_rules WHERE id=?1`).bind(id).run();
	return c.json({ ok: true });
});

app.get('/admin/emails', async (c) => {
	const url = new URL(c.req.url);
	const q = url.searchParams;
	const to = q.get('to') ?? undefined;
	const after = q.get('after') ? Number(q.get('after')) : undefined;
	const before = q.get('before') ? Number(q.get('before')) : undefined;
	const minSize = q.get('minSize') ? Number(q.get('minSize')) : undefined;
	const maxSize = q.get('maxSize') ? Number(q.get('maxSize')) : undefined;

	let sql = `SELECT e.*, COALESCE(SUM(a.size_bytes),0) AS total_size
		 FROM emails e LEFT JOIN attachments a ON a.email_id=e.id`;
	const cond: string[] = [];
	const binds: any[] = [];
	if (to) { cond.push('e.to_addr = ?'); binds.push(to); }
	if (after) { cond.push('e.created_at >= ?'); binds.push(after); }
	if (before) { cond.push('e.created_at <= ?'); binds.push(before); }

	if (minSize || maxSize) {
		// 使用 HAVING 过滤汇总大小
		sql += cond.length ? ` WHERE ${cond.join(' AND ')}` : '';
		sql += ' GROUP BY e.id HAVING 1=1';
		if (minSize) { sql += ' AND COALESCE(SUM(a.size_bytes),0) >= ?'; binds.push(minSize); }
		if (maxSize) { sql += ' AND COALESCE(SUM(a.size_bytes),0) <= ?'; binds.push(maxSize); }
	} else {
		sql += cond.length ? ` WHERE ${cond.join(' AND ')}` : '';
		sql += ' GROUP BY e.id';
	}

	sql += ' ORDER BY e.created_at DESC LIMIT 200';
	const stmt = c.env.DB.prepare(sql);
	const { results } = await stmt.bind(...binds).all();
	return c.json({ ok: true, data: results });
});

app.delete('/admin/emails/:id', async (c) => {
	const id = c.req.param('id');
	const { results: atts } = await c.env.DB.prepare(`SELECT r2_key FROM attachments WHERE email_id=?1`).bind(id).all();
	for (const row of atts) {
		if (row.r2_key) await c.env.R2.delete(row.r2_key as string);
	}
	await c.env.DB.batch([
		c.env.DB.prepare(`DELETE FROM attachments WHERE email_id=?1`).bind(id),
		c.env.DB.prepare(`DELETE FROM emails WHERE id=?1`).bind(id)
	]);
	return c.json({ ok: true });
});