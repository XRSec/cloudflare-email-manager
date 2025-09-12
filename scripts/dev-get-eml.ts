import type { Env } from '../worker/src/types';

let errors: string[] = [];

export default {
  // 邮件入口
  async email(message: EmailMessage, env: Env) {
    try {
      const id = crypto.randomUUID();
      const headers = Object.fromEntries(message.headers);

      // 存 metadata
      const meta = {
        id,
        from: message.from,
        to: message.to,
        rawSize: message.rawSize,
        headers,
        createdAt: new Date().toISOString(),
      };

      await env.R2.put(
        `email:${id}:meta.json`,
        JSON.stringify(meta),
        { httpMetadata: { contentType: "application/json" } }
      );

      // 转 ArrayBuffer
      const rawBuffer = await new Response(message.raw).arrayBuffer();

      await env.R2.put(
        `email:${id}.eml`,
        rawBuffer,
        { httpMetadata: { contentType: "message/rfc822" } }
      );
      console.log(`📩 邮件已保存: ${id}`);
    } catch (err) {
      logError("邮件处理错误", err);
    }
  },

  // HTTP 接口
  async fetch(req: Request, env: Env) {
    const url = new URL(req.url);

    if (url.pathname === "/emails") return await renderEmailList(env);
    if (url.pathname === "/") return new Response(renderStatusPage(env), { headers: { "Content-Type": "text/html; charset=utf-8" } });

    return new Response("hello world", { status: 200 });
  },
};

// ---- 工具函数 ----
function logError(prefix: string, err: unknown) {
  const msg = `${prefix}: ${err instanceof Error ? err.message : String(err)}`;
  console.error(msg);
  errors.push(`${new Date().toISOString()}: ${msg}`);
  if (errors.length > 100) errors = errors.slice(-100);
}

function jsonResponse(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json" } });
}

function errorResponse(prefix: string, err: unknown) {
  logError(prefix, err);
  return jsonResponse({ success: false, error: `${prefix}: ${err instanceof Error ? err.message : String(err)}`, errors: errors.slice(-10) }, 500);
}

// ---- 渲染邮件列表 ----
async function renderEmailList(env: Env) {
  try {
    const list = await env.R2.list({ prefix: "email:" }); // ✅ 去掉 delimiter
    const metaFiles = list.objects.filter(obj => obj.key.endsWith("meta.json"));

    const rows = await Promise.all(
      metaFiles.map(async obj => {
        const meta = JSON.parse(await (await env.R2.get(obj.key))?.text() || "{}");
        return `
            <tr>
              <td>${meta.id || "-"}</td>
              <td>${meta.from || "-"}</td>
              <td>${meta.to || "-"}</td>
              <td>${(meta.rawSize / 1024).toFixed(1)} KB</td>
              <td>${new Date(meta.createdAt).toLocaleString()}</td>
            </tr>
          `;
      })
    );

    return new Response(`<!DOCTYPE html>
        <html>
        <head>
          <meta charset="utf-8">
          <title>邮件列表</title>
          <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            table { border-collapse: collapse; width: 100%; }
            th, td { border: 1px solid #ddd; padding: 8px; }
            th { background: #f4f4f4; text-align: left; }
            tr:nth-child(even) { background: #f9f9f9; }
          </style>
        </head>
        <body>
          <h1>📬 邮件列表 (${metaFiles.length} 封)</h1>
          <table>
            <thead>
              <tr>
                <th>ID</th>
                <th>From</th>
                <th>To</th>
                <th>大小</th>
                <th>时间</th>
              </tr>
            </thead>
            <tbody>${rows.join("")}</tbody>
          </table>
          <p><a href="/">返回首页</a></p>
        </body>
        </html>`, {
      headers: { "Content-Type": "text/html; charset=utf-8" },
    });
  } catch (err) {
    return errorResponse("获取邮件列表失败", err);
  }
}


// ---- 渲染状态页 ----
function renderStatusPage(env: Env) {
  return `<!DOCTYPE html>
  <html>
  <head>
    <title>邮件系统调试信息</title>
    <meta charset="utf-8">
    <style>
      body { font-family: Arial, sans-serif; margin: 20px; }
      .error { background: #ffe6e6; padding: 10px; margin: 5px 0; border-left: 4px solid #ff0000; }
      .success { background: #e6ffe6; padding: 10px; margin: 5px 0; border-left: 4px solid #00ff00; }
    </style>
  </head>
  <body>
    <h1>邮件系统调试信息</h1>
    <h2>错误日志 (${errors.length} 条)</h2>
    ${errors.length
      ? errors.map(e => `<div class="error">${e}</div>`).join('')
      : '<div class="success">暂无错误</div>'
    }
    <h2>系统状态</h2>
    <div class="success">
      <p>R2存储桶: ${env.R2 ? '已连接' : '未连接'}</p>
      <p>当前时间: ${new Date().toISOString()}</p>
      <p>Worker运行正常</p>
    </div>
    <h2>操作</h2>
    <p><a href="/emails">查看邮件列表</a></p>
  </body>
  </html>`;
}
