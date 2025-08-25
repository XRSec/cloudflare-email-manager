// 钉钉与飞书 Webhook 帮助函数（中文注释）

export async function sendFeishu(webhook: string, title: string, text: string) {
  const body = {
    msg_type: 'post',
    content: {
      post: {
        zh_cn: {
          title,
          content: [[{ tag: 'text', text }]]
        }
      }
    }
  };
  const resp = await fetch(webhook, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  return resp.ok;
}

export async function sendDingTalk(webhook: string, title: string, text: string) {
  const body = {
    msgtype: 'markdown',
    markdown: { title, text }
  };
  const resp = await fetch(webhook, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  return resp.ok;
}

export async function sendGeneric(webhook: string, payload: any) {
  const resp = await fetch(webhook, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(payload) });
  return resp.ok;
}

