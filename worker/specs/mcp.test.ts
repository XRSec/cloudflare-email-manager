import assert from 'node:assert/strict';
import test from 'node:test';
import { MCP_TOOLS } from '../../shared/mcp.ts';
import { createMcpRouter, handleMcpJsonRpc, type ApiInvoker } from '../src/routes/mcp.ts';

test('MCP_TOOLS exposes expected 7 core email tools', () => {
  const names = MCP_TOOLS.map(t => t.name);
  assert.deepEqual(names, [
    'list_emails',
    'get_latest_verification',
    'read_email',
    'send_email',
    'forward_email',
    'mark_email_read',
    'delete_email'
  ]);
});

test('handleMcpJsonRpc handles initialize, tools/list, notifications, and errors', async () => {
  const noopInvoker: ApiInvoker = async () => ({ status: 200, json: { success: true } });

  const initRes = await handleMcpJsonRpc({ jsonrpc: '2.0', id: 1, method: 'initialize' }, noopInvoker);
  assert.equal(initRes.status, 200);
  assert.equal((initRes.body?.result as any).serverInfo.name, 'cloudflare-email-manager');

  const notifyRes = await handleMcpJsonRpc({ jsonrpc: '2.0', method: 'notifications/initialized' }, noopInvoker);
  assert.equal(notifyRes.status, 202);
  assert.equal(notifyRes.body, null);

  const listRes = await handleMcpJsonRpc({ jsonrpc: '2.0', id: 2, method: 'tools/list' }, noopInvoker);
  assert.equal((listRes.body?.result as any).tools.length, 7);

  const unknownTool = await handleMcpJsonRpc(
    { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'nonexistent', arguments: {} } },
    noopInvoker
  );
  assert.equal((unknownTool.body?.error as any).code, -32602);
});

test('handleMcpJsonRpc routes tools/call to API invoker and returns verification without side effects', async () => {
  const calls: Array<{ path: string; method: string }> = [];
  const invoker: ApiInvoker = async (path, init) => {
    calls.push({ path, method: init?.method || 'GET' });
    return {
      status: 200,
      json: {
        success: true,
        data: {
          total: 1,
          items: [
            {
              id: 'email-123',
              subject: 'Code',
              from: 'noreply@example.com',
              to: 'me@example.com',
              received_at: '2026-11-28T00:00:00Z',
              status: 'unread',
              verification: { code: '889900', links: [], primaryLink: null, preview: 'Your Verification Code: 889900' }
            }
          ]
        }
      }
    };
  };

  const res = await handleMcpJsonRpc(
    {
      jsonrpc: '2.0',
      id: 10,
      method: 'tools/call',
      params: { name: 'get_latest_verification', arguments: { recipient: 'me@example.com' } }
    },
    invoker
  );

  assert.equal(calls.length, 1);
  assert.match(calls[0].path, /^\/api\/emails\?/);
  assert.equal(calls[0].method, 'GET');
  const structured = (res.body?.result as any).structuredContent;
  assert.equal(structured.found, true);
  assert.equal(structured.verification.code, '889900');
});

test('MCP router serves /.well-known/mcp.json and enforces auth on POST /mcp', async () => {
  const router = createMcpRouter(
    async () => new Response(JSON.stringify({ success: true })),
    async (c, next) => {
      if (c.req.header('Authorization') !== 'Bearer test_token') {
        return c.json({ success: false, message: '未提供认证令牌' }, 401);
      }
      await next();
    }
  );

  const discoveryRes = await router.request('https://mail.example.com/.well-known/mcp.json');
  assert.equal(discoveryRes.status, 200);
  const discoveryJson = await discoveryRes.json() as any;
  assert.equal(discoveryJson.endpoint, 'https://mail.example.com/mcp');
  assert.equal(discoveryJson.tools.length, 7);

  const unauthRes = await router.request('https://mail.example.com/mcp', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' })
  });
  assert.equal(unauthRes.status, 401);

  const authRes = await router.request('https://mail.example.com/mcp', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: 'Bearer test_token' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' })
  });
  assert.equal(authRes.status, 200);
  const authJson = await authRes.json() as any;
  assert.equal(authJson.result.tools.length, 7);
});
