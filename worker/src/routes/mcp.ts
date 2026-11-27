import { Hono, type MiddlewareHandler } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { MCP_SERVER_INFO, MCP_TOOLS } from '../../../shared/mcp.ts';
import type { Env } from '../types';

export type ApiInvoker = (
  path: string,
  init?: RequestInit
) => Promise<{ status: number; json: any }>;

interface JsonRpcRequest {
  jsonrpc?: unknown;
  id?: string | number | null;
  method?: unknown;
  params?: Record<string, any>;
}

function jsonRpcError(id: string | number | null, code: number, message: string, httpStatus = 200) {
  return {
    status: httpStatus,
    body: {
      jsonrpc: '2.0',
      id,
      error: { code, message }
    }
  };
}

function requireStringArg(args: Record<string, any>, key: string): string {
  const val = args[key];
  if (typeof val !== 'string' || !val.trim()) {
    throw new Error(`Missing or invalid required argument: ${key}`);
  }
  return val.trim();
}

async function executeMcpTool(
  name: string,
  args: Record<string, any>,
  invokeApi: ApiInvoker
): Promise<unknown> {
  switch (name) {
    case 'list_emails': {
      const query = new URLSearchParams();
      for (const key of ['folder', 'status', 'recipient', 'sender', 'search', 'limit', 'page']) {
        if (args[key] !== undefined && args[key] !== null && args[key] !== '') {
          query.set(key, String(args[key]));
        }
      }
      const qs = query.toString();
      const res = await invokeApi(`/api/emails${qs ? `?${qs}` : ''}`);
      if (res.status >= 400 || !res.json?.success) {
        throw new Error(res.json?.message || res.json?.error || `HTTP ${res.status}`);
      }
      return res.json.data;
    }

    case 'get_latest_verification': {
      const query = new URLSearchParams({ folder: 'inbox', limit: '1', page: '1' });
      for (const key of ['recipient', 'sender', 'search']) {
        if (typeof args[key] === 'string' && args[key].trim()) {
          query.set(key, args[key].trim());
        }
      }
      const res = await invokeApi(`/api/emails?${query.toString()}`);
      if (res.status >= 400 || !res.json?.success) {
        throw new Error(res.json?.message || res.json?.error || `HTTP ${res.status}`);
      }
      const item = res.json.data?.items?.[0];
      if (!item) {
        return { found: false, email: null, verification: null };
      }
      return {
        found: Boolean(item.verification),
        email: {
          id: item.id,
          subject: item.subject,
          from: item.from,
          to: item.to,
          received_at: item.received_at,
          status: item.status
        },
        verification: item.verification || null
      };
    }

    case 'read_email': {
      const id = requireStringArg(args, 'id');
      const res = await invokeApi(`/api/emails/${encodeURIComponent(id)}`);
      if (res.status >= 400 || !res.json?.success) {
        throw new Error(res.json?.message || res.json?.error || `HTTP ${res.status}`);
      }
      return res.json.data;
    }

    case 'send_email': {
      const payload = {
        to: requireStringArg(args, 'to'),
        from: requireStringArg(args, 'from'),
        subject: requireStringArg(args, 'subject'),
        content: requireStringArg(args, 'content'),
        content_type: args.content_type === 'html' ? 'html' : 'text',
        delivery_method: requireStringArg(args, 'delivery_method')
      };
      const res = await invokeApi('/api/emails/send', {
        method: 'POST',
        body: JSON.stringify(payload)
      });
      if (res.status >= 400 || !res.json?.success) {
        throw new Error(res.json?.message || res.json?.error || `HTTP ${res.status}`);
      }
      return res.json.data ?? res.json;
    }

    case 'forward_email': {
      const id = requireStringArg(args, 'id');
      const mode = requireStringArg(args, 'mode');
      const payload = mode === 'webhook'
        ? { mode: 'webhook', channelId: Number(args.channelId) }
        : {
            mode: 'recipient',
            targetEmail: requireStringArg(args, 'targetEmail'),
            targetForwardType: args.targetForwardType,
            from: args.from
          };
      const res = await invokeApi(`/api/emails/${encodeURIComponent(id)}/forward`, {
        method: 'POST',
        body: JSON.stringify(payload)
      });
      if (res.status >= 400 || !res.json?.success) {
        throw new Error(res.json?.message || res.json?.error || `HTTP ${res.status}`);
      }
      return res.json.data ?? res.json;
    }

    case 'mark_email_read': {
      const id = requireStringArg(args, 'id');
      if (typeof args.is_read !== 'boolean') {
        throw new Error('Missing or invalid required argument: is_read');
      }
      const res = await invokeApi(`/api/emails/${encodeURIComponent(id)}/read-status`, {
        method: 'PATCH',
        body: JSON.stringify({ is_read: args.is_read })
      });
      if (res.status >= 400 || !res.json?.success) {
        throw new Error(res.json?.message || res.json?.error || `HTTP ${res.status}`);
      }
      return res.json;
    }

    case 'delete_email': {
      const id = requireStringArg(args, 'id');
      const res = await invokeApi(`/api/emails/${encodeURIComponent(id)}`, {
        method: 'DELETE'
      });
      if (res.status >= 400 || !res.json?.success) {
        throw new Error(res.json?.message || res.json?.error || `HTTP ${res.status}`);
      }
      return res.json;
    }

    default:
      throw new Error(`Unknown tool: ${name}`);
  }
}

export async function handleMcpJsonRpc(
  rawBody: unknown,
  invokeApi: ApiInvoker
): Promise<{ status: number; body: Record<string, unknown> | null }> {
  if (!rawBody || typeof rawBody !== 'object' || Array.isArray(rawBody)) {
    return jsonRpcError(null, -32600, 'Invalid Request', 400);
  }

  const req = rawBody as JsonRpcRequest;
  const id = req.id ?? null;
  if (req.jsonrpc !== '2.0' || typeof req.method !== 'string') {
    return jsonRpcError(id, -32600, 'Invalid Request', 400);
  }

  // Notifications have no id
  if (req.id === undefined || req.method.startsWith('notifications/')) {
    return { status: 202, body: null };
  }

  switch (req.method) {
    case 'initialize':
      return {
        status: 200,
        body: {
          jsonrpc: '2.0',
          id,
          result: {
            protocolVersion: MCP_SERVER_INFO.protocolVersion,
            capabilities: { tools: {} },
            serverInfo: {
              name: MCP_SERVER_INFO.name,
              version: MCP_SERVER_INFO.version
            }
          }
        }
      };

    case 'ping':
      return {
        status: 200,
        body: { jsonrpc: '2.0', id, result: {} }
      };

    case 'tools/list':
      return {
        status: 200,
        body: {
          jsonrpc: '2.0',
          id,
          result: { tools: MCP_TOOLS }
        }
      };

    case 'tools/call': {
      const toolName = req.params?.name;
      if (typeof toolName !== 'string' || !MCP_TOOLS.some(t => t.name === toolName)) {
        return jsonRpcError(id, -32602, `Invalid params: unknown tool '${String(toolName || '')}'`);
      }
      const toolArgs = (req.params?.arguments && typeof req.params.arguments === 'object')
        ? req.params.arguments
        : {};

      try {
        const data = await executeMcpTool(toolName, toolArgs, invokeApi);
        return {
          status: 200,
          body: {
            jsonrpc: '2.0',
            id,
            result: {
              content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
              structuredContent: data,
              isError: false
            }
          }
        };
      } catch (err) {
        const message = err instanceof HTTPException
          ? err.message
          : err instanceof Error
            ? err.message
            : String(err);
        return {
          status: 200,
          body: {
            jsonrpc: '2.0',
            id,
            result: {
              content: [{ type: 'text', text: message }],
              isError: true
            }
          }
        };
      }
    }

    default:
      return jsonRpcError(id, -32601, `Method not found: ${req.method}`);
  }
}

export function createMcpRouter(
  appFetcher: (req: Request, env: Env, ctx?: any) => Promise<Response> | Response,
  authMiddleware: MiddlewareHandler<{ Bindings: Env }>
) {
  const mcp = new Hono<{ Bindings: Env }>();

  mcp.get('/.well-known/mcp.json', (c) => {
    const origin = new URL(c.req.url).origin;
    return c.json({
      name: MCP_SERVER_INFO.name,
      version: MCP_SERVER_INFO.version,
      protocolVersion: MCP_SERVER_INFO.protocolVersion,
      transport: 'streamable-http',
      endpoint: `${origin}/mcp`,
      authentication: {
        type: 'bearer',
        header: 'Authorization',
        format: 'Bearer <api_token>'
      },
      tools: MCP_TOOLS
    });
  });

  mcp.post('/mcp', authMiddleware, async (c) => {
    let rawBody: unknown;
    try {
      rawBody = await c.req.json();
    } catch {
      const errRes = jsonRpcError(null, -32700, 'Parse error', 400);
      return c.json(errRes.body, 400);
    }

    const authHeader = c.req.header('Authorization') || '';
    const invokeApi: ApiInvoker = async (path, init = {}) => {
      const headers = new Headers(init.headers);
      if (authHeader) headers.set('Authorization', authHeader);
      if (init.body && !headers.has('Content-Type')) {
        headers.set('Content-Type', 'application/json');
      }
      const internalReq = new Request(`http://internal${path}`, {
        ...init,
        headers
      });
      const res = await appFetcher(internalReq, c.env, c.executionCtx);
      const json = await res.json().catch(() => null);
      return { status: res.status, json };
    };

    const result = await handleMcpJsonRpc(rawBody, invokeApi);
    if (result.body === null) {
      return c.body(null, 202);
    }
    return c.json(result.body, result.status as 200 | 400);
  });

  return mcp;
}
