import type { EmailVerificationInfo } from '../../shared/verification.ts';
import type { CemConfig } from './config.ts';

export interface ApiEnvelope<T = unknown> {
  success: boolean;
  message?: string;
  data?: T;
  error?: string;
}

export interface EmailListItem {
  id: string;
  subject: string | null;
  from: string;
  to: string;
  content: string | null;
  status: 'read' | 'unread';
  is_read: number;
  attachment_count: number;
  received_at: string;
  verification?: EmailVerificationInfo | null;
}

export interface EmailDetailItem extends EmailListItem {
  full_content?: string;
  full_content_type?: 'text' | 'html';
  attachments?: Array<{
    id: string;
    filename: string;
    content_type: string;
    size_bytes: number;
    url?: string;
  }>;
}

export class CemClient {
  private readonly baseUrl: string;
  private readonly token: string;

  constructor(config: Pick<CemConfig, 'baseUrl' | 'token'>) {
    this.baseUrl = config.baseUrl.replace(/\/+$/, '');
    this.token = config.token;
  }

  private async requestJson<T>(path: string, init: RequestInit = {}): Promise<T> {
    const headers = new Headers(init.headers);
    headers.set('Authorization', `Bearer ${this.token}`);
    if (init.body && !headers.has('Content-Type')) {
      headers.set('Content-Type', 'application/json');
    }

    const res = await fetch(`${this.baseUrl}${path}`, {
      ...init,
      headers
    });

    const text = await res.text();
    let json: ApiEnvelope<T>;
    try {
      json = JSON.parse(text) as ApiEnvelope<T>;
    } catch {
      throw new Error(`HTTP ${res.status} ${res.statusText}: ${text.slice(0, 200)}`);
    }

    if (!res.ok || !json.success) {
      throw new Error(json.message || json.error || `HTTP ${res.status} ${res.statusText}`);
    }

    return json.data as T;
  }

  async requestBytes(path: string): Promise<{ bytes: Uint8Array; contentType: string }> {
    const res = await fetch(`${this.baseUrl}${path}`, {
      headers: {
        Authorization: `Bearer ${this.token}`
      }
    });

    if (!res.ok) {
      const errText = await res.text();
      throw new Error(`HTTP ${res.status} ${res.statusText}: ${errText.slice(0, 200)}`);
    }

    const buffer = await res.arrayBuffer();
    return {
      bytes: new Uint8Array(buffer),
      contentType: res.headers.get('content-type') || 'application/octet-stream'
    };
  }

  health() {
    return this.requestJson<Record<string, unknown>>('/api/system/health');
  }

  listEmails(params: Record<string, string | number | undefined>) {
    const query = new URLSearchParams();
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== '') {
        query.set(k, String(v));
      }
    }
    const qs = query.toString();
    return this.requestJson<{ total: number; items: EmailListItem[] }>(
      `/api/emails${qs ? `?${qs}` : ''}`
    );
  }

  readEmail(id: string) {
    return this.requestJson<EmailDetailItem>(`/api/emails/${encodeURIComponent(id)}`);
  }

  markReadStatus(id: string, isRead: boolean) {
    return this.requestJson<unknown>(`/api/emails/${encodeURIComponent(id)}/read-status`, {
      method: 'PATCH',
      body: JSON.stringify({ is_read: isRead })
    });
  }

  deleteEmail(id: string) {
    return this.requestJson<unknown>(`/api/emails/${encodeURIComponent(id)}`, {
      method: 'DELETE'
    });
  }

  sendEmail(payload: {
    to: string;
    from?: string;
    subject: string;
    content: string;
    content_type: 'text' | 'html';
    delivery_method: 'internal' | 'cf' | 'resend';
  }) {
    return this.requestJson<unknown>('/api/emails/send', {
      method: 'POST',
      body: JSON.stringify(payload)
    });
  }

  forwardEmail(
    id: string,
    payload:
      | { mode: 'webhook'; channelId: number }
      | { mode: 'recipient'; targetEmail: string; targetForwardType?: 'internal' | 'cf' | 'resend'; from?: string }
  ) {
    return this.requestJson<unknown>(`/api/emails/${encodeURIComponent(id)}/forward`, {
      method: 'POST',
      body: JSON.stringify(payload)
    });
  }
}
