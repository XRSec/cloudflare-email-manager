export interface McpToolInputSchema {
  type: 'object';
  properties: Record<string, {
    type: string;
    description: string;
    enum?: string[];
  }>;
  required?: string[];
  additionalProperties?: boolean;
}

export interface McpToolDefinition {
  name: string;
  description: string;
  inputSchema: McpToolInputSchema;
}

export const MCP_SERVER_INFO = {
  name: 'cloudflare-email-manager',
  version: '1.0.0',
  protocolVersion: '2025-03-26'
} as const;

export const MCP_TOOLS: McpToolDefinition[] = [
  {
    name: 'list_emails',
    description: 'List emails with optional filters. Side-effect-free: does not read R2 or mark emails as read, and includes structured verification info when available.',
    inputSchema: {
      type: 'object',
      properties: {
        folder: { type: 'string', description: 'Mailbox folder', enum: ['inbox', 'sent'] },
        status: { type: 'string', description: 'Read status filter', enum: ['read', 'unread'] },
        recipient: { type: 'string', description: 'Filter by recipient email or domain' },
        sender: { type: 'string', description: 'Filter by sender email or domain' },
        search: { type: 'string', description: 'Full-text search across subject, content, sender, recipient' },
        limit: { type: 'number', description: 'Page size (default 20)' },
        page: { type: 'number', description: 'Page number (default 1)' }
      },
      additionalProperties: false
    }
  },
  {
    name: 'get_latest_verification',
    description: 'Get the latest matching email verification code and/or unwrapped verification link without triggering unnecessary R2 reads.',
    inputSchema: {
      type: 'object',
      properties: {
        recipient: { type: 'string', description: 'Filter by recipient email or domain' },
        sender: { type: 'string', description: 'Filter by sender email or domain' },
        search: { type: 'string', description: 'Search keyword in subject or preview' }
      },
      additionalProperties: false
    }
  },
  {
    name: 'read_email',
    description: 'Read full email content (HTML/text), attachments metadata, and structured verification info. Marks unread emails as read.',
    inputSchema: {
      type: 'object',
      properties: {
        id: { type: 'string', description: 'Email UUID' }
      },
      required: ['id'],
      additionalProperties: false
    }
  },
  {
    name: 'send_email',
    description: 'Send an email via internal, Cloudflare Email Service (cf), or Resend.',
    inputSchema: {
      type: 'object',
      properties: {
        to: { type: 'string', description: 'Recipient email address' },
        from: { type: 'string', description: 'Sender email address' },
        subject: { type: 'string', description: 'Email subject' },
        content: { type: 'string', description: 'Email body content' },
        content_type: { type: 'string', description: 'Body format', enum: ['text', 'html'] },
        delivery_method: { type: 'string', description: 'Delivery method', enum: ['internal', 'cf', 'resend'] }
      },
      required: ['to', 'from', 'subject', 'content', 'delivery_method'],
      additionalProperties: false
    }
  },
  {
    name: 'forward_email',
    description: 'Forward an existing email to a recipient address or a configured webhook channel.',
    inputSchema: {
      type: 'object',
      properties: {
        id: { type: 'string', description: 'Source email UUID' },
        mode: { type: 'string', description: 'Forward mode', enum: ['recipient', 'webhook'] },
        targetEmail: { type: 'string', description: 'Target email address (when mode=recipient)' },
        targetForwardType: { type: 'string', description: 'Forward delivery method', enum: ['internal', 'cf', 'resend'] },
        from: { type: 'string', description: 'Sender address (when mode=recipient)' },
        channelId: { type: 'number', description: 'Webhook channel ID (when mode=webhook)' }
      },
      required: ['id', 'mode'],
      additionalProperties: false
    }
  },
  {
    name: 'mark_email_read',
    description: 'Mark an email as read or unread.',
    inputSchema: {
      type: 'object',
      properties: {
        id: { type: 'string', description: 'Email UUID' },
        is_read: { type: 'boolean', description: 'true for read, false for unread' }
      },
      required: ['id', 'is_read'],
      additionalProperties: false
    }
  },
  {
    name: 'delete_email',
    description: 'Permanently delete an email by ID.',
    inputSchema: {
      type: 'object',
      properties: {
        id: { type: 'string', description: 'Email UUID' }
      },
      required: ['id'],
      additionalProperties: false
    }
  }
];
