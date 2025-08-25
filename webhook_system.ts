/**
 * Webhook系统 - 支持钉钉、飞书等平台的消息推送
 * 这部分代码将被集成到主Worker中
 */

// Webhook类型枚举
enum WebhookType {
  CUSTOM = 'custom',
  DINGTALK = 'dingtalk',
  FEISHU = 'feishu'
}

// 邮件数据接口
interface EmailData {
  id?: number;
  messageId: string;
  from: string;
  to: string;
  subject?: string;
  text?: string;
  html?: string;
  receivedAt: string;
  hasAttachments: boolean;
  attachmentCount?: number;
}

// Webhook配置接口
interface WebhookConfig {
  url: string;
  secret?: string;
  type: WebhookType;
  timeout?: number;
}

/**
 * Webhook发送器类
 */
class WebhookSender {
  private config: WebhookConfig;
  
  constructor(config: WebhookConfig) {
    this.config = {
      timeout: 10000, // 默认10秒超时
      ...config
    };
  }

  /**
   * 发送Webhook通知
   */
  async send(emailData: EmailData): Promise<{
    success: boolean;
    status?: number;
    error?: string;
  }> {
    try {
      console.log(`发送Webhook通知到 ${this.config.url}, 类型: ${this.config.type}`);
      
      // 构建payload
      const payload = this.buildPayload(emailData);
      
      // 构建请求头
      const headers = await this.buildHeaders(payload);
      
      // 发送请求
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), this.config.timeout);
      
      const response = await fetch(this.config.url, {
        method: 'POST',
        headers: headers,
        body: JSON.stringify(payload),
        signal: controller.signal
      });
      
      clearTimeout(timeoutId);
      
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }
      
      console.log(`Webhook发送成功: ${this.config.url}, 状态码: ${response.status}`);
      
      return {
        success: true,
        status: response.status
      };
      
    } catch (error) {
      console.error('Webhook发送失败:', this.config.url, error);
      
      return {
        success: false,
        error: error instanceof Error ? error.message : '未知错误'
      };
    }
  }

  /**
   * 构建请求payload
   */
  private buildPayload(emailData: EmailData): any {
    switch (this.config.type) {
      case WebhookType.DINGTALK:
        return this.buildDingTalkPayload(emailData);
      case WebhookType.FEISHU:
        return this.buildFeishuPayload(emailData);
      default:
        return this.buildCustomPayload(emailData);
    }
  }

  /**
   * 构建钉钉消息payload
   */
  private buildDingTalkPayload(emailData: EmailData): any {
    const title = `新邮件: ${emailData.subject || '(无主题)'}`;
    const content = this.formatEmailContent(emailData);
    
    // 支持多种钉钉消息类型
    if (emailData.html) {
      // Markdown格式
      return {
        msgtype: 'markdown',
        markdown: {
          title: title,
          text: this.buildDingTalkMarkdown(emailData)
        }
      };
    } else {
      // 文本格式
      return {
        msgtype: 'text',
        text: {
          content: `${title}\n\n${content}`
        }
      };
    }
  }

  /**
   * 构建钉钉Markdown消息
   */
  private buildDingTalkMarkdown(emailData: EmailData): string {
    let markdown = `# 📧 新邮件通知\n\n`;
    markdown += `**发件人:** ${emailData.from}\n\n`;
    markdown += `**收件人:** ${emailData.to}\n\n`;
    markdown += `**主题:** ${emailData.subject || '(无主题)'}\n\n`;
    markdown += `**时间:** ${new Date(emailData.receivedAt).toLocaleString('zh-CN')}\n\n`;
    
    if (emailData.hasAttachments) {
      markdown += `**附件:** ✅ (${emailData.attachmentCount || 0}个)\n\n`;
    }
    
    // 邮件内容预览
    const preview = this.getContentPreview(emailData.text || '', 200);
    if (preview) {
      markdown += `**内容预览:**\n> ${preview}\n\n`;
    }
    
    markdown += `---\n`;
    markdown += `*邮件ID: ${emailData.messageId}*`;
    
    return markdown;
  }

  /**
   * 构建飞书消息payload
   */
  private buildFeishuPayload(emailData: EmailData): any {
    return {
      msg_type: 'interactive',
      card: {
        config: {
          wide_screen_mode: true
        },
        header: {
          title: {
            tag: 'plain_text',
            content: `📧 新邮件: ${emailData.subject || '(无主题)'}`
          },
          template: 'blue'
        },
        elements: [
          {
            tag: 'div',
            fields: [
              {
                is_short: true,
                text: {
                  tag: 'lark_md',
                  content: `**发件人**\n${emailData.from}`
                }
              },
              {
                is_short: true,
                text: {
                  tag: 'lark_md',
                  content: `**收件人**\n${emailData.to}`
                }
              }
            ]
          },
          {
            tag: 'div',
            fields: [
              {
                is_short: true,
                text: {
                  tag: 'lark_md',
                  content: `**时间**\n${new Date(emailData.receivedAt).toLocaleString('zh-CN')}`
                }
              },
              {
                is_short: true,
                text: {
                  tag: 'lark_md',
                  content: `**附件**\n${emailData.hasAttachments ? `✅ (${emailData.attachmentCount || 0}个)` : '❌'}`
                }
              }
            ]
          },
          ...this.buildFeishuContentElements(emailData)
        ]
      }
    };
  }

  /**
   * 构建飞书内容元素
   */
  private buildFeishuContentElements(emailData: EmailData): any[] {
    const elements = [];
    
    // 邮件内容
    const preview = this.getContentPreview(emailData.text || '', 300);
    if (preview) {
      elements.push({
        tag: 'div',
        text: {
          tag: 'lark_md',
          content: `**内容预览**\n${preview}`
        }
      });
    }
    
    // 分割线
    elements.push({
      tag: 'hr'
    });
    
    // 邮件ID
    elements.push({
      tag: 'div',
      text: {
        tag: 'plain_text',
        content: `邮件ID: ${emailData.messageId}`
      }
    });
    
    return elements;
  }

  /**
   * 构建自定义消息payload
   */
  private buildCustomPayload(emailData: EmailData): any {
    return {
      type: 'email_received',
      timestamp: new Date().toISOString(),
      data: {
        messageId: emailData.messageId,
        from: emailData.from,
        to: emailData.to,
        subject: emailData.subject,
        content: this.getContentPreview(emailData.text || '', 500),
        hasAttachments: emailData.hasAttachments,
        attachmentCount: emailData.attachmentCount || 0,
        receivedAt: emailData.receivedAt
      },
      // 用于验证的额外信息
      version: '1.0',
      source: 'temp-email-system'
    };
  }

  /**
   * 构建请求头
   */
  private async buildHeaders(payload: any): Promise<Record<string, string>> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'User-Agent': 'TempEmail-Webhook/1.0'
    };
    
    // 添加签名（如果有密钥）
    if (this.config.secret) {
      const signature = await this.generateSignature(payload, this.config.secret);
      
      // 根据不同平台使用不同的签名头
      switch (this.config.type) {
        case WebhookType.DINGTALK:
          // 钉钉使用时间戳和签名
          const timestamp = Date.now();
          headers['X-DingTalk-Timestamp'] = timestamp.toString();
          headers['X-DingTalk-Signature'] = await this.generateDingTalkSignature(timestamp, this.config.secret);
          break;
        case WebhookType.FEISHU:
          // 飞书使用签名验证
          headers['X-Feishu-Signature'] = signature;
          break;
        default:
          // 自定义webhook使用标准签名头
          headers['X-Signature'] = signature;
          headers['X-Signature-Algorithm'] = 'sha256';
          break;
      }
    }
    
    return headers;
  }

  /**
   * 生成通用签名
   */
  private async generateSignature(payload: any, secret: string): Promise<string> {
    const message = JSON.stringify(payload);
    const encoder = new TextEncoder();
    const data = encoder.encode(message);
    const key = encoder.encode(secret);
    
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      key,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );
    
    const signature = await crypto.subtle.sign('HMAC', cryptoKey, data);
    return Array.from(new Uint8Array(signature))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }

  /**
   * 生成钉钉签名
   */
  private async generateDingTalkSignature(timestamp: number, secret: string): Promise<string> {
    const stringToSign = `${timestamp}\n${secret}`;
    const encoder = new TextEncoder();
    const data = encoder.encode(stringToSign);
    const key = encoder.encode(secret);
    
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      key,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );
    
    const signature = await crypto.subtle.sign('HMAC', cryptoKey, data);
    const base64 = btoa(String.fromCharCode(...new Uint8Array(signature)));
    return encodeURIComponent(base64);
  }

  /**
   * 格式化邮件内容
   */
  private formatEmailContent(emailData: EmailData): string {
    let content = `发件人: ${emailData.from}\n`;
    content += `收件人: ${emailData.to}\n`;
    content += `主题: ${emailData.subject || '(无主题)'}\n`;
    content += `时间: ${new Date(emailData.receivedAt).toLocaleString('zh-CN')}\n`;
    
    if (emailData.hasAttachments) {
      content += `附件: ${emailData.attachmentCount || 0}个\n`;
    }
    
    content += '\n内容:\n';
    content += this.getContentPreview(emailData.text || '', 300);
    
    return content;
  }

  /**
   * 获取内容预览
   */
  private getContentPreview(text: string, maxLength: number = 200): string {
    if (!text) return '(无内容)';
    
    // 清理HTML标签和多余空格
    const cleanText = text
      .replace(/<[^>]*>/g, '') // 移除HTML标签
      .replace(/\s+/g, ' ')     // 合并多个空格
      .trim();
    
    if (cleanText.length <= maxLength) {
      return cleanText;
    }
    
    return cleanText.substring(0, maxLength) + '...';
  }
}

/**
 * Webhook管理器
 */
class WebhookManager {
  private db: D1Database;
  
  constructor(db: D1Database) {
    this.db = db;
  }

  /**
   * 处理邮件接收时的Webhook通知
   */
  async handleEmailReceived(emailData: EmailData, userId: number): Promise<void> {
    try {
      // 获取用户个人Webhook配置
      const userWebhook = await this.getUserWebhook(userId);
      
      // 获取匹配的转发规则
      const matchingRules = await this.getMatchingForwardRules(emailData);
      
      // 发送通知任务
      const webhookTasks: Promise<void>[] = [];
      
      // 用户个人Webhook
      if (userWebhook && userWebhook.url) {
        webhookTasks.push(this.sendWebhookNotification(
          emailData,
          userWebhook,
          null, // 用户个人webhook没有规则ID
          userId
        ));
      }
      
      // 转发规则Webhook
      for (const rule of matchingRules) {
        webhookTasks.push(this.sendWebhookNotification(
          emailData,
          {
            url: rule.webhook_url,
            secret: rule.webhook_secret,
            type: rule.webhook_type as WebhookType
          },
          rule.id,
          userId
        ));
      }
      
      // 并行执行所有Webhook通知
      await Promise.allSettled(webhookTasks);
      
    } catch (error) {
      console.error('处理Webhook通知失败:', error);
    }
  }

  /**
   * 获取用户Webhook配置
   */
  private async getUserWebhook(userId: number): Promise<{
    url?: string;
    secret?: string;
    type: WebhookType;
  } | null> {
    const result = await this.db.prepare(`
      SELECT webhook_url, webhook_secret 
      FROM users 
      WHERE id = ? AND webhook_url IS NOT NULL AND webhook_url != ''
    `).bind(userId).first();
    
    if (!result || !result.webhook_url) {
      return null;
    }
    
    return {
      url: result.webhook_url as string,
      secret: result.webhook_secret as string || undefined,
      type: WebhookType.CUSTOM // 用户个人webhook默认为自定义类型
    };
  }

  /**
   * 获取匹配的转发规则
   */
  private async getMatchingForwardRules(emailData: EmailData): Promise<any[]> {
    // 获取所有启用的转发规则
    const rules = await this.db.prepare(`
      SELECT * FROM forward_rules WHERE enabled = 1
    `).all();
    
    const matchingRules = [];
    
    for (const rule of rules.results) {
      if (this.isRuleMatching(rule, emailData)) {
        matchingRules.push(rule);
      }
    }
    
    return matchingRules;
  }

  /**
   * 检查规则是否匹配
   */
  private isRuleMatching(rule: any, emailData: EmailData): boolean {
    // 发件人过滤
    if (rule.sender_filter && !this.matchesPattern(emailData.from, rule.sender_filter)) {
      return false;
    }
    
    // 关键字过滤（检查主题和内容）
    if (rule.keyword_filter) {
      const searchText = `${emailData.subject || ''} ${emailData.text || ''}`.toLowerCase();
      if (!searchText.includes(rule.keyword_filter.toLowerCase())) {
        return false;
      }
    }
    
    // 收件人过滤（检查邮箱前缀）
    if (rule.recipient_filter) {
      const recipient = emailData.to.split('@')[0]; // 提取前缀
      if (!this.matchesPattern(recipient, rule.recipient_filter)) {
        return false;
      }
    }
    
    return true;
  }

  /**
   * 模式匹配检查
   */
  private matchesPattern(text: string, pattern: string): boolean {
    // 支持简单的通配符匹配
    const regexPattern = pattern
      .replace(/\*/g, '.*')  // * 匹配任意字符
      .replace(/\?/g, '.');  // ? 匹配单个字符
    
    const regex = new RegExp(`^${regexPattern}$`, 'i'); // 不区分大小写
    return regex.test(text);
  }

  /**
   * 发送Webhook通知
   */
  private async sendWebhookNotification(
    emailData: EmailData,
    webhookConfig: { url: string; secret?: string; type: WebhookType },
    ruleId: number | null,
    userId: number
  ): Promise<void> {
    try {
      const sender = new WebhookSender({
        url: webhookConfig.url,
        secret: webhookConfig.secret,
        type: webhookConfig.type
      });
      
      const result = await sender.send(emailData);
      
      // 记录发送日志（如果有邮件ID）
      if (emailData.id) {
        await this.logWebhookResult(emailData.id, ruleId, webhookConfig.url, result);
      }
      
    } catch (error) {
      console.error('Webhook通知发送失败:', webhookConfig.url, error);
      
      // 记录失败日志
      if (emailData.id) {
        await this.logWebhookResult(emailData.id, ruleId, webhookConfig.url, {
          success: false,
          error: error instanceof Error ? error.message : '未知错误'
        });
      }
    }
  }

  /**
   * 记录Webhook发送日志
   */
  private async logWebhookResult(
    emailId: number,
    ruleId: number | null,
    webhookUrl: string,
    result: { success: boolean; status?: number; error?: string }
  ): Promise<void> {
    try {
      await this.db.prepare(`
        INSERT INTO forward_logs (
          email_id, rule_id, webhook_url, status, response_code, error_message
        ) VALUES (?, ?, ?, ?, ?, ?)
      `).bind(
        emailId,
        ruleId,
        webhookUrl,
        result.success ? 'success' : 'failed',
        result.status || null,
        result.error || null
      ).run();
    } catch (error) {
      console.warn('记录Webhook日志失败:', error);
    }
  }

  /**
   * 测试Webhook配置
   */
  async testWebhook(config: {
    url: string;
    secret?: string;
    type: WebhookType;
  }): Promise<{ success: boolean; message: string; status?: number }> {
    try {
      const testEmailData: EmailData = {
        messageId: 'test-' + Date.now(),
        from: 'test@example.com',
        to: 'user@yourdomain.com',
        subject: '测试邮件',
        text: '这是一封测试邮件，用于验证Webhook配置是否正确。',
        receivedAt: new Date().toISOString(),
        hasAttachments: false,
        attachmentCount: 0
      };
      
      const sender = new WebhookSender(config);
      const result = await sender.send(testEmailData);
      
      if (result.success) {
        return {
          success: true,
          message: 'Webhook测试成功',
          status: result.status
        };
      } else {
        return {
          success: false,
          message: `Webhook测试失败: ${result.error}`
        };
      }
      
    } catch (error) {
      return {
        success: false,
        message: `Webhook测试失败: ${error instanceof Error ? error.message : '未知错误'}`
      };
    }
  }
}

// 导出类和枚举供其他模块使用
export { WebhookSender, WebhookManager, WebhookType };
export type { EmailData, WebhookConfig };