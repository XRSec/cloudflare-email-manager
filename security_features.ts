/**
 * 安全特性模块 - 防SQL注入、验签、限流等安全功能
 * 这部分代码将被集成到主Worker中
 */

import { Context } from 'hono';
import { HTTPException } from 'hono/http-exception';

// 安全配置接口
interface SecurityConfig {
  maxRequestsPerMinute: number;    // 每分钟最大请求数
  maxRequestsPerHour: number;      // 每小时最大请求数
  maxLoginAttempts: number;        // 最大登录尝试次数
  loginAttemptWindow: number;      // 登录尝试时间窗口（分钟）
  enableIPWhitelist: boolean;      // 是否启用IP白名单
  ipWhitelist: string[];          // IP白名单
  enableRequestLogging: boolean;   // 是否启用请求日志
  sensitiveHeaders: string[];      // 敏感请求头
}

// 限流记录接口
interface RateLimitRecord {
  requests: number;
  lastRequest: number;
  blocked: boolean;
}

// 登录尝试记录接口
interface LoginAttemptRecord {
  attempts: number;
  lastAttempt: number;
  blocked: boolean;
}

/**
 * 安全管理器
 */
class SecurityManager {
  private kv: KVNamespace;
  private config: SecurityConfig;
  
  constructor(kv: KVNamespace, config?: Partial<SecurityConfig>) {
    this.kv = kv;
    this.config = {
      maxRequestsPerMinute: 60,
      maxRequestsPerHour: 1000,
      maxLoginAttempts: 5,
      loginAttemptWindow: 15, // 15分钟
      enableIPWhitelist: false,
      ipWhitelist: [],
      enableRequestLogging: true,
      sensitiveHeaders: ['authorization', 'x-api-key', 'cookie'],
      ...config
    };
  }

  /**
   * 限流中间件
   */
  async rateLimitMiddleware(c: Context, next: () => Promise<void>): Promise<void> {
    const clientIP = this.getClientIP(c);
    const key = `rate_limit:${clientIP}`;
    
    try {
      // 检查限流
      const isAllowed = await this.checkRateLimit(key);
      
      if (!isAllowed) {
        console.warn(`限流触发: IP ${clientIP}`);
        throw new HTTPException(429, { 
          message: '请求过于频繁，请稍后再试',
          res: new Response('Too Many Requests', {
            status: 429,
            headers: {
              'Retry-After': '60'
            }
          })
        });
      }
      
      await next();
      
    } catch (error) {
      if (error instanceof HTTPException) {
        throw error;
      }
      console.error('限流检查失败:', error);
      await next(); // 限流检查失败时允许请求通过
    }
  }

  /**
   * IP白名单中间件
   */
  async ipWhitelistMiddleware(c: Context, next: () => Promise<void>): Promise<void> {
    if (!this.config.enableIPWhitelist) {
      await next();
      return;
    }

    const clientIP = this.getClientIP(c);
    
    if (!this.isIPWhitelisted(clientIP)) {
      console.warn(`IP不在白名单中: ${clientIP}`);
      throw new HTTPException(403, { message: '访问被拒绝' });
    }
    
    await next();
  }

  /**
   * 登录尝试限制
   */
  async checkLoginAttempts(identifier: string): Promise<boolean> {
    const key = `login_attempts:${identifier}`;
    
    try {
      const record = await this.kv.get<LoginAttemptRecord>(key, 'json');
      
      if (!record) {
        return true; // 没有记录，允许登录
      }
      
      const now = Date.now();
      const windowStart = now - (this.config.loginAttemptWindow * 60 * 1000);
      
      // 如果超出时间窗口，重置计数
      if (record.lastAttempt < windowStart) {
        await this.kv.delete(key);
        return true;
      }
      
      // 检查是否被阻止
      if (record.blocked || record.attempts >= this.config.maxLoginAttempts) {
        return false;
      }
      
      return true;
      
    } catch (error) {
      console.error('检查登录尝试失败:', error);
      return true; // 检查失败时允许登录
    }
  }

  /**
   * 记录登录尝试
   */
  async recordLoginAttempt(identifier: string, success: boolean): Promise<void> {
    const key = `login_attempts:${identifier}`;
    
    try {
      if (success) {
        // 登录成功，清除记录
        await this.kv.delete(key);
        return;
      }
      
      // 登录失败，增加计数
      const record = await this.kv.get<LoginAttemptRecord>(key, 'json') || {
        attempts: 0,
        lastAttempt: 0,
        blocked: false
      };
      
      record.attempts++;
      record.lastAttempt = Date.now();
      record.blocked = record.attempts >= this.config.maxLoginAttempts;
      
      // 设置过期时间为时间窗口的2倍
      const expirationTtl = this.config.loginAttemptWindow * 60 * 2;
      
      await this.kv.put(key, JSON.stringify(record), {
        expirationTtl: expirationTtl
      });
      
      if (record.blocked) {
        console.warn(`用户被临时锁定: ${identifier}, 尝试次数: ${record.attempts}`);
      }
      
    } catch (error) {
      console.error('记录登录尝试失败:', error);
    }
  }

  /**
   * 检查限流
   */
  private async checkRateLimit(key: string): Promise<boolean> {
    try {
      const record = await this.kv.get<RateLimitRecord>(key, 'json') || {
        requests: 0,
        lastRequest: 0,
        blocked: false
      };
      
      const now = Date.now();
      const oneMinuteAgo = now - 60000;
      const oneHourAgo = now - 3600000;
      
      // 重置分钟计数器
      if (record.lastRequest < oneMinuteAgo) {
        record.requests = 0;
      }
      
      // 增加请求计数
      record.requests++;
      record.lastRequest = now;
      
      // 检查限流
      if (record.requests > this.config.maxRequestsPerMinute) {
        record.blocked = true;
      }
      
      // 保存记录，过期时间1小时
      await this.kv.put(key, JSON.stringify(record), {
        expirationTtl: 3600
      });
      
      return !record.blocked;
      
    } catch (error) {
      console.error('限流检查失败:', error);
      return true; // 检查失败时允许请求
    }
  }

  /**
   * 获取客户端IP
   */
  private getClientIP(c: Context): string {
    // 尝试从不同的头部获取真实IP
    const headers = [
      'CF-Connecting-IP',     // Cloudflare
      'X-Forwarded-For',      // 标准代理头
      'X-Real-IP',            // Nginx
      'X-Client-IP'           // 其他代理
    ];
    
    for (const header of headers) {
      const ip = c.req.header(header);
      if (ip) {
        // 如果是逗号分隔的IP列表，取第一个
        return ip.split(',')[0].trim();
      }
    }
    
    // 兜底方案
    return c.req.header('host') || 'unknown';
  }

  /**
   * 检查IP是否在白名单中
   */
  private isIPWhitelisted(ip: string): boolean {
    if (this.config.ipWhitelist.length === 0) {
      return true; // 空白名单表示允许所有IP
    }
    
    return this.config.ipWhitelist.some(whitelistedIP => {
      // 支持CIDR表示法的简单实现
      if (whitelistedIP.includes('/')) {
        return this.isIPInCIDR(ip, whitelistedIP);
      }
      return ip === whitelistedIP;
    });
  }

  /**
   * 检查IP是否在CIDR范围内（简单实现）
   */
  private isIPInCIDR(ip: string, cidr: string): boolean {
    // 这是一个简化的CIDR检查实现
    // 实际生产环境可能需要更完善的IP地址处理
    const [networkIP, prefixLength] = cidr.split('/');
    
    if (!prefixLength) {
      return ip === networkIP;
    }
    
    // TODO: 实现完整的CIDR匹配逻辑
    // 这里简化为精确匹配
    return ip === networkIP;
  }

  /**
   * 记录安全事件
   */
  async logSecurityEvent(event: {
    type: string;
    ip: string;
    userAgent?: string;
    details?: any;
  }): Promise<void> {
    if (!this.config.enableRequestLogging) {
      return;
    }
    
    try {
      const logEntry = {
        timestamp: new Date().toISOString(),
        type: event.type,
        ip: event.ip,
        userAgent: event.userAgent,
        details: event.details
      };
      
      console.warn('安全事件:', logEntry);
      
      // 可以将安全事件发送到外部日志系统
      // await this.sendToSecurityLog(logEntry);
      
    } catch (error) {
      console.error('记录安全事件失败:', error);
    }
  }
}

/**
 * 输入验证器
 */
class InputValidator {
  /**
   * 验证邮箱前缀
   */
  static validateEmailPrefix(prefix: string): { valid: boolean; message?: string } {
    if (!prefix || typeof prefix !== 'string') {
      return { valid: false, message: '邮箱前缀不能为空' };
    }
    
    if (prefix.length < 3 || prefix.length > 30) {
      return { valid: false, message: '邮箱前缀长度必须在3-30个字符之间' };
    }
    
    // 只允许字母、数字和少数特殊字符
    const validPattern = /^[a-zA-Z0-9._-]+$/;
    if (!validPattern.test(prefix)) {
      return { valid: false, message: '邮箱前缀只能包含字母、数字、点号、下划线和连字符' };
    }
    
    // 不能以特殊字符开头或结尾
    if (/^[._-]|[._-]$/.test(prefix)) {
      return { valid: false, message: '邮箱前缀不能以特殊字符开头或结尾' };
    }
    
    return { valid: true };
  }

  /**
   * 验证密码强度
   */
  static validatePassword(password: string): { valid: boolean; message?: string } {
    if (!password || typeof password !== 'string') {
      return { valid: false, message: '密码不能为空' };
    }
    
    if (password.length < 6) {
      return { valid: false, message: '密码长度至少6位' };
    }
    
    if (password.length > 128) {
      return { valid: false, message: '密码长度不能超过128位' };
    }
    
    // 检查是否包含常见弱密码
    const weakPasswords = ['123456', 'password', 'admin', '123123', '000000'];
    if (weakPasswords.includes(password.toLowerCase())) {
      return { valid: false, message: '密码过于简单，请使用更复杂的密码' };
    }
    
    return { valid: true };
  }

  /**
   * 验证URL
   */
  static validateURL(url: string): { valid: boolean; message?: string } {
    if (!url || typeof url !== 'string') {
      return { valid: false, message: 'URL不能为空' };
    }
    
    try {
      const urlObj = new URL(url);
      
      // 只允许HTTP和HTTPS协议
      if (!['http:', 'https:'].includes(urlObj.protocol)) {
        return { valid: false, message: 'URL必须使用HTTP或HTTPS协议' };
      }
      
      // 检查是否是内网地址（防止SSRF攻击）
      if (this.isPrivateIP(urlObj.hostname)) {
        return { valid: false, message: '不允许访问内网地址' };
      }
      
      return { valid: true };
      
    } catch (error) {
      return { valid: false, message: 'URL格式无效' };
    }
  }

  /**
   * 检查是否是私有IP地址
   */
  private static isPrivateIP(hostname: string): boolean {
    // 检查是否是IP地址
    const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (!ipPattern.test(hostname)) {
      return false; // 不是IP地址，假设是域名，允许通过
    }
    
    const parts = hostname.split('.').map(Number);
    
    // 检查私有IP范围
    if (parts[0] === 10) return true;                                    // 10.0.0.0/8
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true; // 172.16.0.0/12
    if (parts[0] === 192 && parts[1] === 168) return true;              // 192.168.0.0/16
    if (parts[0] === 127) return true;                                  // 127.0.0.0/8 (localhost)
    if (parts[0] === 169 && parts[1] === 254) return true;             // 169.254.0.0/16 (link-local)
    
    return false;
  }

  /**
   * 清理HTML内容（防止XSS）
   */
  static sanitizeHTML(html: string): string {
    if (!html || typeof html !== 'string') {
      return '';
    }
    
    // 简单的HTML清理，移除script标签和事件处理器
    return html
      .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
      .replace(/on\w+\s*=\s*"[^"]*"/gi, '')
      .replace(/on\w+\s*=\s*'[^']*'/gi, '')
      .replace(/javascript:/gi, '');
  }

  /**
   * 验证文件名
   */
  static validateFileName(fileName: string): { valid: boolean; message?: string } {
    if (!fileName || typeof fileName !== 'string') {
      return { valid: false, message: '文件名不能为空' };
    }
    
    if (fileName.length > 255) {
      return { valid: false, message: '文件名过长' };
    }
    
    // 检查危险字符
    const dangerousChars = /[<>:"|?*\x00-\x1f]/;
    if (dangerousChars.test(fileName)) {
      return { valid: false, message: '文件名包含非法字符' };
    }
    
    // 检查是否是危险的文件名
    const dangerousNames = ['con', 'prn', 'aux', 'nul', 'com1', 'com2', 'com3', 'com4', 'com5', 'com6', 'com7', 'com8', 'com9', 'lpt1', 'lpt2', 'lpt3', 'lpt4', 'lpt5', 'lpt6', 'lpt7', 'lpt8', 'lpt9'];
    const nameWithoutExt = fileName.split('.')[0].toLowerCase();
    if (dangerousNames.includes(nameWithoutExt)) {
      return { valid: false, message: '文件名不允许使用系统保留名称' };
    }
    
    return { valid: true };
  }
}

/**
 * SQL注入防护
 */
class SQLInjectionProtector {
  /**
   * 检测可能的SQL注入攻击
   */
  static detectSQLInjection(input: string): boolean {
    if (!input || typeof input !== 'string') {
      return false;
    }
    
    // SQL注入关键字模式
    const sqlPatterns = [
      /(\bUNION\b.*\bSELECT\b)/i,
      /(\bSELECT\b.*\bFROM\b)/i,
      /(\bINSERT\b.*\bINTO\b)/i,
      /(\bUPDATE\b.*\bSET\b)/i,
      /(\bDELETE\b.*\bFROM\b)/i,
      /(\bDROP\b.*\bTABLE\b)/i,
      /(\bCREATE\b.*\bTABLE\b)/i,
      /(\bALTER\b.*\bTABLE\b)/i,
      /(\bEXEC\b|\bEXECUTE\b)/i,
      /(\-\-)|(\#)|(\;)/,
      /(\bOR\b.*=.*)/i,
      /(\bAND\b.*=.*)/i,
      /('.*OR.*'=')/i,
      /('.*AND.*'=')/i
    ];
    
    return sqlPatterns.some(pattern => pattern.test(input));
  }

  /**
   * 清理可能包含SQL注入的输入
   */
  static sanitizeInput(input: string): string {
    if (!input || typeof input !== 'string') {
      return '';
    }
    
    // 移除或转义危险字符
    return input
      .replace(/['"]/g, '') // 移除引号
      .replace(/[;\-#]/g, '') // 移除分号、双破折号、井号
      .replace(/\b(UNION|SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE|OR|AND)\b/gi, '') // 移除SQL关键字
      .trim();
  }
}

/**
 * 请求日志记录器
 */
class RequestLogger {
  private kv: KVNamespace;
  
  constructor(kv: KVNamespace) {
    this.kv = kv;
  }

  /**
   * 记录请求
   */
  async logRequest(c: Context, startTime: number): Promise<void> {
    try {
      const endTime = Date.now();
      const duration = endTime - startTime;
      
      const logEntry = {
        timestamp: new Date().toISOString(),
        method: c.req.method,
        url: c.req.url,
        ip: this.getClientIP(c),
        userAgent: c.req.header('User-Agent'),
        duration: duration,
        status: c.res?.status || 0
      };
      
      // 记录到控制台
      console.log('请求日志:', logEntry);
      
      // 可以选择将日志存储到KV或发送到外部系统
      // await this.storeLogEntry(logEntry);
      
    } catch (error) {
      console.error('记录请求日志失败:', error);
    }
  }

  /**
   * 获取客户端IP
   */
  private getClientIP(c: Context): string {
    return c.req.header('CF-Connecting-IP') || 
           c.req.header('X-Forwarded-For')?.split(',')[0]?.trim() || 
           'unknown';
  }
}

// 导出类供其他模块使用
export { 
  SecurityManager, 
  InputValidator, 
  SQLInjectionProtector, 
  RequestLogger 
};

export type { 
  SecurityConfig, 
  RateLimitRecord, 
  LoginAttemptRecord 
};