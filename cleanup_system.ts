/**
 * 自动清理系统 - 定时清理过期邮件和附件
 * 这部分代码将被集成到主Worker的scheduled事件处理中
 */

// 清理策略配置接口
interface CleanupConfig {
  emailRetentionDays: number;     // 邮件保留天数
  attachmentRetentionDays: number; // 附件保留天数
  logRetentionDays: number;       // 日志保留天数
  batchSize: number;              // 批处理大小
  maxExecutionTime: number;       // 最大执行时间（毫秒）
}

// 清理统计接口
interface CleanupStats {
  emailsDeleted: number;
  attachmentsDeleted: number;
  attachmentsBytesFreed: number;
  logsDeleted: number;
  executionTime: number;
  errors: string[];
}

/**
 * 清理系统管理器
 */
class CleanupManager {
  private db: D1Database;
  private r2: R2Bucket;
  private config: CleanupConfig;
  
  constructor(db: D1Database, r2: R2Bucket, config?: Partial<CleanupConfig>) {
    this.db = db;
    this.r2 = r2;
    this.config = {
      emailRetentionDays: 7,
      attachmentRetentionDays: 7,
      logRetentionDays: 30,
      batchSize: 100,
      maxExecutionTime: 50000, // 50秒，留10秒缓冲
      ...config
    };
  }

  /**
   * 执行完整的清理任务
   */
  async performCleanup(): Promise<CleanupStats> {
    const startTime = Date.now();
    const stats: CleanupStats = {
      emailsDeleted: 0,
      attachmentsDeleted: 0,
      attachmentsBytesFreed: 0,
      logsDeleted: 0,
      executionTime: 0,
      errors: []
    };

    try {
      console.log('开始执行自动清理任务...');
      
      // 按优先级执行清理任务
      await this.cleanupExpiredEmails(stats);
      
      // 检查执行时间
      if (this.shouldContinue(startTime)) {
        await this.cleanupOrphanedAttachments(stats);
      }
      
      if (this.shouldContinue(startTime)) {
        await this.cleanupExpiredLogs(stats);
      }
      
      if (this.shouldContinue(startTime)) {
        await this.optimizeDatabase(stats);
      }
      
      stats.executionTime = Date.now() - startTime;
      
      console.log('清理任务完成:', stats);
      
      // 记录清理日志
      await this.logCleanupResult(stats);
      
    } catch (error) {
      console.error('清理任务执行失败:', error);
      stats.errors.push(error instanceof Error ? error.message : '未知错误');
      stats.executionTime = Date.now() - startTime;
    }

    return stats;
  }

  /**
   * 清理过期邮件
   */
  private async cleanupExpiredEmails(stats: CleanupStats): Promise<void> {
    try {
      console.log(`清理 ${this.config.emailRetentionDays} 天前的邮件...`);
      
      const cutoffDate = new Date();
      cutoffDate.setDate(cutoffDate.getDate() - this.config.emailRetentionDays);
      
      let totalProcessed = 0;
      let hasMore = true;
      
      while (hasMore && this.shouldContinue(Date.now() - stats.executionTime)) {
        // 分批查询过期邮件
        const expiredEmails = await this.db.prepare(`
          SELECT e.id, e.message_id,
                 GROUP_CONCAT(a.r2_key) as attachment_keys,
                 SUM(a.size_bytes) as total_attachment_size
          FROM emails e
          LEFT JOIN attachments a ON e.id = a.email_id
          WHERE e.received_at < ?
          GROUP BY e.id
          LIMIT ?
        `).bind(cutoffDate.toISOString(), this.config.batchSize).all();
        
        if (expiredEmails.results.length === 0) {
          hasMore = false;
          break;
        }
        
        // 处理每批邮件
        for (const email of expiredEmails.results) {
          try {
            // 删除R2中的附件
            if (email.attachment_keys) {
              const keys = (email.attachment_keys as string).split(',');
              await this.deleteAttachmentsFromR2(keys, stats);
            }
            
            // 删除数据库中的邮件记录（附件记录会因为外键约束自动删除）
            await this.db.prepare(`DELETE FROM emails WHERE id = ?`)
              .bind(email.id).run();
            
            stats.emailsDeleted++;
            
            if (email.total_attachment_size) {
              stats.attachmentsBytesFreed += email.total_attachment_size as number;
            }
            
          } catch (error) {
            console.warn(`删除邮件失败 (ID: ${email.id}):`, error);
            stats.errors.push(`删除邮件 ${email.message_id} 失败: ${error instanceof Error ? error.message : '未知错误'}`);
          }
        }
        
        totalProcessed += expiredEmails.results.length;
        
        // 如果返回的结果少于批处理大小，说明没有更多数据了
        if (expiredEmails.results.length < this.config.batchSize) {
          hasMore = false;
        }
      }
      
      console.log(`邮件清理完成，处理了 ${totalProcessed} 条记录，删除了 ${stats.emailsDeleted} 封邮件`);
      
    } catch (error) {
      console.error('清理过期邮件失败:', error);
      stats.errors.push(`清理过期邮件失败: ${error instanceof Error ? error.message : '未知错误'}`);
    }
  }

  /**
   * 清理孤立的附件
   */
  private async cleanupOrphanedAttachments(stats: CleanupStats): Promise<void> {
    try {
      console.log('清理孤立的附件...');
      
      // 查找数据库中存在但邮件已被删除的附件记录
      const orphanedAttachments = await this.db.prepare(`
        SELECT a.id, a.r2_key, a.size_bytes
        FROM attachments a
        LEFT JOIN emails e ON a.email_id = e.id
        WHERE e.id IS NULL
        LIMIT ?
      `).bind(this.config.batchSize).all();
      
      for (const attachment of orphanedAttachments.results) {
        try {
          // 从R2删除附件文件
          await this.r2.delete(attachment.r2_key as string);
          
          // 从数据库删除附件记录
          await this.db.prepare(`DELETE FROM attachments WHERE id = ?`)
            .bind(attachment.id).run();
          
          stats.attachmentsDeleted++;
          stats.attachmentsBytesFreed += attachment.size_bytes as number || 0;
          
        } catch (error) {
          console.warn(`删除孤立附件失败 (ID: ${attachment.id}):`, error);
          stats.errors.push(`删除孤立附件失败: ${error instanceof Error ? error.message : '未知错误'}`);
        }
      }
      
      console.log(`孤立附件清理完成，删除了 ${orphanedAttachments.results.length} 个附件`);
      
    } catch (error) {
      console.error('清理孤立附件失败:', error);
      stats.errors.push(`清理孤立附件失败: ${error instanceof Error ? error.message : '未知错误'}`);
    }
  }

  /**
   * 清理过期日志
   */
  private async cleanupExpiredLogs(stats: CleanupStats): Promise<void> {
    try {
      console.log(`清理 ${this.config.logRetentionDays} 天前的转发日志...`);
      
      const cutoffDate = new Date();
      cutoffDate.setDate(cutoffDate.getDate() - this.config.logRetentionDays);
      
      const result = await this.db.prepare(`
        DELETE FROM forward_logs 
        WHERE sent_at < ?
      `).bind(cutoffDate.toISOString()).run();
      
      stats.logsDeleted = result.changes || 0;
      
      console.log(`日志清理完成，删除了 ${stats.logsDeleted} 条日志记录`);
      
    } catch (error) {
      console.error('清理过期日志失败:', error);
      stats.errors.push(`清理过期日志失败: ${error instanceof Error ? error.message : '未知错误'}`);
    }
  }

  /**
   * 优化数据库
   */
  private async optimizeDatabase(stats: CleanupStats): Promise<void> {
    try {
      console.log('优化数据库...');
      
      // SQLite VACUUM操作来回收空间
      await this.db.prepare('VACUUM').run();
      
      // 更新统计信息
      await this.db.prepare('ANALYZE').run();
      
      console.log('数据库优化完成');
      
    } catch (error) {
      console.warn('数据库优化失败:', error);
      // 数据库优化失败不算严重错误，记录警告即可
      stats.errors.push(`数据库优化失败: ${error instanceof Error ? error.message : '未知错误'}`);
    }
  }

  /**
   * 从R2删除附件文件
   */
  private async deleteAttachmentsFromR2(keys: string[], stats: CleanupStats): Promise<void> {
    for (const key of keys) {
      if (!key.trim()) continue;
      
      try {
        await this.r2.delete(key.trim());
        stats.attachmentsDeleted++;
      } catch (error) {
        console.warn(`删除R2附件失败 (key: ${key}):`, error);
        stats.errors.push(`删除R2附件 ${key} 失败: ${error instanceof Error ? error.message : '未知错误'}`);
      }
    }
  }

  /**
   * 检查是否应该继续执行
   */
  private shouldContinue(startTime: number): boolean {
    return Date.now() - startTime < this.config.maxExecutionTime;
  }

  /**
   * 记录清理结果
   */
  private async logCleanupResult(stats: CleanupStats): Promise<void> {
    try {
      // 可以将清理结果记录到数据库或发送到监控系统
      console.log('清理统计:', {
        邮件删除数量: stats.emailsDeleted,
        附件删除数量: stats.attachmentsDeleted,
        释放存储空间: this.formatBytes(stats.attachmentsBytesFreed),
        日志删除数量: stats.logsDeleted,
        执行时间: `${stats.executionTime}ms`,
        错误数量: stats.errors.length
      });
      
      if (stats.errors.length > 0) {
        console.warn('清理过程中的错误:', stats.errors);
      }
      
    } catch (error) {
      console.warn('记录清理结果失败:', error);
    }
  }

  /**
   * 格式化字节数
   */
  private formatBytes(bytes: number): string {
    if (bytes === 0) return '0 B';
    
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }

  /**
   * 获取系统配置
   */
  async loadConfigFromDatabase(): Promise<void> {
    try {
      const settings = await this.db.prepare(`
        SELECT key, value FROM system_settings 
        WHERE key IN ('cleanup_days', 'max_attachment_size')
      `).all();
      
      for (const setting of settings.results) {
        switch (setting.key) {
          case 'cleanup_days':
            const days = parseInt(setting.value as string);
            if (!isNaN(days) && days > 0) {
              this.config.emailRetentionDays = days;
              this.config.attachmentRetentionDays = days;
            }
            break;
          // 可以根据需要添加更多配置项
        }
      }
      
      console.log('清理配置已更新:', this.config);
      
    } catch (error) {
      console.warn('加载清理配置失败，使用默认配置:', error);
    }
  }

  /**
   * 手动触发清理（用于管理员手动执行）
   */
  async manualCleanup(customConfig?: Partial<CleanupConfig>): Promise<CleanupStats> {
    if (customConfig) {
      this.config = { ...this.config, ...customConfig };
    }
    
    return await this.performCleanup();
  }

  /**
   * 获取清理预览（不实际删除，只统计会被清理的数据）
   */
  async getCleanupPreview(): Promise<{
    expiredEmailsCount: number;
    expiredAttachmentsCount: number;
    expiredAttachmentsSize: number;
    expiredLogsCount: number;
  }> {
    try {
      const emailCutoffDate = new Date();
      emailCutoffDate.setDate(emailCutoffDate.getDate() - this.config.emailRetentionDays);
      
      const logCutoffDate = new Date();
      logCutoffDate.setDate(logCutoffDate.getDate() - this.config.logRetentionDays);
      
      // 统计过期邮件
      const expiredEmailsResult = await this.db.prepare(`
        SELECT 
          COUNT(*) as email_count,
          COUNT(a.id) as attachment_count,
          SUM(a.size_bytes) as attachment_size
        FROM emails e
        LEFT JOIN attachments a ON e.id = a.email_id
        WHERE e.received_at < ?
      `).bind(emailCutoffDate.toISOString()).first();
      
      // 统计过期日志
      const expiredLogsResult = await this.db.prepare(`
        SELECT COUNT(*) as log_count
        FROM forward_logs
        WHERE sent_at < ?
      `).bind(logCutoffDate.toISOString()).first();
      
      return {
        expiredEmailsCount: expiredEmailsResult?.email_count as number || 0,
        expiredAttachmentsCount: expiredEmailsResult?.attachment_count as number || 0,
        expiredAttachmentsSize: expiredEmailsResult?.attachment_size as number || 0,
        expiredLogsCount: expiredLogsResult?.log_count as number || 0
      };
      
    } catch (error) {
      console.error('获取清理预览失败:', error);
      return {
        expiredEmailsCount: 0,
        expiredAttachmentsCount: 0,
        expiredAttachmentsSize: 0,
        expiredLogsCount: 0
      };
    }
  }
}

/**
 * 清理调度器 - 管理定时清理任务
 */
class CleanupScheduler {
  private cleanupManager: CleanupManager;
  
  constructor(cleanupManager: CleanupManager) {
    this.cleanupManager = cleanupManager;
  }

  /**
   * 处理定时清理事件
   */
  async handleScheduledEvent(cron: string): Promise<CleanupStats> {
    console.log(`收到定时清理事件，cron: ${cron}`);
    
    // 从数据库加载最新配置
    await this.cleanupManager.loadConfigFromDatabase();
    
    // 执行清理
    return await this.cleanupManager.performCleanup();
  }

  /**
   * 检查是否需要执行清理
   */
  shouldRunCleanup(cron: string): boolean {
    // 根据cron表达式决定是否执行清理
    // 例如，只在每天的凌晨2点执行清理
    const now = new Date();
    const hour = now.getUTCHours();
    
    // 简单的时间检查，可以根据需要实现更复杂的cron解析
    return hour >= 2 && hour < 3;
  }
}

// 导出类供其他模块使用
export { CleanupManager, CleanupScheduler };
export type { CleanupConfig, CleanupStats };