/**
 * 重试工具函数
 */

import { debugLog, errorLog } from './debug';

export interface RetryOptions {
  maxAttempts?: number;
  delayMs?: number;
  backoffMultiplier?: number;
  maxDelayMs?: number;
  onRetry?: (attempt: number, error: Error) => void;
}

/**
 * 通用重试函数
 * 
 * @param fn 要执行的异步函数
 * @param options 重试选项
 * @returns 函数执行结果
 */
export async function retryAsync<T>(
  fn: () => Promise<T>,
  options: RetryOptions = {}
): Promise<T> {
  const {
    maxAttempts = 3,
    delayMs = 1000,
    backoffMultiplier = 2,
    maxDelayMs = 10000,
    onRetry
  } = options;

  let lastError: Error;
  let currentDelay = delayMs;

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error instanceof Error ? error : new Error(String(error));

      if (attempt === maxAttempts) {
        break;
      }

      // 通知重试回调
      if (onRetry) {
        onRetry(attempt, lastError);
      }

      // 等待后重试
      await new Promise(resolve => setTimeout(resolve, currentDelay));

      // 增加延迟（指数退避）
      currentDelay = Math.min(currentDelay * backoffMultiplier, maxDelayMs);
    }
  }

  throw lastError!;
}

/**
 * R2 操作重试包装
 * 
 * @param operation 操作名称
 * @param fn R2 操作函数
 * @returns 操作结果
 */
export async function retryR2Operation<T>(
  operation: string,
  fn: () => Promise<T>
): Promise<T> {
  return retryAsync(fn, {
    maxAttempts: 3,
    delayMs: 500,
    backoffMultiplier: 2,
    onRetry: (attempt, error) => {
      debugLog(`[R2重试] ${operation} - 第 ${attempt} 次重试:`, error.message);
    }
  });
}

/**
 * D1 操作重试包装
 * 
 * @param operation 操作名称
 * @param fn D1 操作函数
 * @returns 操作结果
 */
export async function retryD1Operation<T>(
  operation: string,
  fn: () => Promise<T>
): Promise<T> {
  return retryAsync(fn, {
    maxAttempts: 3,
    delayMs: 1000,
    backoffMultiplier: 2,
    onRetry: (attempt, error) => {
      debugLog(`[D1重试] ${operation} - 第 ${attempt} 次重试:`, error.message);
    }
  });
}

