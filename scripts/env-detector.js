#!/usr/bin/env node

/**
 * 环境检测模块
 * 提供统一的环境检测功能
 */

import { execSync } from 'child_process';

/**
 * 检查环境是否可用
 * @returns {boolean} 环境是否可用
 */
export function isEnvironmentAvailable() {
  try {
    execSync('npx --version', { stdio: 'ignore' });
    execSync('wrangler --version', { stdio: 'ignore' });
    return true;
  } catch (e) {
    return false;
  }
}
