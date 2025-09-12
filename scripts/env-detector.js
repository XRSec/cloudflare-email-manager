#!/usr/bin/env node

/**
 * 环境检测模块
 * 提供统一的环境检测功能
 */

import { execSync } from 'child_process';
import { join } from 'path';
import fs from 'fs';

/**
 * 检测当前运行环境
 * @returns {string} 'local' | 'docker'
 */
export function detectEnvironment() {
  // 检查是否在 Docker 容器内
  if (process.env.DOCKER_CONTAINER === 'true' || fs.existsSync('/.dockerenv')) {
    return 'docker';
  }
  return 'local'
}


/**
 * 获取环境信息
 * @returns {object} 环境信息对象
 */
export function getEnvironmentInfo() {
  const env = detectEnvironment();
  return {
    type: env,
    isLocal: env === 'local',
    isDocker: env === 'docker',
    description: env === 'local' ? '本地环境' : 'Docker 环境'
  };
}

/**
 * 检查环境是否可用
 * @returns {boolean} 环境是否可用
 */
export function isEnvironmentAvailable() {
  try {
    const env = detectEnvironment();
    if (env === 'local') {
      // 本地环境：检查 Docker 容器是否运行（因为本地 wrangler 有兼容性问题）
      execSync('docker ps | grep -q "node"', { stdio: 'ignore' });
      return true;
    } else {
      // Docker 环境：检查 npx 是否可用
      execSync('npx --version', { stdio: 'ignore' });
      return true;
    }
  } catch (e) {
    return false;
  }
}
