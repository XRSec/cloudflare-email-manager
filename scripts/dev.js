#!/usr/bin/env node

/**
 * 开发环境启动脚本
 * 同时启动前端和后端开发服务器
 */

import { spawn } from 'child_process';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { getEnvironmentInfo, isEnvironmentAvailable } from './env-detector.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const projectRoot = join(__dirname, '..');

// 启动前端
function startFrontend() {
  console.log('🚀 启动前端开发服务器 (端口 3000)...');
  const frontend = spawn('npx', ['vite'], {
    cwd: join(projectRoot, 'frontend'),
    stdio: 'inherit',
    shell: true
  });

  return frontend;
}

// 启动后端
function startBackend() {
  const envInfo = getEnvironmentInfo();
  console.log(`🔧 启动 Worker 开发服务器 (端口 8787) - ${envInfo.description}...`);

  if (envInfo.isLocal) {
    // 本地环境：使用 Docker 容器运行 wrangler（因为本地 wrangler 有兼容性问题）
    const backend = spawn('docker', ['exec', '-it ', 'node', 'bash', '-c', 'cd worker && npx wrangler dev'], {
      stdio: 'inherit',
      shell: true
    });
    return backend;
  } else {
    // Docker 环境：直接在容器内运行 wrangler
    const backend = spawn('npx', ['wrangler', 'dev'], {
      cwd: join(projectRoot, 'worker'),
      stdio: 'inherit',
      shell: true
    });
    return backend;
  }
}

// 主函数
function main() {
  // 检查环境是否可用
  if (!isEnvironmentAvailable()) {
    console.error('❌ 环境不可用，请检查 wrangler 安装或 Docker 容器状态');
    process.exit(1);
  }

  const envInfo = getEnvironmentInfo();
  console.log(`🚀 启动开发环境 (${envInfo.description})...`);

  const frontend = startFrontend();
  const backend = startBackend();

  // 处理退出信号
  const handleSignal = (signal) => {
    console.log(`\n🛑 收到 ${signal} 信号，正在停止开发服务器...`);
    frontend.kill(signal);
    backend.kill(signal);
    process.exit(0);
  };

  process.on('SIGINT', handleSignal);
  process.on('SIGTERM', handleSignal);

  // 处理进程退出
  frontend.on('exit', (code) => {
    console.log(`前端进程退出，代码: ${code}`);
    if (backend && !backend.killed) {
      backend.kill();
    }
  });

  backend.on('exit', (code) => {
    console.log(`后端进程退出，代码: ${code}`);
    if (frontend && !frontend.killed) {
      frontend.kill();
    }
  });

  // 处理进程错误
  frontend.on('error', (error) => {
    console.error('❌ 前端进程错误:', error.message);
    if (backend && !backend.killed) {
      backend.kill();
    }
  });

  backend.on('error', (error) => {
    console.error('❌ 后端进程错误:', error.message);
    if (frontend && !frontend.killed) {
      frontend.kill();
    }
  });
}

main();
