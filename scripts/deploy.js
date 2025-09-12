#!/usr/bin/env node

/**
 * 部署脚本
 * 构建前端和后端，然后部署到 Cloudflare
 */

import { spawn } from 'child_process';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { getEnvironmentInfo, isEnvironmentAvailable } from './env-detector.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const projectRoot = join(__dirname, '..');

// 构建前端
async function buildFrontend() {
  console.log('🔨 构建前端...');
  return new Promise((resolve, reject) => {
    const build = spawn('npx', ['vite', 'build'], {
      cwd: join(projectRoot, 'frontend'),
      stdio: 'inherit',
      shell: true
    });

    build.on('exit', (code) => {
      if (code === 0) {
        console.log('✅ 前端构建完成');
        resolve();
      } else {
        reject(new Error(`前端构建失败，代码: ${code}`));
      }
    });
  });
}

// 构建后端
async function buildBackend() {
  console.log('🔨 构建后端...');
  return new Promise((resolve, reject) => {

    const build = spawn('npx', ['tsc'], {
      cwd: join(projectRoot, 'worker'),
      stdio: 'inherit',
      shell: true
    });

    build.on('exit', (code) => {
      if (code === 0) {
        console.log('✅ 后端构建完成');
        resolve();
      } else {
        reject(new Error(`后端构建失败，代码: ${code}`));
      }
    });
  });
}

// 部署到 Cloudflare
async function deploy() {
  const envInfo = getEnvironmentInfo();
  console.log(`🚀 部署到 Cloudflare (${envInfo.description})...`);

  return new Promise((resolve, reject) => {
    let deployCmd;

    if (envInfo.isLocal) {
      deployCmd = spawn('npx', ['wrangler', 'deploy'], {
        cwd: join(projectRoot, 'worker'),
        stdio: 'inherit',
        shell: true
      });
    } else {
      // Docker 环境（使用 --net=host，路径映射到宿主机）
      deployCmd = spawn('docker', ['exec', 'node', 'bash', '-c', `cd worker && npx wrangler deploy`], {
        stdio: 'inherit',
        shell: true
      });
    }

    deployCmd.on('exit', (code) => {
      if (code === 0) {
        console.log('✅ 部署完成');
        resolve();
      } else {
        reject(new Error(`部署失败，代码: ${code}`));
      }
    });
  });
}

// 主函数
async function main() {
  try {
    // 检查环境是否可用
    if (!isEnvironmentAvailable()) {
      console.error('❌ 环境不可用，请检查 wrangler 安装或 Docker 容器状态');
      process.exit(1);
    }

    const envInfo = getEnvironmentInfo();
    console.log(`🔧 检测到环境: ${envInfo.description}`);

    await buildFrontend();
    await buildBackend();
    await deploy();
    console.log('🎉 部署成功！');
  } catch (error) {
    console.error('❌ 部署失败:', error.message);
    process.exit(1);
  }
}

main();
