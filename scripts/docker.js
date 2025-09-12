#!/usr/bin/env node

/**
 * Docker 容器管理脚本
 * 智能管理 node 容器的创建、启动、停止
 */

import { spawn, execSync } from 'child_process';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const projectRoot = join(__dirname, '..');

// 检查容器是否存在
function checkContainerExists() {
  try {
    execSync('docker ps -a | grep -q "node"', { stdio: 'ignore' });
    return true;
  } catch (e) {
    return false;
  }
}

// 检查容器是否运行
function checkContainerRunning() {
  try {
    execSync('docker ps | grep -q "node"', { stdio: 'ignore' });
    return true;
  } catch (e) {
    return false;
  }
}

// 检查镜像是否存在
function checkImageExists() {
  try {
    execSync('docker images | grep -q "node.*cem"', { stdio: 'ignore' });
    return true;
  } catch (e) {
    return false;
  }
}

// 构建镜像
async function buildImage() {
  console.log('🔨 构建 Docker 镜像...');
  return new Promise((resolve, reject) => {
    const build = spawn('docker', ['build', '-t', 'node:cem', '--progress=plain', '.'], {
      cwd: projectRoot,
      stdio: 'inherit',
      shell: true
    });

    build.on('exit', (code) => {
      if (code === 0) {
        console.log('✅ 镜像构建完成');
        resolve();
      } else {
        reject(new Error(`镜像构建失败，代码: ${code}`));
      }
    });
  });
}

// 创建并启动容器
async function createContainer() {
  console.log('🚀 创建并启动 node 容器...');
  return new Promise((resolve, reject) => {
    const run = spawn('docker', [
      'run', '-itd', '--name', 'node',
      '-v', `${process.cwd()}/:${process.cwd()}`,
      '-w', process.cwd(),
      '--net=host',
      'node:cem'
    ], {
      stdio: 'inherit',
      shell: true
    });

    run.on('exit', async (code) => {
      if (code === 0) {
        console.log('✅ 容器创建并启动成功');
        // 在容器内安装依赖
        try {
          await startDevServerInContainer();
          resolve();
        } catch (error) {
          reject(error);
        }
      } else {
        reject(new Error(`容器创建失败，代码: ${code}`));
      }
    });
  });
}

// 在容器内启动开发服务器
async function startDevServerInContainer() {
  console.log('🚀 在容器内启动开发服务器...');
  return new Promise((resolve, reject) => {
    // 使用 npx 运行，不需要本地 node_modules
    const dev = spawn('docker', ['exec', 'node', 'bash', '-c', 'npx --yes concurrently "cd frontend && npm run dev" "cd worker && npx wrangler dev"'], {
      stdio: 'inherit',
      shell: true
    });

    // 处理 Ctrl+C 信号
    const handleSignal = (signal) => {
      console.log(`\n🛑 收到 ${signal} 信号，正在停止开发服务器...`);
      dev.kill(signal);
    };

    // 监听退出信号
    process.on('SIGINT', handleSignal);
    process.on('SIGTERM', handleSignal);

    dev.on('exit', (code) => {
      // 清理信号监听器
      process.removeListener('SIGINT', handleSignal);
      process.removeListener('SIGTERM', handleSignal);

      if (code === 0) {
        console.log('✅ 开发服务器正常退出');
        resolve();
      } else if (code === null) {
        console.log('🛑 开发服务器被强制停止');
        resolve();
      } else {
        console.log(`❌ 开发服务器异常退出，代码: ${code}`);
        reject(new Error(`开发服务器启动失败，代码: ${code}`));
      }
    });

    // 处理进程错误
    dev.on('error', (error) => {
      console.error('❌ 开发服务器进程错误:', error.message);
      process.removeListener('SIGINT', handleSignal);
      process.removeListener('SIGTERM', handleSignal);
      reject(error);
    });
  });
}

// 启动现有容器
async function startContainer() {
  console.log('▶️ 启动现有 node 容器...');
  return new Promise((resolve, reject) => {
    const start = spawn('docker', ['start', 'node'], {
      stdio: 'inherit',
      shell: true
    });

    start.on('exit', (code) => {
      if (code === 0) {
        console.log('✅ 容器启动成功');
        resolve();
      } else {
        reject(new Error(`容器启动失败，代码: ${code}`));
      }
    });
  });
}

// 停止容器
async function stopContainer() {
  console.log('⏹️ 停止 node 容器...');
  return new Promise((resolve, reject) => {
    const stop = spawn('docker', ['stop', 'node'], {
      stdio: 'inherit',
      shell: true
    });

    stop.on('exit', (code) => {
      if (code === 0) {
        console.log('✅ 容器已停止');
        resolve();
      } else {
        reject(new Error(`容器停止失败，代码: ${code}`));
      }
    });
  });
}

// 删除容器
async function removeContainer() {
  console.log('🗑️ 删除 node 容器...');
  return new Promise((resolve, reject) => {
    const rm = spawn('docker', ['rm', 'node'], {
      stdio: 'inherit',
      shell: true
    });

    rm.on('exit', (code) => {
      if (code === 0) {
        console.log('✅ 容器已删除');
        resolve();
      } else {
        reject(new Error(`容器删除失败，代码: ${code}`));
      }
    });
  });
}

// 显示容器状态
function showStatus() {
  console.log('📊 容器状态:');
  try {
    const output = execSync('docker ps -a | grep node', { encoding: 'utf-8' });
    console.log(output);
  } catch (e) {
    console.log('❌ 没有找到 node 容器');
  }
}

// 主函数
async function main() {
  const command = process.argv[2];

  try {
    switch (command) {
      case 'start':
        if (!checkImageExists()) {
          await buildImage();
        }
        if (checkContainerExists()) {
          if (checkContainerRunning()) {
            console.log('✅ 容器已在运行');
          } else {
            await startContainer();
          }
        } else {
          await createContainer();
        }
        break;

      case 'stop':
        if (checkContainerExists()) {
          await stopContainer();
        } else {
          console.log('❌ 容器不存在');
        }
        break;

      case 'restart':
        if (checkContainerExists()) {
          await stopContainer();
          await startContainer();
        } else {
          console.log('❌ 容器不存在，请先创建');
        }
        break;

      case 'remove':
        if (checkContainerExists()) {
          await stopContainer();
          await removeContainer();
        } else {
          console.log('❌ 容器不存在');
        }
        break;

      case 'status':
        showStatus();
        break;

      case 'build':
        await buildImage();
        break;

      default:
        console.log(`
🐳 Docker 容器管理脚本

用法:
  node scripts/docker.js <command>

命令:
  start     启动容器（如果不存在则创建）
  stop      停止容器
  restart   重启容器
  remove    删除容器
  status    显示容器状态
  build     构建镜像

示例:
  node scripts/docker.js start
  node scripts/docker.js status
  node scripts/docker.js stop
`);
    }
  } catch (error) {
    console.error('❌ 操作失败:', error.message);
    process.exit(1);
  }
}

main();
