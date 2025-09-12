/**
 * 因为 wrangler 不在支持 macOS Ventura 所以下下策 不安装 Linux 的 wrangler 到 node_modules
 */
import { execSync } from 'child_process';
import os from 'os';

const platform = os.platform(); // 'darwin', 'linux', 'win32'

if (platform === 'darwin') {
  console.log('macOS detected, installing wrangler...');
  execSync('npm install wrangler --no-save --no-package-lock', { stdio: 'inherit' });
} else {
  execSync('npm install -g wrangler', { stdio: 'inherit' });
  console.log(`Platform is ${platform}, skipping wrangler install.`);
}
