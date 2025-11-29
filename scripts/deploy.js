#!/usr/bin/env node

/**
 * 完整的部署脚本
 * 包含资源创建、构建、部署到 Cloudflare 的完整流程
 */

import {spawn, execSync} from 'child_process';
import {fileURLToPath} from 'url';
import {dirname, join} from 'path';
import {readFileSync, writeFileSync, existsSync, copyFileSync} from 'fs';
import {createHash, randomBytes} from 'crypto';
import {createInterface} from 'readline';
import {parse, stringify} from '@iarna/toml';
import {isEnvironmentAvailable} from './env-detector.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const projectRoot = join(__dirname, '..');

// ================== 🎨 颜色定义 ==================
const RED = "\x1b[31m";
const GREEN = "\x1b[32m";
const YELLOW = "\x1b[33m";
const BLUE = "\x1b[34m";
const NC = "\x1b[0m"; // Reset

function log(type, msg) {
    const colors = {error: RED, success: GREEN, warn: YELLOW, info: BLUE};
    console.log(`${colors[type] || NC}${msg}${NC}`);
}

// ================== 🔧 工具函数 ==================
function run(exec, stdio = ["pipe", "pipe", "pipe"]) {
    let output, err;
    try {
        output = execSync(exec, {encoding: "utf-8", stdio});
    } catch (err1) {
        try {
            output = execSync(exec, {encoding: "utf-8", stdio});
        } catch (err2) {
            err = err2;
            if (err2 && err2?.stdout?.includes("Authentication error")) {
                try {
                    output = execSync(exec, {encoding: "utf-8", stdio});
                } catch (err3) {
                    err = err3;
                }
            }
        }
    }
    return {output, err};
}

// ================== 📦 资源创建 ==================
function createOrGetResource(type, name) {
    let id = "";
    let {output, err} = run(`wrangler ${type} create ${name}`);

    if (err?.stderr.includes("already exists") || err?.stdout.includes("already exists")) {
        const {
            output: listOutput,
            err: err1
        } = run(`wrangler ${type} list ${type === "d1" ? "--json" : ""} ${type === "r2 bucket" ? "" : "| jq -c '.'"}`)
        err1 && process.exit(1)
        if (type === "r2 bucket") {
            id = name
        } else {
            const jsonStr = listOutput.split('\n').filter(l => l.trim().startsWith('[') || l.trim().startsWith('{')).join('\n');
            const jsonList = JSON.parse(jsonStr);
            id = type === "d1"
                ? jsonList.find(d1 => d1.name === name)?.uuid
                : jsonList.find(k => k.title === name)?.id;
        }
        log("warn", `⚠️ ${type} ${name} 已存在 ${id}`);
        return id;
    } else if (err) {
        log("error", `❌ ${type} 创建失败, ${err}`);
        console.log(`stdout: ${err?.stdout}`)
        console.log(`stderr: ${err?.stderr}`)
        process.exit(1);
    }
    const match = output.match(/id = "([^"]+)"/);
    if (match) id = match[1];
    log("success", `✅ ${type} 创建成功: ${type === "r2" ? id : name}`);
    return id;
}

// ================== 🔨 构建函数 ==================
async function buildvue() {
    console.log('🔨 构建前端...');
    return new Promise((resolve, reject) => {
        const build = spawn('npx', ['vite', 'build'], {
            cwd: join(projectRoot, 'vue'),
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

// ================== 📝 配置文件更新 ==================
function updateWranglerToml(dbId, kvId, devMode) {
    const wranglerPath = join(projectRoot, 'wrangler.toml');
    const examplePath = join(projectRoot, 'wrangler.example.toml');

    if (!existsSync(wranglerPath)) {
        if (existsSync(examplePath)) {
            copyFileSync(examplePath, wranglerPath);
        } else {
            log("error", "❌ 找不到 wrangler.example.toml 文件");
            process.exit(1);
        }
    }

    try {
        // 读取并解析 TOML 文件
        const tomlContent = readFileSync(wranglerPath, 'utf-8');
        const config = parse(tomlContent);

        if (devMode) {
            // 开发环境：更新 env.dev 部分的配置
            if (!config.env || !config.env.dev) {
                log("error", "❌ 配置文件中缺少 [env.dev] 段");
                process.exit(1);
            }

            // 更新开发环境 D1 数据库 ID
            if (config.env.dev.d1_databases?.[0]) {
                config.env.dev.d1_databases[0].database_id = dbId;
            } else {
                log("warn", "⚠️ 开发环境 D1 数据库配置不存在，跳过更新");
            }

            // 更新开发环境 KV 命名空间 ID
            if (config.env.dev.kv_namespaces?.[0]) {
                config.env.dev.kv_namespaces[0].id = kvId;
            } else {
                log("warn", "⚠️ 开发环境 KV 命名空间配置不存在，跳过更新");
            }

            log("info", `🔧 更新开发环境配置: D1=${dbId}, KV=${kvId}`);
        } else {
            // 生产环境：更新主配置部分
            // 更新生产环境 D1 数据库 ID
            if (config.d1_databases?.[0]) {
                config.d1_databases[0].database_id = dbId;
            } else {
                log("warn", "⚠️ 生产环境 D1 数据库配置不存在，跳过更新");
            }

            // 更新生产环境 KV 命名空间 ID
            if (config.kv_namespaces?.[0]) {
                config.kv_namespaces[0].id = kvId;
            } else {
                log("warn", "⚠️ 生产环境 KV 命名空间配置不存在，跳过更新");
            }

            log("info", `🔧 更新生产环境配置: D1=${dbId}, KV=${kvId}`);
        }

        // 将配置写回文件
        const updatedTomlContent = stringify(config);
        writeFileSync(wranglerPath, updatedTomlContent);

        // 验证更新是否成功
        const verifyConfig = parse(updatedTomlContent);
        if (devMode) {
            const devDbId = verifyConfig.env?.dev?.d1_databases?.[0]?.database_id;
            const devKvId = verifyConfig.env?.dev?.kv_namespaces?.[0]?.id;
            if (devDbId === dbId && devKvId === kvId) {
                log("success", `✅ 已更新 wrangler.toml (开发环境)`);
            } else {
                log("error", `❌ 配置更新验证失败`);
                process.exit(1);
            }
        } else {
            const prodDbId = verifyConfig.d1_databases?.[0]?.database_id;
            const prodKvId = verifyConfig.kv_namespaces?.[0]?.id;
            if (prodDbId === dbId && prodKvId === kvId) {
                log("success", `✅ 已更新 wrangler.toml (生产环境)`);
            } else {
                log("error", `❌ 配置更新验证失败`);
                process.exit(1);
            }
        }

    } catch (error) {
        log("error", `❌ 解析 TOML 文件失败: ${error.message}`);
        process.exit(1);
    }
}

// ================== 🚀 部署函数 ==================
async function deploy(devMode) {
    console.log(`🚀 部署到 Cloudflare...`);

    return new Promise((resolve, reject) => {
        const deployArgs = ['wrangler', 'deploy'];
        if (devMode) {
            deployArgs.push('--env', 'dev');
        }

        const deployCmd = spawn('npx', deployArgs, {
            cwd: join(projectRoot, 'worker'),
            stdio: 'inherit',
            shell: true
        });

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

// ================== 🔑 用户交互 ==================
function createReadlineInterface() {
    return createInterface({
        input: process.stdin,
        output: process.stdout,
    });
}

function question(query) {
    return new Promise(resolve => {
        const rl = createReadlineInterface();
        rl.question(query, ans => {
            rl.close();
            resolve(ans);
        });
    });
}

// ================== 🗑️ 删除所有资源 ==================
function deleteAll() {
    log("warn", "🗑️ 删除所有 Cloudflare 资源...");
    run(`for name in $(wrangler d1 list --json | jq -r '.[].name'); do wrangler d1 delete "$name" -y; done`, "inherit");
    run(`for id in $(wrangler kv namespace list | jq -r '.[].id'); do wrangler kv namespace delete --namespace-id "$id"; done`, "inherit");
    run(`for name in $(wrangler r2 bucket list | awk '/^name:/ {print $2}'); do wrangler r2 bucket delete "$name"; done`, "inherit");
    log("success", "✅ 所有资源已删除");
    process.exit(0);
}

// ================== 🎯 主函数 ==================
async function main() {
    try {
        // 检查是否是删除所有资源的命令
        const target = process.argv[2] || "";
        if (target === "deleteAll") {
            deleteAll();
        }

        console.log('👋 欢迎使用 CEM (Cloud Email Manager) 部署脚本');

        // 检查环境
        if (!isEnvironmentAvailable()) {
            console.error('❌ 环境不可用，请检查本地 wrangler 安装状态');
            process.exit(1);
        }

        // 检查 wrangler 登录状态
        log("info", "🔐 检查 Cloudflare 登录状态...");
        const {output, err: err1} = run("wrangler whoami");
        if (err1) {
            log("error", `❌ 检查 Cloudflare 登录状态失败: ${err1}`);
            process.exit(1);
        }
        if (output.includes("You are not authenticated")) {
            log("warn", "⚠️  未登录 Cloudflare，正在启动登录流程...");
            run("wrangler login", "inherit");
        } else {
            log("success", "✅ 已登录 Cloudflare");
        }

        // 获取用户输入
        const dev_input = (await question(`是否开发模式? (y/n) [n]: `)).trim() || 'n';
        const devMode = /^[Yy]$/.test(dev_input);
        const DB_NAME = devMode ? 'cem-db-dev' : 'cem-db';
        const KV_NAME = devMode ? 'cem-kv-dev' : 'cem-kv';
        const BUCKET_NAME = devMode ? 'cem-r2-dev' : 'cem-r2';

        devMode && log("info", "🚧 开发模式");

        // 创建资源
        log("info", "📦 创建 / 获取资源...");
        const dbId = createOrGetResource("d1", DB_NAME);
        const kvId = createOrGetResource("kv namespace", KV_NAME);
        createOrGetResource("r2 bucket", BUCKET_NAME);

        // 更新配置文件
        log("info", "📝 更新 wrangler.toml ...");
        updateWranglerToml(dbId, kvId, devMode);

        // 初始化数据库
        log("info", "🗄️ 初始化数据库结构 (schema.sql)...");
        const {err: err2} = run(`wrangler d1 execute ${DB_NAME} --file=./db/schema.sql --remote`);
        if (err2) {
            log("error", `❌ 初始化数据库结构失败: ${err2}`);
            process.exit(1);
        }
        log("success", "✅ 数据库结构已初始化");
        log("success", "✅ 默认用户 admin/123456");

        // 构建和部署
        await buildvue();
        await buildBackend();
        await deploy(devMode);

        // 完成信息
        log("success", "🎉 部署完成");
        log("info", "📋 部署信息:");
        devMode && log("info", "  🚧 开发模式");
        log("info", `  D1 数据库 ID: ${dbId}`);
        log("info", `  KV 命名空间 ID: ${kvId}`);
        log("info", `  R2 存储桶: ${BUCKET_NAME}\n`);
        log("warn", "重要提醒:");
        log("info", "1. 请在 Cloudflare 控制台配置邮件路由");
        log("info", "2. 记得修改默认密码 admin/123456\n");
        log("success", "🌐 访问地址:");

        if (devMode) {
            log("info", "  开发环境: http://localhost:8787");
            log("info", "  启动开发服务器: npm run dev");
            log("info", "  使用开发环境资源: wrangler dev --env dev");
        } else {
            log("info", `  Worker 地址: https://cem.workers.dev`);
            log("info", "  使用生产环境资源: wrangler dev");
        }

        log("info", "\n📋 配置说明:");
        log("info", "  [dev] 段: 本地开发服务器配置 (端口 8787)");
        log("info", "  [triggers] 段: 定时任务配置");
        log("info", "  [observability] 段: 可观测性配置 (全局)");
        log("info", "  [env.dev] 段: 开发环境资源绑定");

        log("info", "\n📚 更多信息请查看 README.md");

    } catch (error) {
        console.error('❌ 部署失败:', error.message);
        process.exit(1);
    }
}

main();
