#!/usr/bin/env node

const os = require("os")
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const {execSync} = require('child_process');
const toml = require('@iarna/toml');
const readline = require('readline');

// ================== 🎨 颜色定义 ==================
const RED = "\x1b[31m";
const GREEN = "\x1b[32m";
const YELLOW = "\x1b[33m";
const BLUE = "\x1b[34m";
const NC = "\x1b[0m"; // Reset
let DB_NAME;
let KV_NAME;
let BUCKET_NAME;

function log(type, msg) {
    const colors = {error: RED, success: GREEN, warn: YELLOW, info: BLUE};
    console.log(`${colors[type] || NC}${msg}${NC}`);
}

// ================== ✅ 检查 wrangler 是否安装 ==================
function checkWrangler() {
    try {
        execSync("wrangler --version", {encoding: 'utf-8', stdio: ["pipe", "pipe", "pipe"]});
        log("success", "✅ Wrangler 已安装");
    } catch {
        log("error", "❌ Wrangler CLI 未安装");
        console.log("请运行: npm install -g wrangler");
        process.exit(1);
    }
}

// ================== ⚙️ 环境变量 ==================
let DOMAIN = process.env.DOMAIN
let ENVIRONMENT = process.env.ENVIRONMENT

// ================== 🔑 管理员密码输入 ==================
const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
});

function question(query) {
    return new Promise(resolve => rl.question(query, ans => resolve(ans)));
}

function askPassword() {
    return new Promise((resolve) => {
        rl.question("请输入管理员密码: ", (password) => {
            rl.close();
            resolve(password);
        });
    });
}

// ================== 📦 资源创建通用函数 ==================
function createOrGetResource(type, name) {
    let id = "";
    try {
        const output = execSync(`wrangler ${type} create ${name}`, {
            encoding: 'utf-8',
            stdio: ["pipe", "pipe", "pipe"]
        });
        const match = output.match(/id = "([^"]+)"/);
        if (match) id = match[1];
        log("success", `✅ ${type} 创建成功: ${id}`);
    } catch (err) {
        if (err.stdout.includes("already exists") || err.stderr.includes("already exists")) {
            const listOutput = execSync(`wrangler ${type} list`, {
                encoding: 'utf-8',
                stdio: ["pipe", "pipe", "pipe"]
            });
            // const match = listOutput.match(new RegExp(`│\\s*([a-f0-9-]{36})\\s*│\\s*${DB_NAME}\\s*│`));

            if (type === "d1") {
                const match = listOutput.match(`│\\s*([a-f0-9-]{36})\\s*│\\s*${name}\\s*│`);
                if (match) id = match[1];
            } else if (type === "kv namespace") {
                const kvList = JSON.parse(listOutput);
                const kv = kvList.find(k => k.title === name);
                if (kv) id = kv.id
            } else if (type === "r2 bucket") {
                id = BUCKET_NAME
                // const match = listOutput.match(/name:\s+(\S+)[\s\S]*?creation_date:\s+(\S+)/);
                // if (match) id = match[1];
            }
            log("warn", `⚠️  ${type} ${name} 已存在 ${id}`);
        } else {
            log("error", `❌ ${type} 创建失败, ${err}`);
            // console.error(err.stdout || err.message);
            process.exit(1);
        }
    }
    return id;
}

// ================== 📝 wrangler.toml 更新 ==================
function updateWranglerToml(configPath, dbId, kvId, JWT_SECRET) {
    let config = {};
    if (fs.existsSync(configPath)) {
        config = toml.parse(fs.readFileSync(configPath, "utf-8"));
    }

    // 确保 env.production 存在
    config.env = config.env || {};
    config.env[ENVIRONMENT] = config.env[ENVIRONMENT] || {};

    // 配置 D1
    config.env[ENVIRONMENT].vars.DOMAIN = DOMAIN
    config.env[ENVIRONMENT].vars.JWT_SECRET ||= JWT_SECRET // 避免总是更新

    // 配置 D1
    config.env[ENVIRONMENT].d1_databases = [
        {
            binding: "DB",
            database_id: dbId,
            database_name: DB_NAME,
        },
    ];

    // 配置 KV
    config.env[ENVIRONMENT].kv_namespaces = [
        {
            binding: "KV",
            id: kvId,
        },
    ];

    // 配置 R2
    config.env[ENVIRONMENT].r2_buckets = [
        {
            binding: "R2",
            bucket_name: BUCKET_NAME,
        },
    ];

    fs.writeFileSync(configPath, toml.stringify(config));
    log("success", `✅ 已更新 ${configPath}`);
}

// ================== 🚀 部署流程 ==================
async function main() {
    console.log('👋 欢迎使用 CEM (Cloud Email Manager)')
    checkWrangler()
    log("info", "🔐 检查 Cloudflare 登录状态...");
    try {
        // execSync("wrangler whoami", {encoding: 'utf-8',});
        execSync("wrangler whoami", {encoding: 'utf-8', stdio: ["pipe", "pipe", "pipe"]});
        log("success", "✅ 已登录 Cloudflare");
    } catch {
        log("warn", "⚠️  未登录 Cloudflare，正在启动登录流程...");
        execSync("wrangler login", {encoding: 'utf-8', stdio: "inherit"});
    }

    DOMAIN ||= (await question('请输入您的域名 (例如: example.com): ')).trim() || 'doubi.tech';
    ENVIRONMENT ||= (await question('请输入环境 (development/production) [production]: ')).trim() || 'production';
    DB_NAME = `${ENVIRONMENT}-cem-db`;
    KV_NAME = `${ENVIRONMENT}-cem-kv`;
    BUCKET_NAME = `${ENVIRONMENT}-cem-r2`;

    log("info", `📋 部署配置:`);
    log("info", `  域名: ${DOMAIN}`);
    log("info", `  环境: ${ENVIRONMENT}`);

    // 生成 JWT
    const JWT_SECRET = crypto.randomBytes(32).toString('base64');
    log("warn", `🔑 生成的 JWT 密钥: ${JWT_SECRET} （请妥善保存）`);

    log("info", "📦 创建 / 获取资源...");
    const dbId = createOrGetResource("d1", DB_NAME);
    const kvId = createOrGetResource("kv namespace", KV_NAME);
    createOrGetResource("r2 bucket", BUCKET_NAME);

    log("info", "📝 更新 wrangler.toml ...");
    updateWranglerToml("wrangler.toml", dbId, kvId, JWT_SECRET);

    const ADMIN_PREFIX = (await question('请输入管理员邮箱前缀 (例如: admin) [admin]: ')).trim() || 'admin';
    const ADMIN_PASSWORD = await askPassword();
    const ADMIN_PASSWORD_HASH = crypto
        .createHash("sha256")
        .update(String(ADMIN_PASSWORD))
        .digest("hex");

    log("info", "👤 初始化管理员账户...");
    try {
        execSync(
            `wrangler d1 execute ${DB_NAME} --command="INSERT INTO users (email_prefix, email_password, user_type) VALUES ('${ADMIN_PREFIX}', '${ADMIN_PASSWORD_HASH}', 'admin')" --env=${ENVIRONMENT}`,
            {encoding: 'utf-8', stdio: ["pipe", "pipe", "pipe"]}
        );
        log("success", "✅ 管理员账户已创建");
    } catch (err) {
        if (err.stdout && err.stdout.includes("UNIQUE constraint failed")) {
            log("warn", "⚠️  管理员账户已存在");
        } else {
            log("error", `❌ 管理员账户创建失败 ${err}`);
        }
    }

    log("success", "🎉 部署完成！");
}

main();
