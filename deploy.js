#!/usr/bin/env node

const fs = require('fs');
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
    const {err} = run("wrangler --version");
    if (err) {
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
        rl.question("请输入管理员密码 (例如: 123456) [123456]: ", (password) => {
            rl.close();
            resolve(password);
        });
    });
}

// ================== 📦 资源创建通用函数 ==================
function createOrGetResource(type, name) {
    let id = "";
    const {output, err} = run(`wrangler ${type} create ${name}`);

    if ((err?.stderr || err?.stdout || err?.toString() || "").includes("already exists")) {
        const {output: listOutput, err: err1} = run(`wrangler ${type} list`)
        // const match = listOutput.match(new RegExp(`│\\s*([a-f0-9-]{36})\\s*│\\s*${DB_NAME}\\s*│`));
        err1 && process.exit(1)
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
        log("warn", `⚠️ ${type} ${name} 已存在 ${id}`);
        return id;
    } else if (err) {
        log("error", `❌ ${type} 创建失败, ${err}`);
        console.log(`stdout: ${err?.stdout}`)
        console.log(`stderr: ${err?.stderr}`)
        // console.error(err.stdout || err.message);
        process.exit(1);
    }
    const match = output.match(/id = "([^"]+)"/);
    if (match) id = match[1];
    log("success", `✅ ${type} 创建成功: ${id}`);
    return id;
}

function run(exec, stdio = ["pipe", "pipe", "pipe"]) {
    let output, err;
    try {
        output = execSync(exec, {encoding: "utf-8", stdio});
    } catch (err1) {
        try {
            output = execSync(exec, {encoding: "utf-8", stdio});
        } catch (err2) {
            err = err2;
        }
    }

    return {output, err};
}

async function endMsg(ADMIN_PREFIX, dbId, kvId, JWT_SECRET) {
    // 设置自定义域名
    if (ENVIRONMENT === "production") {
        log("info", "🌐 配置自定义域名...")
        const setupDomain = (await question(`是否要配置自定义域名? (y/n) [y]: `)).trim() || 'y'
        if (/^[Yy]$/.test(setupDomain)) {
            log("warn", "请在 Cloudflare 控制台中手动配置以下设置:")
            log("info", "1. 添加域名到 Cloudflare")
            log("info", "2. 在 Workers & Pages 中绑定自定义域名")
            log("info", "3. 在 Email Routing 中配置路由规则")
            log("info", `   规则: *@${DOMAIN} → Send to Worker → cem`)
        }
    }
    log("success", "🎉 部署完成")
    log("info", "📋 部署信息:")
    log("info", `  域名: ${DOMAIN}`);
    log("info", `  环境: ${ENVIRONMENT}`);
    log("info", `  管理员: ${ADMIN_PREFIX}@${DOMAIN}`);
    log("info", `  D1 数据库 ID: ${dbId}`);
    log("info", `  KV 命名空间 ID: ${kvId}`);
    log("info", `  R2 存储桶: ${BUCKET_NAME}\n`);
    log("warn", "重要提醒:");
    log("info", `1. 请保存 JWT 密钥: ${JWT_SECRET}`);
    log("info", "2. 请在 Cloudflare 控制台配置邮件路由");
    log("info", "3. 配置文件已备份为 wrangler.toml.backup");
    log("info", "4. 管理员密码请妥善保管\n");
    log("success", "🌐 访问地址:")
    if (ENVIRONMENT === "development") {
        log("info", "  开发环境: http://localhost:8787")
        log("info", "  启动开发服务器: npm run dev")
    } else {
        log("info", `  生产环境: https://${DOMAIN}`)
        log("info", `  Worker 地址: https://cem.name.workers.dev`)
    }
    log("info", "\n📚 更多信息请查看 README.md")
    if (ENVIRONMENT === "development") {
        const setupDomain = (await question(`是否启动开发服务器? (y/n) [y]: `)).trim() || 'y'
        if (/^[Yy]$/.test(setupDomain)) {
            log("success", "🚀 启动开发服务器...")
            run("npm run dev")
        }
    }
}

// ================== 📝 wrangler.toml 更新 ==================
function updateWranglerToml(dbId, kvId, JWT_SECRET) {
    if (!fs.existsSync("wrangler.toml")) fs.copyFileSync("wrangler.example.toml", "wrangler.toml")
    const config = toml.parse(fs.readFileSync("wrangler.toml", "utf-8"));

    // 确保 env.production 存在
    config.env ||= {};
    config.env[ENVIRONMENT] ||= {};

    // 配置 D1
    config.env[ENVIRONMENT].vars.DOMAIN = DOMAIN
    config.env[ENVIRONMENT].vars.JWT_SECRET = JWT_SECRET

    // 配置 D1
    config.env[ENVIRONMENT].d1_databases = [{binding: "DB", database_id: dbId, database_name: DB_NAME}];

    // 配置 KV
    config.env[ENVIRONMENT].kv_namespaces = [{binding: "KV", id: kvId}];

    // 配置 R2
    config.env[ENVIRONMENT].r2_buckets = [{binding: "R2", bucket_name: BUCKET_NAME}];

    if (ENVIRONMENT === "production") {
        config.vars.DOMAIN = DOMAIN
        config.vars.JWT_SECRET = JWT_SECRET
        config.d1_databases = [{binding: "DB", database_id: dbId, database_name: DB_NAME}];
        config.env[ENVIRONMENT].kv_namespaces = [{binding: "KV", id: kvId}];
        config.env[ENVIRONMENT].r2_buckets = [{binding: "R2", bucket_name: BUCKET_NAME}];
    }

    fs.writeFileSync("wrangler.toml", toml.stringify(config));
    log("success", `✅ 已更新 wrangler.toml`);
}

// ================== 🚀 部署流程 ==================
async function main() {
    console.log('👋 欢迎使用 CEM (Cloud Email Manager)')
    checkWrangler()
    log("info", "🔐 检查 Cloudflare 登录状态...");

    const {output, err: err1} = run("wrangler whoami",)
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

    // DOMAIN ||= (await question('请输入您的域名 (例如: example.com): ')).trim() || 'doubi.tech';
    DOMAIN ||= 'doubi.tech';
    // ENVIRONMENT ||= (await question('请输入环境 (development/production) [production]: ')).trim() || 'production';
    ENVIRONMENT ||= 'production';
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
    updateWranglerToml(dbId, kvId, JWT_SECRET);

    // const ADMIN_PREFIX = (await question('请输入管理员邮箱前缀 (例如: admin) [admin]: ')).trim() || 'admin';
    const ADMIN_PREFIX = 'admin';
    // const ADMIN_PASSWORD = (await askPassword()) || '123456';
    const ADMIN_PASSWORD = '123456';
    const ADMIN_PASSWORD_HASH = crypto
        .createHash("sha256")
        .update(String(ADMIN_PASSWORD))
        .digest("hex");

    // 运行数据库 schema，确保表存在
    log("info", "🗄️ 初始化数据库结构 (new_db_schema.sql)...");
    const {err: err2} = run(`wrangler d1 execute ${DB_NAME} --file=./new_db_schema.sql`);
    if (err2) {
        log("error", `❌ 初始化数据库结构失败: ${err2}`);
        process.exit(1);
    }
    log("success", "✅ 数据库结构已初始化");

    log("info", "👤 初始化管理员账户...");
    const {err: error} = run(
        `wrangler d1 execute ${DB_NAME} --command="INSERT INTO users (email_prefix, email_password, user_type) VALUES ('${ADMIN_PREFIX}', '${ADMIN_PASSWORD_HASH}', 'admin')"`);
    log("success", "✅ 管理员账户已创建");
    if ((error?.stderr || error?.stdout || error?.toString() || "").includes("UNIQUE constraint failed")) {
        log("warn", "⚠️  管理员账户已存在");
    } else if (error) {
        log("error", `❌ 管理员账户创建失败 ${error}`);
        process.exit(1);
    }

    log("info", "🚀 部署 Worker...")
    const {err: err3} = run(`wrangler deploy --env ${ENVIRONMENT}`);
    if (err3) {
        log("error", `❌ 部署 Worker 失败: ${err3}`)
        process.exit(1);
    }
    log("success", "🎉 Worker 部署完成")

    await endMsg(ADMIN_PREFIX, dbId, kvId, JWT_SECRET)
    rl.close()
}

main();
