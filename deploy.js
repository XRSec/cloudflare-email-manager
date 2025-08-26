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
let DB_NAME = `cem-db`;
let KV_NAME = `cem-kv`;
let BUCKET_NAME = `cem-r2`;

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

function checkJq() {
    const {err} = run("jq --version");
    if (err) {
        log("error", "❌ jq 未安装");
        process.exit(1);
    }
}

// ================== ⚙️ 环境变量 ==================
let DOMAIN
let devMode

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
    let {output, err} = run(`wrangler ${type} create ${name}`);

    if (err?.stderr.includes("already exists") || err?.stdout.includes("already exists")) {
        const {
            output: listOutput,
            err: err1
        } = run(`wrangler ${type} list ${type === "d1" ? "--json" : ""} ${type === "r2 bucket" ? "" : "| jq -c '.'"}`)
        err1 && process.exit(1)
        if (type === "r2 bucket") {
            id = name
            // const match = listOutput.match(/name:\s+(\S+)[\s\S]*?creation_date:\s+(\S+)/);
            // if (match) id = match[1];
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
        // console.error(err.stdout || err.message);
        process.exit(1);
    }
    const match = output.match(/id = "([^"]+)"/);
    if (match) id = match[1];
    log("success", `✅ ${type} 创建成功: ${type === "r2" ? id : name}`);
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

async function endMsg(ADMIN_PREFIX, dbId, kvId, JWT_SECRET) {
    // 设置自定义域名
    log("info", "🌐 配置自定义域名...")
    const setupDomain = (await question(`是否要配置自定义域名? (y/n) [y]: `)).trim() || 'y'
    if (/^[Yy]$/.test(setupDomain)) {
        log("warn", "请在 Cloudflare 控制台中手动配置以下设置:")
        log("info", "1. 添加域名到 Cloudflare")
        log("info", "2. 在 Workers & Pages 中绑定自定义域名")
        log("info", "3. 在 Email Routing 中配置路由规则")
        log("info", `   规则: *@${DOMAIN} → Send to Worker → cem`)
    }

    log("success", "🎉 部署完成")
    log("info", "📋 部署信息:")
    log("info", `  域名: ${DOMAIN}`);
    devMode && log("info", "  🚧 开发模式");
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

    if (devMode) {
        log("info", "  开发环境: http://localhost:8787");
        log("info", "  启动开发服务器: npm run dev");

        const setupDomain = (await question("是否启动开发服务器? (y/n) [y]: ")).trim() || "y";
        if (/^[Yy]$/.test(setupDomain)) {
            log("success", "🚀 启动开发服务器...");
            run("npm run dev");
        }
    } else {
        log("info", `  生产环境: https://${DOMAIN}`);
        log("info", `  Worker 地址: https://cem.name.workers.dev`);
    }

    log("info", "\n📚 更多信息请查看 README.md");
}

// ================== 📝 wrangler.toml 更新 ==================
function updateWranglerToml(dbId, kvId, JWT_SECRET) {
    if (!fs.existsSync("wrangler.toml")) fs.copyFileSync("wrangler.example.toml", "wrangler.toml")
    const config = toml.parse(fs.readFileSync("wrangler.toml", "utf-8"));

    const target = devMode ? config.env[dev] : config;

    // 配置 vars
    target.vars = {...target.vars, DOMAIN, JWT_SECRET};
    target.d1_databases = [{binding: "DB", database_id: dbId, database_name: DB_NAME}]; // 配置 D1
    target.kv_namespaces = [{binding: "KV", id: kvId}]; // 配置 KV
    target.r2_buckets = [{binding: "R2", bucket_name: BUCKET_NAME}]; // 配置 R2

    fs.writeFileSync("wrangler.toml", toml.stringify(config));
    log("success", `✅ 已更新 wrangler.toml`);
}

function deleteAll() {
    run(`for name in $(wrangler d1 list --json | jq -r '.[].name'); do wrangler d1 delete "$name" -y; done`, "inherit")
    run(`for id in $(wrangler kv namespace list | jq -r '.[].id'); do wrangler kv namespace delete --namespace-id "$id"; done`, "inherit")
    run(`for name in $(wrangler r2 bucket list | awk '/^name:/ {print $2}'); do wrangler r2 bucket delete "$name"; done`, "inherit")
    process.exit(0)
}

// ================== 🚀 部署流程 ==================
async function main() {
    const target = process.argv[2] || ""
    if (target === "deleteAll") deleteAll();


    console.log('👋 欢迎使用 CEM (Cloud Email Manager)')
    checkWrangler()
    checkJq()
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
    // const dev_input = (await question(`是否开发模式? (y/n) [n]: `)).trim() || 'n'
    const dev_input = "n"
    if (/^[Yy]$/.test(dev_input)) {
        devMode = true;
        DB_NAME = 'cem-db-dev';
        KV_NAME = 'cem-kv-dev';
        BUCKET_NAME = 'cem-r2-dev';
    }

    log("info", `📋 部署配置:`);
    log("info", `  域名: ${DOMAIN}`);
    devMode && log("info", "🚧 开发模式");

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
    log("info", "🗄️ 初始化数据库结构 (schema.sql)...");
    const {err: err2} = run(`wrangler d1 execute ${DB_NAME} --file=./db/schema.sql --remote`);
    if (err2) {
        log("error", `❌ 初始化数据库结构失败: ${err2}`);
        process.exit(1);
    }
    log("success", "✅ 数据库结构已初始化");

    log("info", "👤 初始化管理员账户...");
    const {err: error} = run(
        `wrangler d1 execute ${DB_NAME} --command="INSERT OR IGNORE INTO users (email_prefix, email_password, user_type) VALUES ('${ADMIN_PREFIX}', '${ADMIN_PASSWORD_HASH}', 'admin')"`);
    log("success", "✅ 管理员账户已创建");
    if (error?.stderr?.includes("UNIQUE constraint failed") || error?.stdout?.includes("UNIQUE constraint failed")) {
        log("warn", "⚠️  管理员账户已存在");
    } else if (error) {
        log("error", `❌ 管理员账户创建失败 ${error}`);
        process.exit(1);
    }

    log("info", "🚀 部署 Worker...")
    const {err: err3} = run(`wrangler deploy ${devMode ? "--env dev" : ""}`);

    if (err3) {
        log("error", `❌ 部署 Worker 失败: ${err3}`)
        process.exit(1);
    }
    log("success", "🎉 Worker 部署完成")

    await endMsg(ADMIN_PREFIX, dbId, kvId, JWT_SECRET)
    rl.close()
}

main();