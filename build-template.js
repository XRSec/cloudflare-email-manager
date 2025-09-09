/**
 * 构建脚本 - 将 HTML 模板转换为 TypeScript 模块
 * 在部署前运行此脚本
 */

const fs = require('fs');
const path = require('path');

// 配置
const CONFIG = {
    sourceFile: 'src/templates/index.html',
    outputFile: 'src/templates/compiled.ts',
    minify: process.env.NODE_ENV === 'production', // 生产环境压缩
    removeComments: true, // 移除注释
    removeEmptyLines: true // 移除空行
};

// 读取 HTML 模板
console.log(`📖 读取模板文件: ${CONFIG.sourceFile}`);
const htmlPath = path.join(__dirname, CONFIG.sourceFile);

if (!fs.existsSync(htmlPath)) {
    console.error(`❌ 文件不存在: ${CONFIG.sourceFile}`);
    process.exit(1);
}

let htmlContent = fs.readFileSync(htmlPath, 'utf-8');
const originalSize = htmlContent.length;

// 可选：压缩 HTML
if (CONFIG.minify) {
    console.log('🗜️  压缩 HTML...');
    
    // 移除注释
    if (CONFIG.removeComments) {
        htmlContent = htmlContent
            .replace(/<!--[\s\S]*?-->/g, '') // HTML 注释
            .replace(/\/\*[\s\S]*?\*\//g, '') // CSS 注释
            .replace(/\/\/.*$/gm, ''); // JS 单行注释（小心处理）
    }
    
    // 移除多余空白
    htmlContent = htmlContent
        .replace(/\s+/g, ' ') // 多个空白符替换为单个空格
        .replace(/>\s+</g, '><') // 移除标签间的空白
        .replace(/\n\s*\n/g, '\n'); // 移除空行
    
    // 压缩内联 CSS
    htmlContent = htmlContent.replace(/<style[^>]*>([\s\S]*?)<\/style>/gi, (match, css) => {
        const minifiedCss = css
            .replace(/\s+/g, ' ')
            .replace(/:\s+/g, ':')
            .replace(/;\s+/g, ';')
            .replace(/\{\s+/g, '{')
            .replace(/\}\s+/g, '}')
            .replace(/,\s+/g, ',');
        return `<style>${minifiedCss}</style>`;
    });
}

// 移除空行（总是执行）
if (CONFIG.removeEmptyLines) {
    htmlContent = htmlContent
        .split('\n')
        .filter(line => line.trim() !== '')
        .join('\n');
}

const compressedSize = htmlContent.length;

// 转义特殊字符
const escapedHtml = htmlContent
    .replace(/\\/g, '\\\\')
    .replace(/`/g, '\\`')
    .replace(/\${/g, '\\${');

// 生成 TypeScript 文件
const tsContent = `/**
 * 自动生成的模板文件
 * 由 build-template.js 生成
 * 源文件: ${CONFIG.sourceFile}
 * 生成时间: ${new Date().toISOString()}
 * 原始大小: ${(originalSize / 1024).toFixed(2)} KB
 * 压缩后: ${(compressedSize / 1024).toFixed(2)} KB
 * 压缩率: ${((1 - compressedSize / originalSize) * 100).toFixed(1)}%
 */

export const htmlTemplate = \`${escapedHtml}\`;

export function getTemplate(): string {
    return htmlTemplate;
}

// 模板信息
export const templateInfo = {
    originalSize: ${originalSize},
    compressedSize: ${compressedSize},
    compressionRatio: ${((1 - compressedSize / originalSize) * 100).toFixed(1)},
    buildTime: '${new Date().toISOString()}',
    minified: ${CONFIG.minify}
};
`;

// 写入 TypeScript 文件
const outputPath = path.join(__dirname, CONFIG.outputFile);
fs.writeFileSync(outputPath, tsContent, 'utf-8');

// 输出统计信息
console.log('✅ 模板编译完成!');
console.log('📊 统计信息:');
console.log(`   原始大小: ${(originalSize / 1024).toFixed(2)} KB`);
console.log(`   压缩后: ${(compressedSize / 1024).toFixed(2)} KB`);
console.log(`   压缩率: ${((1 - compressedSize / originalSize) * 100).toFixed(1)}%`);
console.log(`   输出文件: ${CONFIG.outputFile}`);

// 警告检查
if (compressedSize > 100 * 1024) {
    console.warn('⚠️  警告: 模板大小超过 100KB，考虑进一步优化');
}

if (compressedSize > 500 * 1024) {
    console.error('❌ 错误: 模板大小超过 500KB，可能影响 Worker 性能');
    process.exit(1);
}