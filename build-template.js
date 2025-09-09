/**
 * 构建脚本 - 将 HTML 模板转换为 TypeScript 模块
 * 在部署前运行此脚本
 */

const fs = require('fs');
const path = require('path');

// 读取 HTML 模板
const htmlPath = path.join(__dirname, 'src/templates/index.html');
const htmlContent = fs.readFileSync(htmlPath, 'utf-8');

// 转义特殊字符
const escapedHtml = htmlContent
    .replace(/\\/g, '\\\\')
    .replace(/`/g, '\\`')
    .replace(/\${/g, '\\${');

// 生成 TypeScript 文件
const tsContent = `/**
 * 自动生成的模板文件
 * 由 build-template.js 生成
 * 源文件: src/templates/index.html
 */

export const htmlTemplate = \`${escapedHtml}\`;

export function getTemplate(): string {
    return htmlTemplate;
}
`;

// 写入 TypeScript 文件
const outputPath = path.join(__dirname, 'src/templates/compiled.ts');
fs.writeFileSync(outputPath, tsContent, 'utf-8');

console.log('✅ 模板编译完成: src/templates/compiled.ts');
console.log(`📊 模板大小: ${(htmlContent.length / 1024).toFixed(2)} KB`);