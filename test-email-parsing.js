/**
 * 测试邮件解析逻辑
 * 用于测试 parsedEmail.text 是否包含 HTML 标签
 */

import { readFileSync } from 'fs';
import PostalMime from 'postal-mime';
import { convert } from 'html-to-text';

// 检查字符串是否包含 HTML 标签
function containsHtmlTags(text) {
  if (!text) return false;
  return /<[^>]+>/.test(text);
}

// 从 HTML 中提取纯文本（使用 html-to-text）
async function extractTextFromHtmlAsync(html) {
  if (!html) {
    return '';
  }

  try {
    const text = convert(html, {
      preserveNewlines: true,
      longWordSplit: {
        wrapCharacters: [],
        forceWrapOnLimit: false
      },
      selectors: [
        { selector: 'script', format: 'skip' },
        { selector: 'style', format: 'skip' },
        { selector: 'a', options: { ignoreHref: false } },
        { selector: 'img', format: 'image', options: { baseUrl: '' } },
        { selector: 'ul', format: 'unorderedList' },
        { selector: 'ol', format: 'orderedList' },
        { selector: 'table', format: 'dataTable' }
      ],
      wordwrap: 0
    });

    return text.trim();
  } catch (error) {
    console.warn('html-to-text 转换失败，使用备用方法:', error);
    return extractTextFromHtmlFallback(html);
  }
}

// 从 HTML 中提取纯文本（备用方法）
function extractTextFromHtmlFallback(html) {
  if (!html) {
    return '';
  }

  // 移除 script 和 style 标签及其内容
  let text = html.replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '');
  text = text.replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '');

  // 将常见的 HTML 实体转换为换行或空格
  text = text.replace(/<br\s*\/?>/gi, '\n');
  text = text.replace(/<\/p>/gi, '\n');
  text = text.replace(/<\/div>/gi, '\n');
  text = text.replace(/<\/li>/gi, '\n');
  text = text.replace(/<li[^>]*>/gi, '• ');

  // 移除所有 HTML 标签
  text = text.replace(/<[^>]+>/g, '');

  // 解码 HTML 实体
  text = text.replace(/&nbsp;/g, ' ');
  text = text.replace(/&amp;/g, '&');
  text = text.replace(/&lt;/g, '<');
  text = text.replace(/&gt;/g, '>');
  text = text.replace(/&quot;/g, '"');
  text = text.replace(/&#39;/g, "'");
  text = text.replace(/&apos;/g, "'");

  // 处理其他常见的 HTML 实体
  text = text.replace(/&#(\d+);/g, (match, dec) => {
    return String.fromCharCode(parseInt(dec, 10));
  });
  text = text.replace(/&#x([0-9A-Fa-f]+);/g, (match, hex) => {
    return String.fromCharCode(parseInt(hex, 16));
  });

  // 清理多余的空白字符
  text = text.replace(/\n\s*\n\s*\n/g, '\n\n');
  text = text.replace(/[ \t]+/g, ' ');
  text = text.replace(/^\s+|\s+$/gm, '');

  return text.trim();
}

async function testEmailParsing() {
  try {
    // 读取 .eml 文件
    const emlPath = './email_1dfba050-c2cf-440a-8987-8de6c6a07fd4.eml';
    console.log('📧 读取邮件文件:', emlPath);
    const rawEmail = readFileSync(emlPath, 'utf-8');
    console.log('✅ 邮件文件读取成功，大小:', rawEmail.length, '字符');

    // 使用 postal-mime 解析邮件
    console.log('\n🔍 开始解析邮件...');
    const encoder = new TextEncoder();
    const rawEmailBytes = encoder.encode(rawEmail);
    const parser = new PostalMime();
    const parsedEmail = await parser.parse(rawEmailBytes);

    console.log('✅ 邮件解析成功');
    console.log('\n📊 解析结果:');
    console.log('  - Subject:', parsedEmail.subject);
    console.log('  - From:', parsedEmail.from);
    console.log('  - To:', parsedEmail.to);
    console.log('  - Date:', parsedEmail.date);
    console.log('  - Has text:', !!parsedEmail.text);
    console.log('  - Has html:', !!parsedEmail.html);
    console.log('  - Attachments count:', parsedEmail.attachments?.length || 0);

    // 检查 parsedEmail.text
    if (parsedEmail.text) {
      console.log('\n📝 parsedEmail.text 分析:');
      console.log('  - 长度:', parsedEmail.text.length);
      console.log('  - 前200字符:', parsedEmail.text.substring(0, 200));
      console.log('  - 包含 HTML 标签:', containsHtmlTags(parsedEmail.text));

      if (containsHtmlTags(parsedEmail.text)) {
        console.log('  ⚠️  警告: parsedEmail.text 包含 HTML 标签！');
        console.log('  🔧 尝试提取纯文本...');

        try {
          const extractedText = await extractTextFromHtmlAsync(parsedEmail.text);
          if (extractedText && extractedText.trim()) {
            console.log('  ✅ 使用 extractTextFromHtml 提取成功');
            console.log('  - 提取后长度:', extractedText.length);
            console.log('  - 前200字符:', extractedText.substring(0, 200));
          } else {
            console.log('  ⚠️  extractTextFromHtml 返回空，使用备用方法');
            const fallbackText = extractTextFromHtmlFallback(parsedEmail.text);
            if (fallbackText && fallbackText.trim()) {
              console.log('  ✅ 备用方法提取成功');
              console.log('  - 提取后长度:', fallbackText.length);
              console.log('  - 前200字符:', fallbackText.substring(0, 200));
            } else {
              console.log('  ❌ 所有提取方法都失败');
            }
          }
        } catch (error) {
          console.log('  ❌ extractTextFromHtml 出错:', error.message);
          const fallbackText = extractTextFromHtmlFallback(parsedEmail.text);
          if (fallbackText && fallbackText.trim()) {
            console.log('  ✅ 备用方法提取成功');
            console.log('  - 提取后长度:', fallbackText.length);
            console.log('  - 前200字符:', fallbackText.substring(0, 200));
          }
        }
      } else {
        console.log('  ✅ parsedEmail.text 是纯文本，可以直接使用');
      }
    } else {
      console.log('\n⚠️  parsedEmail.text 不存在');
    }

    // 检查 parsedEmail.html
    if (parsedEmail.html) {
      console.log('\n🌐 parsedEmail.html 分析:');
      console.log('  - 长度:', parsedEmail.html.length);
      console.log('  - 前200字符:', parsedEmail.html.substring(0, 200));
      console.log('  - 包含 HTML 标签:', containsHtmlTags(parsedEmail.html));
    } else {
      console.log('\n⚠️  parsedEmail.html 不存在');
    }

    // 模拟邮件处理逻辑
    console.log('\n🔄 模拟邮件处理逻辑:');
    let content = '';
    let contentType = 'text';

    if (parsedEmail.text) {
      if (containsHtmlTags(parsedEmail.text)) {
        console.log('  ⚠️  parsedEmail.text 包含 HTML，需要提取纯文本');
        try {
          const extractedText = await extractTextFromHtmlAsync(parsedEmail.text);
          if (extractedText && extractedText.trim()) {
            content = extractedText;
            contentType = 'text';
            console.log('  ✅ 提取成功，长度:', content.length);
          } else {
            const fallbackText = extractTextFromHtmlFallback(parsedEmail.text);
            if (fallbackText && fallbackText.trim()) {
              content = fallbackText;
              contentType = 'text';
              console.log('  ✅ 使用备用方法提取成功，长度:', content.length);
            } else {
              content = '[无法提取邮件内容预览]';
              console.log('  ❌ 所有提取方法都失败');
            }
          }
        } catch (error) {
          const fallbackText = extractTextFromHtmlFallback(parsedEmail.text);
          if (fallbackText && fallbackText.trim()) {
            content = fallbackText;
            contentType = 'text';
            console.log('  ✅ 使用备用方法提取成功，长度:', content.length);
          } else {
            content = '[无法提取邮件内容预览]';
            console.log('  ❌ 所有提取方法都失败');
          }
        }
      } else {
        content = parsedEmail.text;
        contentType = 'text';
        console.log('  ✅ 使用纯文本，长度:', content.length);
      }
    } else if (parsedEmail.html) {
      console.log('  ⚠️  只有 HTML，需要提取纯文本');
      try {
        const extractedText = await extractTextFromHtmlAsync(parsedEmail.html);
        if (extractedText && extractedText.trim()) {
          content = extractedText;
          contentType = 'text';
          console.log('  ✅ 提取成功，长度:', content.length);
        } else {
          const fallbackText = extractTextFromHtmlFallback(parsedEmail.html);
          if (fallbackText && fallbackText.trim()) {
            content = fallbackText;
            contentType = 'text';
            console.log('  ✅ 使用备用方法提取成功，长度:', content.length);
          } else {
            content = '[无法提取邮件内容预览]';
            console.log('  ❌ 所有提取方法都失败');
          }
        }
      } catch (error) {
        const fallbackText = extractTextFromHtmlFallback(parsedEmail.html);
        if (fallbackText && fallbackText.trim()) {
          content = fallbackText;
          contentType = 'text';
          console.log('  ✅ 使用备用方法提取成功，长度:', content.length);
        } else {
          content = '[无法提取邮件内容预览]';
          console.log('  ❌ 所有提取方法都失败');
        }
      }
    }

    // 截取预览
    const CONTENT_PREVIEW_LENGTH = 1000;
    let contentPreview = content;
    if (content && content.length > CONTENT_PREVIEW_LENGTH) {
      contentPreview = content.substring(0, CONTENT_PREVIEW_LENGTH) + '...';
    }

    console.log('\n📋 最终结果:');
    console.log('  - Content Type:', contentType);
    console.log('  - Content Length:', content.length);
    console.log('  - Preview Length:', contentPreview.length);
    console.log('  - Preview (前500字符):', contentPreview.substring(0, 500));
    console.log('  - 包含 HTML 标签:', containsHtmlTags(contentPreview));

    // 最终验证
    if (containsHtmlTags(contentPreview)) {
      console.log('\n❌ 错误: 最终内容仍然包含 HTML 标签！');
      console.log('  🔧 尝试清理...');
      const cleanedContent = extractTextFromHtmlFallback(contentPreview);
      if (cleanedContent && cleanedContent.trim()) {
        console.log('  ✅ 清理成功');
        console.log('  - 清理后长度:', cleanedContent.length);
        console.log('  - 清理后前200字符:', cleanedContent.substring(0, 200));
      } else {
        console.log('  ❌ 清理失败');
      }
    } else {
      console.log('\n✅ 最终内容不包含 HTML 标签，可以保存到数据库');
    }

  } catch (error) {
    console.error('❌ 测试失败:', error);
    console.error(error.stack);
  }
}

// 运行测试
testEmailParsing();

