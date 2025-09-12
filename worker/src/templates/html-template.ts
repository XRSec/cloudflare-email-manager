/**
 * HTML 模板模块
 * 主要的 HTML 结构 - 包含 HTML、CSS、JavaScript 的完整前端文件
 */

import { getStyleTag } from '../static/styles';
import { AppConfig } from '../static/app-config';
import { getJavaScript } from '../static/app';
import {
    BaseTemplates,
    EmailTemplates,
    UserTemplates,
    DebugTemplates,
    MessageTemplates,
    TemplateHelpers
} from '../shared/html-templates';
import { renderTemplate, createTemplate } from '../shared/template-engine';
import { escapeHtml, formatDate, truncateText } from '../shared/utils';
import { FRONTEND_ROUTES, USER_TYPES, STORAGE_KEYS } from '../shared/constants';

/**
 * 获取 HTML 头部
 */

