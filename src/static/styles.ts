/**
 * 模块化 CSS 样式
 * 所有样式定义在这里，支持缓存控制
 */

// 基础样式
const baseStyles = `
    * {
        margin: 0;
        padding: 0;
        box-sizing: border-box;
    }

    body {
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        min-height: 100vh;
        color: #333;
        line-height: 1.6;
    }

    .container {
        max-width: 1200px;
        margin: 0 auto;
        padding: 20px;
    }

    .hidden {
        display: none !important;
    }
`;

// 卡片组件样式
const cardStyles = `
    .card {
        background: white;
        border-radius: 10px;
        padding: 30px;
        box-shadow: 0 10px 40px rgba(0, 0, 0, 0.1);
        margin-bottom: 20px;
    }

    .card h2 {
        margin-bottom: 20px;
        color: #2c3e50;
    }

    .header {
        text-align: center;
        padding: 40px 0;
        color: white;
    }

    .header h1 {
        font-size: 2.5rem;
        margin-bottom: 10px;
        text-shadow: 2px 2px 4px rgba(0, 0, 0, 0.2);
    }
`;

// 侧边栏样式
const sidebarStyles = `
    .sidebar {
        position: fixed;
        left: -250px;
        top: 0;
        width: 250px;
        height: 100vh;
        background: #2c3e50;
        transition: left 0.3s ease;
        z-index: 1000;
        overflow-y: auto;
    }

    .sidebar.open {
        left: 0;
    }

    .sidebar-header {
        padding: 20px;
        background: #1a252f;
        color: white;
    }

    .sidebar-header h3 {
        margin: 0;
    }

    .sidebar-menu {
        padding: 10px 0;
    }

    .sidebar-item {
        padding: 15px 20px;
        color: #ecf0f1;
        cursor: pointer;
        transition: background 0.3s;
    }

    .sidebar-item:hover {
        background: #34495e;
    }

    .sidebar-item.active {
        background: #3498db;
    }

    .main-content {
        transition: margin-left 0.3s ease;
        min-height: 100vh;
    }

    .main-content.sidebar-open {
        margin-left: 250px;
    }
`;

// 表单样式
const formStyles = `
    .form-group {
        margin-bottom: 20px;
    }

    .form-label {
        display: block;
        margin-bottom: 5px;
        font-weight: 500;
        color: #555;
    }

    .form-control {
        width: 100%;
        padding: 10px;
        border: 1px solid #ddd;
        border-radius: 5px;
        font-size: 14px;
        transition: border-color 0.3s;
    }

    .form-control:focus {
        outline: none;
        border-color: #3498db;
        box-shadow: 0 0 0 3px rgba(52, 152, 219, 0.1);
    }

    .form-row {
        display: flex;
        gap: 20px;
        margin-bottom: 20px;
    }

    .form-col {
        flex: 1;
    }

    textarea.form-control {
        resize: vertical;
        min-height: 100px;
    }
`;

// 按钮样式
const buttonStyles = `
    .btn {
        padding: 10px 20px;
        border: none;
        border-radius: 5px;
        font-size: 14px;
        cursor: pointer;
        transition: all 0.3s;
        font-weight: 500;
        display: inline-block;
    }

    .btn-primary {
        background: #3498db;
        color: white;
    }

    .btn-primary:hover {
        background: #2980b9;
        transform: translateY(-2px);
        box-shadow: 0 5px 15px rgba(52, 152, 219, 0.3);
    }

    .btn-secondary {
        background: #95a5a6;
        color: white;
    }

    .btn-secondary:hover {
        background: #7f8c8d;
    }

    .btn-danger {
        background: #e74c3c;
        color: white;
    }

    .btn-danger:hover {
        background: #c0392b;
    }

    .btn-success {
        background: #27ae60;
        color: white;
    }

    .btn-sm {
        padding: 5px 10px;
        font-size: 12px;
        margin: 0 10px;
    }
`;

// 表格样式
const tableStyles = `
    .table {
        width: 100%;
        border-collapse: collapse;
        margin-top: 20px;
    }

    .table th,
    .table td {
        padding: 12px;
        text-align: left;
        border-bottom: 1px solid #ecf0f1;
    }

    .table th {
        background: #f8f9fa;
        font-weight: 600;
        color: #555;
    }

    .table tr:hover {
        background: #f8f9fa;
    }

    .table-responsive {
        overflow-x: auto;
    }
`;

// 消息提示样式
const messageStyles = `
    .message {
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 15px 20px;
        border-radius: 5px;
        color: white;
        z-index: 2000;
        animation: slideIn 0.3s ease;
        max-width: 400px;
    }

    .message.success {
        background: #27ae60;
    }

    .message.error {
        background: #e74c3c;
    }

    .message.warning {
        background: #f39c12;
    }

    .message.info {
        background: #3498db;
    }

    @keyframes slideIn {
        from {
            transform: translateX(100%);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }
`;

// 邮件列表样式
const emailStyles = `
    .email-item {
        border: 1px solid #ecf0f1;
        border-radius: 15px;
        padding: 0 15px;
        margin-bottom: 10px;
        cursor: pointer;
        transition: all 0.3s;
    }

    .email-item:hover {
        box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
        transform: translateY(-2px);
    }

    .email-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        cursor: pointer;
        padding: 12px 0;
        min-height: 40px;
    }

    .email-main-info {
        flex: 1;
        min-width: 0;
    }

    .email-sender-line {
        display: flex;
        align-items: center;
        gap: 12px;
        flex-wrap: wrap;
    }

    .email-sender {
        font-weight: 600;
        color: #2c3e50;
        white-space: nowrap;
        flex-shrink: 0;
    }

    .email-content-preview {
        color: #7f8c8d;
        font-size: 0.9rem;
        font-style: italic;
        flex: 1;
        min-width: 0;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
        margin-left: 12px;
    }

    .email-meta {
        display: flex;
        align-items: center;
        gap: 8px;
        flex-shrink: 0;
    }

    .email-time {
        color: #7f8c8d;
        font-size: 0.85rem;
        white-space: nowrap;
    }

    .email-attachments {
        color: #e67e22;
        font-size: 1rem;
    }

    .email-toggle {
        cursor: pointer;
        font-size: 1.2rem;
        color: #7f8c8d;
        transition: color 0.2s ease;
    }

    .email-toggle:hover {
        color: #3498db;
    }

    .email-details {
        max-height: 0;
        overflow: hidden;
        transition: all 0.3s ease;
        background: #f8f9fa;
        border-radius: 8px;
        padding: 0;
        margin-top: 0;
        opacity: 0;
    }

    .email-details.expanded {
        max-height: 600px;
        padding: 20px;
        margin-top: 15px;
        opacity: 1;
        box-shadow: inset 0 1px 3px rgba(0,0,0,0.1);
    }

    .email-detail-row {
        display: flex;
        margin-bottom: 12px;
        align-items: flex-start;
        padding: 8px 0;
        border-bottom: 1px solid #e9ecef;
    }

    .email-detail-row:last-child {
        border-bottom: none;
        margin-bottom: 0;
    }

    .detail-label {
        font-weight: 600;
        color: #495057;
        min-width: 100px;
        margin-right: 15px;
        font-size: 0.9rem;
        opacity: 0.8;
    }

    .detail-value {
        color: #212529;
        flex: 1;
        word-break: break-word;
        line-height: 1.4;
    }

    .html-content {
        background: white;
        padding: 15px;
        border-radius: 8px;
        border: 1px solid #dee2e6;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        font-size: 0.95rem;
        max-height: 300px;
        overflow-y: auto;
        line-height: 1.6;
        box-shadow: 0 1px 3px rgba(0,0,0,0.1);
    }

    .text-content {
        background: #f8f9fa;
        padding: 15px;
        border-radius: 8px;
        border-left: 4px solid #007bff;
        font-family: 'SF Mono', Monaco, 'Cascadia Code', 'Roboto Mono', Consolas, 'Courier New', monospace;
        font-size: 0.9rem;
        white-space: pre-wrap;
        max-height: 250px;
        overflow-y: auto;
        line-height: 1.5;
    }

    .truncated {
        color: #6c757d;
        font-style: italic;
        font-size: 0.85rem;
        margin-top: 10px;
        text-align: center;
        padding: 5px;
        background: #e9ecef;
        border-radius: 4px;
    }
`;

// 邮箱管理样式
const mailboxStyles = `
    .mailbox-item {
        border: 1px solid #e9ecef;
        border-radius: 8px;
        padding: 15px;
        margin-bottom: 15px;
        background: white;
        display: flex;
        justify-content: space-between;
        align-items: center;
        transition: box-shadow 0.2s ease;
    }

    .mailbox-item:hover {
        box-shadow: 0 2px 8px rgba(0,0,0,0.1);
    }

    .mailbox-info {
        flex: 1;
    }

    .mailbox-address {
        font-weight: 600;
        color: #2c3e50;
        margin-bottom: 5px;
    }

    .mailbox-user {
        color: #7f8c8d;
        font-size: 0.9rem;
        margin-bottom: 5px;
    }

    .mailbox-date {
        color: #95a5a6;
        font-size: 0.85rem;
    }

    .mailbox-actions {
        display: flex;
        gap: 8px;
    }

    .application-item {
        border: 1px solid #e9ecef;
        border-radius: 8px;
        padding: 15px;
        margin-bottom: 15px;
        background: white;
        display: flex;
        justify-content: space-between;
        align-items: flex-start;
    }

    .application-info {
        flex: 1;
    }

    .application-email {
        font-weight: 600;
        color: #2c3e50;
        margin-bottom: 8px;
    }

    .application-user {
        color: #7f8c8d;
        font-size: 0.9rem;
        margin-bottom: 8px;
    }

    .application-status {
        margin-bottom: 8px;
    }

    .application-date {
        color: #95a5a6;
        font-size: 0.85rem;
        margin-bottom: 8px;
    }

    .application-reason {
        color: #34495e;
        font-size: 0.9rem;
        margin-bottom: 8px;
        padding: 8px;
        background: #f8f9fa;
        border-radius: 4px;
        border-left: 3px solid #3498db;
    }

    .application-comment {
        color: #e74c3c;
        font-size: 0.9rem;
        margin-bottom: 8px;
        padding: 8px;
        background: #fdf2f2;
        border-radius: 4px;
        border-left: 3px solid #e74c3c;
    }

    .application-actions {
        display: flex;
        gap: 8px;
        flex-shrink: 0;
    }

    .application-details {
        background: #f8f9fa;
        border-radius: 8px;
        padding: 15px;
        margin-bottom: 15px;
    }

    .application-details p {
        margin: 8px 0;
    }

    .badge {
        display: inline-block;
        padding: 4px 8px;
        font-size: 0.75rem;
        font-weight: 600;
        border-radius: 4px;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }

    .badge-primary {
        background-color: #3498db;
        color: white;
    }

    .badge-success {
        background-color: #27ae60;
        color: white;
    }

    .badge-warning {
        background-color: #f39c12;
        color: white;
    }

    .badge-danger {
        background-color: #e74c3c;
        color: white;
    }

    .badge-secondary {
        background-color: #95a5a6;
        color: white;
    }

    .empty-state {
        text-align: center;
        padding: 40px 20px;
        color: #7f8c8d;
        font-style: italic;
    }
`;

// 加载动画样式
const loadingStyles = `
    .loading {
        text-align: center;
        padding: 40px;
        color: #7f8c8d;
    }

    .loading::after {
        content: "...";
        animation: dots 1.5s steps(4, end) infinite;
    }

    @keyframes dots {
        0%, 20% {
            content: ".";
        }
        40% {
            content: "..";
        }
        60%, 100% {
            content: "...";
        }
    }

    .spinner {
        border: 3px solid #f3f3f3;
        border-top: 3px solid #3498db;
        border-radius: 50%;
        width: 40px;
        height: 40px;
        animation: spin 1s linear infinite;
        margin: 20px auto;
    }

    @keyframes spin {
        0% { transform: rotate(0deg); }
        100% { transform: rotate(360deg); }
    }
`;

// 响应式设计
const responsiveStyles = `
    @media (max-width: 768px) {
        .sidebar {
            width: 100%;
            left: -100%;
        }

        .sidebar.open {
            left: 0;
        }

        .main-content.sidebar-open {
            margin-left: 0;
        }

        .container {
            padding: 10px;
        }

        .header h1 {
            font-size: 2rem;
        }

        .form-row {
            flex-direction: column;
            gap: 10px;
        }

        .table-responsive {
            font-size: 0.9rem;
        }
    }

    @media (max-width: 480px) {
        .card {
            padding: 20px;
        }

        .btn {
            width: 100%;
            margin-bottom: 10px;
        }
    }
`;

// 其他组件样式
const componentStyles = `
    .badge {
        display: inline-block;
        padding: 3px 8px;
        border-radius: 3px;
        font-size: 0.8rem;
        font-weight: 600;
    }

    .badge-primary {
        background: #3498db;
        color: white;
    }

    .badge-success {
        background: #27ae60;
        color: white;
    }

    .badge-danger {
        background: #e74c3c;
        color: white;
    }

    .badge-warning {
        background: #f39c12;
        color: white;
    }

    .modal {
        display: none;
        position: fixed;
        z-index: 3000;
        left: 0;
        top: 0;
        width: 100%;
        height: 100%;
        background-color: rgba(0, 0, 0, 0.5);
    }

    .modal.show {
        display: flex;
        align-items: center;
        justify-content: center;
    }

    .modal-content {
        background: white;
        border-radius: 10px;
        padding: 30px;
        max-width: 500px;
        width: 90%;
        max-height: 90vh;
        overflow-y: auto;
    }

    .modal-header {
        margin-bottom: 20px;
    }

    .modal-header h3 {
        margin: 0;
        color: #2c3e50;
    }

    .modal-footer {
        margin-top: 20px;
        text-align: right;
    }

    .tabs {
        display: flex;
        border-bottom: 2px solid #ecf0f1;
        margin-bottom: 20px;
    }

    .tab {
        padding: 10px 20px;
        cursor: pointer;
        background: none;
        border: none;
        color: #7f8c8d;
        font-size: 16px;
        transition: all 0.3s;
    }

    .tab.active {
        color: #3498db;
        border-bottom: 2px solid #3498db;
    }

    .tab-content {
        display: none;
    }

    .tab-content.active {
        display: block;
    }

    .search-box {
        position: relative;
        margin-bottom: 20px;
    }

    .search-input {
        width: 100%;
        padding: 10px 40px 10px 15px;
        border: 1px solid #ddd;
        border-radius: 25px;
        font-size: 14px;
    }

    .search-icon {
        position: absolute;
        right: 15px;
        top: 50%;
        transform: translateY(-50%);
        color: #7f8c8d;
    }

    .user-info {
        display: flex;
        align-items: center;
        gap: 10px;
        padding: 10px;
        border-radius: 5px;
    }

    .user-avatar {
        width: 40px;
        height: 40px;
        border-radius: 50%;
        background: #3498db;
        color: white;
        display: flex;
        align-items: center;
        justify-content: center;
        font-weight: bold;
    }

    .top-bar {
        background: white;
        padding: 15px 20px;
        box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 20px;
    }
`;

/**
 * 获取所有样式
 */
export function getAllStyles(): string {
    return `
        ${baseStyles}
        ${cardStyles}
        ${sidebarStyles}
        ${formStyles}
        ${buttonStyles}
        ${tableStyles}
        ${messageStyles}
        ${emailStyles}
        ${mailboxStyles}
        ${loadingStyles}
        ${componentStyles}
        ${responsiveStyles}
    `.trim();
}

/**
 * 获取带缓存控制的样式标签
 */
export function getStyleTag(): string {
    // 生成版本号用于缓存控制
    const version = new Date().getTime();
    
    return `
    <style data-version="${version}">
        ${getAllStyles()}
    </style>
    `;
}

/**
 * 获取外部样式链接（如果使用 CDN）
 */
export function getExternalStyles(): string {
    return `
    <!-- 外部样式（可选） -->
    <!-- <link rel="stylesheet" href="https://cdn.example.com/styles.css"> -->
    `;
}