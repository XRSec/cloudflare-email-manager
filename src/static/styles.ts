/**
 * 样式模块 - 模块化CSS管理
 */

// 基础样式
const baseStyles = `
/* 基础样式重置和字体 */
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

/* 隐藏类 */
.hidden {
    display: none !important;
}

/* 徽章样式 */
.badge {
    padding: 4px 8px;
    border-radius: 4px;
    font-size: 0.75rem;
    font-weight: 600;
    text-transform: uppercase;
}
`;

// 卡片样式
const cardStyles = `
/* 卡片样式 */
.card {
    background: white;
    border-radius: 16px;
    box-shadow: 0 20px 60px rgba(0,0,0,0.1);
    padding: 30px;
    margin-bottom: 20px;
    backdrop-filter: blur(10px);
}

.card h2 {
    margin-bottom: 20px;
    color: #2c3e50;
    font-weight: 600;
}

.card h3 {
    margin-bottom: 15px;
    color: #34495e;
    font-weight: 500;
}
`;

// 头部样式
const headerStyles = `
/* 头部样式 */
.header {
    text-align: center;
    color: white;
    margin-bottom: 40px;
}

.header h1 {
    font-size: 3rem;
    margin-bottom: 10px;
    font-weight: 300;
    text-shadow: 0 2px 10px rgba(0,0,0,0.3);
}

.header p {
    font-size: 1.2rem;
    opacity: 0.9;
}

/* 响应式头部 */
@media (max-width: 768px) {
    .header h1 {
        font-size: 2rem;
    }

    .header p {
        font-size: 1rem;
    }
}
`;

// 表单样式
const formStyles = `
/* 表单样式 */
.form-group {
    margin-bottom: 20px;
}

.form-group label {
    display: block;
    margin-bottom: 8px;
    font-weight: 600;
    color: #2c3e50;
}

.form-control {
    width: 100%;
    padding: 12px 16px;
    border: 2px solid #e9ecef;
    border-radius: 8px;
    font-size: 16px;
    transition: all 0.3s ease;
    background-color: #fff;
}

.form-control:focus {
    outline: none;
    border-color: #667eea;
    box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
}

.form-control::placeholder {
    color: #adb5bd;
}

/* 表单行和列 */
.form-row {
    display: flex;
    gap: 15px;
    margin-bottom: 20px;
}

.form-col {
    flex: 1;
}

@media (max-width: 768px) {
    .form-row {
        flex-direction: column;
        gap: 0;
    }
}
`;

// 按钮样式
const buttonStyles = `
/* 按钮样式 */
.btn {
    display: inline-block;
    padding: 12px 24px;
    border: none;
    border-radius: 8px;
    font-size: 16px;
    font-weight: 600;
    text-decoration: none;
    text-align: center;
    cursor: pointer;
    transition: all 0.3s ease;
    min-width: 120px;
}

.btn-primary {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
}

.btn-primary:hover {
    transform: translateY(-2px);
    box-shadow: 0 10px 25px rgba(102, 126, 234, 0.3);
}

.btn-secondary {
    background: #6c757d;
    color: white;
}

.btn-secondary:hover {
    background: #5a6268;
    transform: translateY(-1px);
}

.btn-success {
    background: #28a745;
    color: white;
}

.btn-success:hover {
    background: #218838;
    transform: translateY(-1px);
}

.btn-danger {
    background: #dc3545;
    color: white;
}

.btn-danger:hover {
    background: #c82333;
    transform: translateY(-1px);
}

.btn-warning {
    background: #ffc107;
    color: #212529;
}

.btn-warning:hover {
    background: #e0a800;
    transform: translateY(-1px);
}

.btn-sm {
    padding: 8px 16px;
    font-size: 14px;
    min-width: 80px;
}

.btn:disabled {
    opacity: 0.6;
    cursor: not-allowed;
    transform: none !important;
}

.btn:disabled:hover {
    transform: none !important;
    box-shadow: none !important;
}
`;

// 标签页样式
const tabStyles = `
/* 标签页样式 */
.tabs {
    display: flex;
    margin-bottom: 30px;
    border-bottom: 2px solid #e9ecef;
}

.tab {
    flex: 1;
    padding: 15px 20px;
    background: none;
    border: none;
    font-size: 16px;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.3s ease;
    color: #6c757d;
    position: relative;
}

.tab.active {
    color: #667eea;
}

.tab.active::after {
    content: '';
    position: absolute;
    bottom: -2px;
    left: 0;
    right: 0;
    height: 3px;
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    border-radius: 2px;
}

.tab:hover {
    color: #667eea;
    background-color: #f8f9fa;
}

.tab-content {
    display: none;
}

.tab-content.active {
    display: block;
}
`;

// 侧边栏样式
const sidebarStyles = `
/* 侧边栏样式 */
.sidebar {
    position: fixed;
    left: -300px;
    top: 0;
    width: 300px;
    height: 100vh;
    background: rgba(255, 255, 255, 0.95);
    backdrop-filter: blur(10px);
    box-shadow: 2px 0 20px rgba(0,0,0,0.1);
    transition: left 0.3s ease;
    z-index: 1000;
    overflow-y: auto;
}

.sidebar.open {
    left: 0;
}

.sidebar-header {
    padding: 30px 20px;
    border-bottom: 1px solid #e9ecef;
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
}

.sidebar-header h3 {
    font-size: 1.5rem;
    margin-bottom: 5px;
    font-weight: 600;
}

.sidebar-header p {
    font-size: 0.9rem;
    opacity: 0.9;
    margin: 0;
}

.sidebar-menu {
    padding: 20px 0;
}

.sidebar-item {
    display: block;
    padding: 15px 25px;
    color: #2c3e50;
    text-decoration: none;
    transition: all 0.3s ease;
    cursor: pointer;
    font-weight: 500;
    border-left: 3px solid transparent;
}

.sidebar-item:hover {
    background: #f8f9fa;
    border-left-color: #667eea;
    color: #667eea;
}

.sidebar-item.active {
    background: #e3f2fd;
    border-left-color: #667eea;
    color: #667eea;
}

/* 主内容区域 */
.main-content {
    margin-left: 0;
    transition: margin-left 0.3s ease;
    min-height: 100vh;
}

.main-content.sidebar-open {
    margin-left: 300px;
}

/* 顶部栏 */
.top-bar {
    display: flex;
    justify-content: space-between;
    align-items: center;
    background: rgba(255, 255, 255, 0.95);
    backdrop-filter: blur(10px);
    padding: 15px 25px;
    border-radius: 12px;
    margin-bottom: 20px;
    box-shadow: 0 4px 20px rgba(0,0,0,0.1);
}

.user-info {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 8px 12px;
    border-radius: 8px;
    transition: all 0.3s ease;
}

.user-avatar {
    width: 40px;
    height: 40px;
    border-radius: 50%;
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
    display: flex;
    align-items: center;
    justify-content: center;
    font-weight: 600;
    font-size: 16px;
}

/* 响应式侧边栏 */
@media (max-width: 768px) {
    .sidebar {
        width: 280px;
    }

    .main-content.sidebar-open {
        margin-left: 0;
    }

    .sidebar.open + .container .main-content::after {
        content: '';
        position: fixed;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        background: rgba(0,0,0,0.5);
        z-index: 999;
    }
}
`;

// 搜索框样式
const searchStyles = `
/* 搜索框样式 */
.search-box {
    position: relative;
    margin-bottom: 25px;
}

.search-input {
    width: 100%;
    padding: 12px 45px 12px 16px;
    border: 2px solid #e9ecef;
    border-radius: 25px;
    font-size: 16px;
    background-color: #f8f9fa;
    transition: all 0.3s ease;
}

.search-input:focus {
    outline: none;
    border-color: #667eea;
    background-color: white;
    box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
}

.search-icon {
    position: absolute;
    right: 15px;
    top: 50%;
    transform: translateY(-50%);
    font-size: 18px;
    color: #adb5bd;
}
`;

// 表格样式
const tableStyles = `
/* 表格和列表样式 */
.table {
    width: 100%;
    border-collapse: collapse;
    margin-top: 20px;
}

.table th,
.table td {
    padding: 12px 15px;
    text-align: left;
    border-bottom: 1px solid #e9ecef;
}

.table th {
    background-color: #f8f9fa;
    font-weight: 600;
    color: #2c3e50;
}

.table tbody tr:hover {
    background-color: #f8f9fa;
}

.table-responsive {
    overflow-x: auto;
}

/* 徽章样式 */
.badge {
    display: inline-block;
    padding: 4px 8px;
    border-radius: 4px;
    font-size: 0.75rem;
    font-weight: 600;
    text-transform: uppercase;
    text-align: center;
    white-space: nowrap;
}

.badge-admin {
    background-color: #dc3545;
    color: white;
}

.badge-user {
    background-color: #28a745;
    color: white;
}

.badge-success {
    background-color: #28a745;
    color: white;
}

.badge-secondary {
    background-color: #6c757d;
    color: white;
}

.badge-dingtalk {
    background-color: #1890ff;
    color: white;
}

.badge-feishu {
    background-color: #00d4aa;
    color: white;
}

.badge-custom {
    background-color: #6f42c1;
    color: white;
}

/* 邮件列表样式 */
.email-item {
    border: 1px solid #e9ecef;
    border-radius: 8px;
    padding: 20px;
    margin-bottom: 15px;
    background: white;
    transition: all 0.3s ease;
    cursor: pointer;
}

.email-item:hover {
    box-shadow: 0 4px 20px rgba(0,0,0,0.1);
    transform: translateY(-2px);
}

.email-header {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    margin-bottom: 10px;
}

.email-sender {
    font-weight: 600;
    color: #2c3e50;
    font-size: 16px;
}

.email-time {
    color: #6c757d;
    font-size: 14px;
}

.email-subject {
    font-size: 18px;
    font-weight: 600;
    color: #495057;
    margin-bottom: 8px;
}

.email-preview {
    color: #6c757d;
    font-size: 14px;
    line-height: 1.4;
    max-height: 40px;
    overflow: hidden;
}

.email-attachments {
    display: flex;
    align-items: center;
    gap: 5px;
    margin-top: 10px;
    color: #667eea;
    font-size: 14px;
}

/* 响应式表格 */
@media (max-width: 768px) {
    .table {
        font-size: 14px;
    }

    .table th,
    .table td {
        padding: 8px 10px;
    }

    .email-header {
        flex-direction: column;
        align-items: flex-start;
        gap: 5px;
    }
}
`;

// 模态框样式
const modalStyles = `
/* 模态框样式 */
.modal {
    display: none;
    position: fixed;
    z-index: 2000;
    left: 0;
    top: 0;
    width: 100%;
    height: 100%;
    background-color: rgba(0,0,0,0.5);
    backdrop-filter: blur(5px);
}

.modal.show {
    display: flex;
    align-items: center;
    justify-content: center;
}

.modal-content {
    background-color: white;
    border-radius: 12px;
    padding: 0;
    width: 90%;
    max-width: 500px;
    max-height: 90vh;
    overflow-y: auto;
    box-shadow: 0 20px 60px rgba(0,0,0,0.3);
    animation: modalSlideIn 0.3s ease;
}

.modal-content.large {
    max-width: 800px;
}

.modal-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 20px 25px;
    border-bottom: 1px solid #e9ecef;
    background: #f8f9fa;
    border-radius: 12px 12px 0 0;
}

.modal-title {
    margin: 0;
    color: #2c3e50;
    font-weight: 600;
}

.close-btn {
    background: none;
    border: none;
    font-size: 24px;
    cursor: pointer;
    color: #6c757d;
    padding: 0;
    width: 30px;
    height: 30px;
    display: flex;
    align-items: center;
    justify-content: center;
    border-radius: 50%;
    transition: all 0.3s ease;
}

.close-btn:hover {
    background-color: #e9ecef;
    color: #495057;
}

.modal form {
    padding: 25px;
}

@keyframes modalSlideIn {
    from {
        opacity: 0;
        transform: translateY(-50px);
    }
    to {
        opacity: 1;
        transform: translateY(0);
    }
}

/* 响应式模态框 */
@media (max-width: 768px) {
    .modal-content {
        width: 95%;
        margin: 20px;
    }

    .modal-header {
        padding: 15px 20px;
    }

    .modal form {
        padding: 20px;
    }
}
`;

// 分页样式
const paginationStyles = `
/* 分页样式 */
.pagination {
    display: flex;
    justify-content: center;
    align-items: center;
    gap: 10px;
    margin-top: 30px;
}

.pagination button {
    padding: 8px 12px;
    border: 1px solid #e9ecef;
    background: white;
    color: #6c757d;
    border-radius: 6px;
    cursor: pointer;
    transition: all 0.3s ease;
    min-width: 40px;
}

.pagination button:hover {
    background: #f8f9fa;
    border-color: #667eea;
    color: #667eea;
}

.pagination button.active {
    background: #667eea;
    color: white;
    border-color: #667eea;
}

.pagination button:disabled {
    opacity: 0.5;
    cursor: not-allowed;
}

.pagination-info {
    color: #6c757d;
    font-size: 14px;
    margin: 0 15px;
}
`;

// 响应式样式
const responsiveStyles = `
/* 响应式设计 */
@media (max-width: 1200px) {
    .container {
        padding: 15px;
    }
}

@media (max-width: 768px) {
    .container {
        padding: 10px;
    }

    .card {
        padding: 20px;
        border-radius: 12px;
    }

    .btn {
        padding: 10px 20px;
        font-size: 14px;
    }

    .form-control {
        padding: 10px 14px;
        font-size: 16px; /* 防止iOS缩放 */
    }

    .search-input {
        font-size: 16px; /* 防止iOS缩放 */
    }
}

@media (max-width: 480px) {
    .header h1 {
        font-size: 1.8rem;
    }

    .top-bar {
        padding: 12px 15px;
        flex-direction: column;
        gap: 10px;
        align-items: stretch;
    }

    .user-info {
        justify-content: center;
    }
}
`;

// 动画样式
const animationStyles = `
/* 动画效果 */
@keyframes fadeIn {
    from {
        opacity: 0;
        transform: translateY(20px);
    }
    to {
        opacity: 1;
        transform: translateY(0);
    }
}

@keyframes slideInRight {
    from {
        opacity: 0;
        transform: translateX(30px);
    }
    to {
        opacity: 1;
        transform: translateX(0);
    }
}

@keyframes pulse {
    0% {
        transform: scale(1);
    }
    50% {
        transform: scale(1.05);
    }
    100% {
        transform: scale(1);
    }
}

.fade-in {
    animation: fadeIn 0.5s ease;
}

.slide-in-right {
    animation: slideInRight 0.3s ease;
}

.pulse {
    animation: pulse 2s infinite;
}

/* 加载状态 */
.loading {
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 40px;
    color: #6c757d;
}

.loading::after {
    content: '';
    width: 20px;
    height: 20px;
    border: 2px solid #e9ecef;
    border-top: 2px solid #667eea;
    border-radius: 50%;
    animation: spin 1s linear infinite;
    margin-left: 10px;
}

@keyframes spin {
    0% { transform: rotate(0deg); }
    100% { transform: rotate(360deg); }
}
`;

/**
 * 获取所有样式
 */
export async function getStyles(): Promise<string> {
    return [
        baseStyles,
        cardStyles,
        headerStyles,
        formStyles,
        buttonStyles,
        tabStyles,
        sidebarStyles,
        searchStyles,
        tableStyles,
        modalStyles,
        paginationStyles,
        responsiveStyles,
        animationStyles
    ].join('\n\n');
}
