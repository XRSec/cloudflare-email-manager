// 视图组件导出
export { default as LoginView } from './auth/LoginView.vue'

// 共享视图
export { default as DashboardView } from './shared/dashboard/DashboardView.vue'
export { default as NotFoundView } from './shared/error/NotFoundView.vue'

// 管理员视图（精简）
export { default as AdminAllEmailsView } from './admin/emails/AllEmailsView.vue'
export { default as AdminForwardRulesView } from './admin/mailboxes/ForwardRulesView.vue'
export { default as AdminSystemSettingsView } from './admin/settings/SystemSettingsView.vue'
export { default as AdminDebugView } from './admin/settings/DebugView.vue'

// 共享组件
export { default as MainLayout } from './shared/layouts/MainLayout.vue'
export { default as AppLoadingSpinner } from './shared/components/AppLoadingSpinner.vue'
export { default as DataTable } from './shared/components/DataTable.vue'
export { default as SearchBox } from './shared/components/SearchBox.vue'
