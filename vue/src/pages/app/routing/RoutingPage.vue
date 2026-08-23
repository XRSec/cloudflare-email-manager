<template>
  <div class="routing-page">
    <PageHeader title="🧭 消息路由"/>

    <PageStates
        :loading="loading"
        :error="error"
        :is-empty="false"
        loading-text="正在加载消息路由..."
        @retry="loadPageData"
    />

    <div v-if="!loading && !error" class="routing-content">
      <section class="save-bar">
        <div>
          <strong>路由配置</strong>
          <span>编辑、启停、删除会先保留在当前页面，点击保存后统一生效。</span>
        </div>
        <button type="button" class="action-button primary" :disabled="saving" @click="saveRoutingConfig">
          {{ saving ? '保存中...' : '保存全部配置' }}
        </button>
      </section>

      <section class="summary-grid">
        <article class="summary-card">
          <div class="summary-eyebrow">默认 Webhook</div>
          <div class="summary-title">{{ defaultWebhookEnabled ? selectedDefaultChannelNames : '已停用' }}</div>
          <p class="summary-copy">{{
              defaultWebhookEnabled ? defaultWebhookModeLabel : '默认 Webhook 规则未启用'
            }}</p>
        </article>

        <article class="summary-card accent-card">
          <div class="summary-eyebrow">转发日志</div>
          <div class="summary-title">{{ forwardStats.success }} / {{ forwardStats.total }}</div>
          <div class="log-stats compact">
            <div class="log-stat"><span>总数</span><strong>{{ forwardStats.total }}</strong></div>
            <div class="log-stat success"><span>成功</span><strong>{{ forwardStats.success }}</strong></div>
            <div class="log-stat failed"><span>失败</span><strong>{{ forwardStats.failed }}</strong></div>
          </div>
        </article>

        <article class="summary-card">
          <div class="summary-eyebrow">默认邮件转发</div>
          <div class="summary-title">{{ emailForwardDefault.enabled ? emailForwardDefault.targetEmail : '已停用' }}</div>
          <p class="summary-copy">{{ emailForwardDefault.enabled ? emailForwardDefaultModeLabel : '默认邮件转发规则未启用' }}</p>
        </article>
      </section>

      <section class="routing-section">
        <article class="panel">
          <div class="panel-head">
            <div class="panel-title">Webhook 通道</div>
            <div class="panel-actions">
              <button type="button" class="action-button secondary" :disabled="saving" @click="addChannel">新增通道
              </button>
            </div>
          </div>

          <div class="channel-list">
            <div v-for="(channel, index) in webhookChannels" :key="channel.id" class="channel-card">
              <div class="channel-head">
                <div class="channel-title-row">
                  <div class="channel-name">{{ channel.name || `通道 ${index + 1}` }}</div>
                  <span class="channel-type-pill">{{ webhookTypeLabel(channel.type) }}</span>
                </div>
                <div class="channel-actions">
                  <button type="button" class="mini-action" :disabled="saving" @click="openEditChannel(channel)">
                    编辑
                  </button>
                  <button type="button" class="mini-action"
                          :disabled="isDefaultChannel(channel) || webhookChannels.length === 1"
                          @click="removeChannel(channel.id)">
                    删除
                  </button>
                </div>
              </div>
            </div>
          </div>

          <div class="form-actions">
            <button type="button" class="action-button secondary" :disabled="saving" @click="resetChannels">重置
            </button>
          </div>
        </article>

        <article class="panel">
          <div class="panel-head">
            <div class="panel-title">默认 Webhook 规则</div>
          </div>

          <article class="rule-card" :class="{ disabled: !defaultWebhookEnabled }">
            <div class="rule-card-top">
              <div class="rule-title-group">
                <h4>默认 Webhook</h4>
              </div>
              <div class="rule-inline-actions">
                <button type="button" class="mini-action state-action" :class="{ active: defaultWebhookEnabled }"
                        @click="toggleDefaultWebhookEnabled">{{ defaultWebhookEnabled ? '启用' : '停用' }}
                </button>
                <button type="button" class="mini-action" @click="openDefaultWebhookEditor">编辑</button>
                <button type="button" class="mini-action" @click="resetDefaultWebhookRule">重置</button>
              </div>
            </div>

            <div class="rule-summary-grid">
              <div class="rule-summary-item">
                <span class="target-label">引用通道</span>
                <strong>{{ selectedDefaultChannelNames }}</strong>
              </div>
              <div class="rule-summary-item conditions">
                <span class="target-label">发送策略</span>
                <div class="condition-chip-list compact">
                  <span class="condition-chip">{{ defaultWebhookModeLabel }}</span>
                </div>
              </div>
            </div>
          </article>
        </article>

        <article class="panel">
          <div class="panel-head">
            <div class="panel-title">Webhook 规则</div>
            <div class="panel-actions">
              <button type="button" class="action-button primary" @click="openCreateRule('webhook')">新增规则
              </button>
            </div>
          </div>

          <div v-if="webhookRules.length === 0" class="empty-panel">
            <div class="empty-icon">📭</div>
            <h4>暂无 Webhook 规则</h4>
          </div>

          <div v-else class="rules-grid">
            <article v-for="rule in webhookRules" :key="rule.id" class="rule-card"
                     :class="{ disabled: !rule.enabled }">
              <div class="rule-card-top">
                <div class="rule-title-group">
                  <h4>{{ rule.name }}</h4>
                </div>
                <div class="rule-inline-actions">
                  <button type="button" class="mini-action state-action" :class="{ active: rule.enabled }"
                          @click="toggleWebhookRule(rule)">{{ rule.enabled ? '启用' : '停用' }}
                  </button>
                  <button type="button" class="mini-action" @click="openEditRule(rule)">编辑</button>
                  <button type="button" class="mini-action danger" @click="deleteWebhookRule(rule.id)">删除
                  </button>
                </div>
              </div>

              <div class="rule-summary-grid">
                <div class="rule-summary-item">
                  <span class="target-label">引用通道</span>
                  <strong>{{ formatChannelNames(rule.targetChannelIds) }}</strong>
                </div>
                <div class="rule-summary-item conditions">
                  <span class="target-label">匹配条件</span>
                  <div class="condition-chip-list compact">
                    <span v-for="chip in getRuleConditionChips(rule)" :key="chip" class="condition-chip">{{
                        chip
                      }}</span>
                  </div>
                </div>
              </div>
            </article>
          </div>
        </article>
      </section>
      <section class="routing-notice">
        <div class="notice-mark">i</div>
        <div class="notice-content">
          <h3>邮件转发说明</h3>
          <p>外部邮件转发服务暂不可用，但可以在本系统已接收的域名之间互转。</p>
          <div class="notice-example">
            <span>{{ forwardingNoticeDomains[0] }}</span>
            <strong>↔</strong>
            <span>{{ forwardingNoticeDomains[1] }}</span>
          </div>
        </div>
      </section>
      <section class="routing-section">
        <article class="panel">
          <div class="panel-head">
            <div>
              <div class="panel-title">邮件通道</div>
              <p class="panel-subtitle">按发件域名配置邮件投递 API Key，用于邮件通道转发。</p>
            </div>
            <div class="panel-actions">
              <button type="button" class="action-button secondary" :disabled="saving" @click="addMailChannelRow">新增通道</button>
            </div>
          </div>

          <div v-if="mailChannelRows.length === 0" class="mail-channel-empty">
            <strong>未配置邮件通道</strong>
            <span>新增通道后，邮件通道转发会按发件人域名选择对应 API Key。</span>
          </div>

          <div v-else class="mail-channel-list">
            <div v-for="channel in mailChannelRows" :key="channel.id" class="mail-channel-card">
              <div class="channel-head">
                <div class="channel-title-row">
                  <div class="channel-name">{{ channel.name || `邮件通道 ${channel.id}` }}</div>
                  <span class="channel-type-pill">{{ mailChannelTypeLabel(channel.type) }}</span>
                </div>
                <div class="channel-actions">
                  <button type="button" class="mini-action" :disabled="saving" @click="openEditMailChannel(channel)">编辑</button>
                  <button type="button" class="mini-action danger" :disabled="saving" @click="removeMailChannelRow(channel.id)">删除</button>
                </div>
              </div>
            </div>
          </div>

          <div class="form-actions">
            <button type="button" class="action-button secondary" :disabled="saving" @click="resetMailChannels">重置</button>
          </div>
        </article>

        <article class="panel">
          <div class="panel-head">
            <div class="panel-title">默认邮件转发规则</div>
          </div>

          <article class="rule-card" :class="{ disabled: !emailForwardDefault.enabled }">
            <div class="rule-card-top">
              <div class="rule-title-group">
                <h4>默认邮件转发</h4>
              </div>
              <div class="rule-inline-actions">
                <button type="button" class="mini-action state-action" :class="{ active: emailForwardDefault.enabled }"
                        @click="toggleEmailForwardDefaultEnabled">{{ emailForwardDefault.enabled ? '启用' : '停用' }}
                </button>
                <button type="button" class="mini-action" @click="openEmailForwardDefaultEditor">编辑</button>
                <button type="button" class="mini-action" @click="resetEmailForwardDefaultRule">重置</button>
              </div>
            </div>

            <div class="rule-summary-grid">
              <div class="rule-summary-item">
                <span class="target-label">转发到</span>
                <strong>{{ emailForwardDefault.targetEmail || '未配置' }}</strong>
              </div>
              <div class="rule-summary-item conditions">
                <span class="target-label">转发策略</span>
                <div class="condition-chip-list compact">
                  <span class="condition-chip">{{ emailForwardDefaultModeLabel }}</span>
                </div>
              </div>
            </div>
          </article>
        </article>

        <article class="panel">
          <div class="panel-head">
            <div class="panel-title">邮件转发规则</div>
            <div class="panel-actions">
              <button type="button" class="action-button primary" @click="openCreateRule('email_forward')">新增规则</button>
            </div>
          </div>

          <div v-if="emailForwardRules.length === 0" class="empty-panel">
            <div class="empty-icon">📭</div>
            <h4>暂无邮件转发规则</h4>
          </div>

          <div v-else class="rules-grid">
            <article v-for="rule in emailForwardRules" :key="rule.id" class="rule-card"
                     :class="{ disabled: !rule.enabled }">
              <div class="rule-card-top">
                <div class="rule-title-group">
                  <h4>{{ rule.name }}</h4>
                </div>
                <div class="rule-inline-actions">
                  <button type="button" class="mini-action state-action" :class="{ active: rule.enabled }"
                          @click="toggleEmailForwardRule(rule)">{{ rule.enabled ? '启用' : '停用' }}
                  </button>
                  <button type="button" class="mini-action" @click="openEditRule(rule)">编辑</button>
                  <button type="button" class="mini-action danger" @click="deleteEmailForwardRule(rule.id)">删除</button>
                </div>
              </div>

              <div class="rule-summary-grid">
                <div class="rule-summary-item">
                  <span class="target-label">转发到</span>
                  <strong>{{ rule.targetEmail }}</strong>
                  <span class="condition-chip">{{ forwardTypeLabel(rule.targetForwardType) }}</span>
                </div>
                <div class="rule-summary-item conditions">
                  <span class="target-label">匹配条件</span>
                  <div class="condition-chip-list compact">
                    <span v-for="chip in getRuleConditionChips(rule)" :key="chip" class="condition-chip">{{
                        chip
                      }}</span>
                  </div>
                </div>
              </div>
            </article>
          </div>
        </article>

        <article class="panel logs-panel">
          <div class="panel-head">
            <div class="panel-title">转发日志</div>
            <div class="panel-actions">
              <button type="button" class="action-button secondary" :disabled="logsLoading"
                      @click="loadForwardLogs(logPagination.page, { forceRefresh: true })">
                {{ logsLoading ? '刷新中...' : '刷新' }}
              </button>
            </div>
          </div>

          <div class="log-stats">
            <div class="log-stat"><span>总数</span><strong>{{ forwardStats.total }}</strong></div>
            <div class="log-stat success"><span>成功</span><strong>{{ forwardStats.success }}</strong></div>
            <div class="log-stat failed"><span>失败</span><strong>{{ forwardStats.failed }}</strong></div>
          </div>

          <div v-if="logsLoading && logs.length === 0" class="empty-panel">
            <div class="empty-icon">📭</div>
            <h4>正在加载日志</h4>
          </div>

          <div v-else-if="logs.length === 0" class="empty-panel">
            <div class="empty-icon">📭</div>
            <h4>暂无转发日志</h4>
          </div>

          <div v-else class="logs-list">
            <article v-for="log in logs" :key="log.id" class="log-card clickable-card" @click="openLogDetail(log.id)">
              <div class="log-status-cell">
                <span class="status-pill" :class="Number(log.status) === 0 ? 'status-live' : 'status-failed'">
                  {{ Number(log.status) === 0 ? '成功' : '失败' }}
                </span>
              </div>

              <div class="log-main-cell">
                <h4>{{ log.subject || '无主题' }}</h4>
                <div class="log-address-row">
                  <span>{{ log.from_address || '未记录发件人' }}</span>
                  <span>→</span>
                  <span>{{ log.to_address || '未记录收件人' }}</span>
                </div>
              </div>

              <div class="log-target-cell">
                <span class="target-label">目标</span>
                <strong>{{ getLogChannelLabel(log) }}</strong>
              </div>

              <div class="log-time-cell">
                <span class="target-label">发送时间 ({{ configuredTimeZoneLabel }})</span>
                <strong>{{ formatDateTime(log.sent_at) }}</strong>
              </div>

              <div class="log-action-cell">
                <button type="button" class="action-button ghost" @click.stop="openLogDetail(log.id)">查看详情</button>
                <button type="button" class="action-button ghost danger" :disabled="logsLoading"
                        @click.stop="deleteForwardLog(log.id)">删除
                </button>
              </div>
            </article>
          </div>

          <Pagination v-if="logPagination.total > logPagination.limit" :pagination="logPagination"
                      @change-page="changeLogPage" @change-page-size="changeLogPageSize"/>
        </article>
      </section>
    </div>

    <Modal :show="ruleEditorVisible" :title="ruleEditorTitle" size="large" @close="closeRuleEditor">
      <form class="rule-editor-form" @submit.prevent="saveRuleEditor">
        <div class="editor-grid">
          <FormField v-model="ruleEditor.name" label="规则名称" type="text" placeholder="规则名称"/>

          <div class="form-group">
            <label for="editor-match-mode">匹配方式</label>
            <select id="editor-match-mode" v-model="ruleEditor.matchMode" class="form-control">
              <option value="all">全部条件匹配</option>
              <option value="any">任一条件匹配</option>
            </select>
          </div>

          <FormField v-model="ruleEditor.senderPattern" label="发件人包含" type="text" placeholder="billing@"/>
          <FormField v-model="ruleEditor.recipientPattern" label="收件人包含" type="text" placeholder="dev@"/>
          <FormField v-model="ruleEditor.subjectPattern" label="主题包含" type="text" placeholder="Alert"/>
          <FormField v-model="ruleEditor.contentPattern" label="正文包含" type="text" placeholder="error"/>

          <div v-if="ruleEditor.category === 'webhook'" class="editor-wide form-group">
            <label for="editor-action">策略</label>
            <select id="editor-action" v-model="ruleEditor.action" class="form-control">
              <option value="send">发送</option>
              <option value="ignore">忽略</option>
            </select>
          </div>

          <div v-if="ruleEditor.category === 'webhook' && ruleEditor.action === 'send'" class="editor-wide form-group">
            <label>引用通道</label>
            <div class="channel-reference-list">
              <button
                  v-for="channel in webhookChannels"
                  :key="channel.id"
                  type="button"
                  class="channel-reference-chip"
                  :class="{ active: ruleEditor.targetChannelIds.includes(channel.id) }"
                  @click="toggleRuleEditorChannel(channel.id)"
              >
                {{ channel.name }}
              </button>
            </div>
          </div>

          <template v-else-if="ruleEditor.category !== 'webhook'">
            <div class="form-group">
              <label for="editor-forward-type">转发方式</label>
              <select id="editor-forward-type" v-model="ruleEditor.targetForwardType" class="form-control">
                <option value="internal">站内转发</option>
                <option value="cf">CF 转发</option>
                <option value="resend">Resend 转发</option>
              </select>
            </div>
            <FormField
                v-model="ruleEditor.targetFromAddress"
                label="发件人"
                type="email"
                placeholder="cem@example.com"
            />
            <FormField
                v-model="ruleEditor.targetEmail"
                label="收件人"
                type="email"
                placeholder="archive@example.com"
            />
          </template>
        </div>
      </form>

      <template #footer>
        <Button variant="secondary" @click="closeRuleEditor">取消</Button>
        <Button variant="primary" @click="saveRuleEditor" :disabled="editorSaving">
          {{ editorSaving ? '应用中...' : '应用' }}
        </Button>
      </template>
    </Modal>

    <Modal :show="emailForwardDefaultEditorVisible" title="编辑默认邮件转发规则" size="large"
           @close="closeEmailForwardDefaultEditor">
      <form class="incoming-default-editor-form" @submit.prevent="saveEmailForwardDefaultEditor">
        <div class="editor-grid">
          <div class="form-group">
            <label for="incoming-default-forward-type">转发方式</label>
            <select id="incoming-default-forward-type" v-model="emailForwardDefaultEditor.targetForwardType"
                    class="form-control">
              <option value="internal">站内转发</option>
              <option value="cf">CF 转发</option>
              <option value="resend">Resend 转发</option>
            </select>
          </div>
          <FormField
              v-model="emailForwardDefaultEditor.targetFromAddress"
              label="发件人"
              type="email"
              placeholder="cem@example.com"
          />
          <FormField
              v-model="emailForwardDefaultEditor.targetEmail"
              label="收件人"
              type="email"
              placeholder="archive@example.com"
          />
          <div class="editor-wide form-group">
            <label>转发策略</label>
            <div class="mode-selector">
              <button type="button" class="mode-button" :class="{ active: emailForwardDefaultEditor.mode === 'always' }"
                      @click="emailForwardDefaultEditor.mode = 'always'">
                始终转发所有邮件
              </button>
              <button type="button" class="mode-button" :class="{ active: emailForwardDefaultEditor.mode === 'unmatched' }"
                      @click="emailForwardDefaultEditor.mode = 'unmatched'">
                仅未命中时转发
              </button>
            </div>
          </div>
        </div>
      </form>

      <template #footer>
        <Button variant="secondary" @click="closeEmailForwardDefaultEditor">取消</Button>
        <Button variant="primary" @click="saveEmailForwardDefaultEditor">应用</Button>
      </template>
    </Modal>

    <Modal :show="defaultWebhookEditorVisible" title="编辑默认 Webhook 规则" size="large"
           @close="closeDefaultWebhookEditor">
      <form class="default-notification-editor-form" @submit.prevent="saveDefaultWebhookEditor">
        <div class="editor-grid">
          <div class="editor-wide form-group">
            <label>引用通道</label>
            <div class="channel-reference-list">
              <button
                  v-for="channel in webhookChannels"
                  :key="channel.id"
                  type="button"
                  class="channel-reference-chip"
                  :class="{ active: defaultWebhookEditor.channelIds.includes(channel.id) }"
                  @click="toggleDefaultWebhookEditorChannel(channel.id)"
              >
                {{ channel.name }}
              </button>
            </div>
          </div>

          <div class="editor-wide form-group">
            <label>发送策略</label>
            <div class="mode-selector">
              <button type="button" class="mode-button" :class="{ active: defaultWebhookEditor.mode === 'always' }"
                      @click="defaultWebhookEditor.mode = 'always'">
                始终发送所有邮件
              </button>
              <button type="button" class="mode-button"
                      :class="{ active: defaultWebhookEditor.mode === 'unmatched' }"
                      @click="defaultWebhookEditor.mode = 'unmatched'">
                仅未命中时发送
              </button>
            </div>
          </div>
        </div>
      </form>

      <template #footer>
        <Button variant="secondary" @click="closeDefaultWebhookEditor">取消</Button>
        <Button variant="primary" @click="saveDefaultWebhookEditor">应用</Button>
      </template>
    </Modal>

    <Modal :show="channelEditorVisible" :title="channelEditorTitle" size="large" @close="closeChannelEditor">
      <form class="channel-editor-form" @submit.prevent="saveChannelEditor">
        <div class="editor-grid">
          <FormField
              v-model="channelEditor.name"
              label="通道名称"
              type="text"
              placeholder="例如：财务钉钉群"
          />

          <div class="form-group">
            <label for="channel-editor-type">类型</label>
            <select id="channel-editor-type" v-model="channelEditor.type" class="form-control">
              <option value="dingtalk">钉钉</option>
              <option value="feishu">飞书</option>
              <option value="bark">Bark</option>
            </select>
          </div>

          <FormField
              v-model="channelEditor.url"
              label="Webhook URL"
              type="url"
              placeholder="https://oapi.dingtalk.com/robot/send?access_token=xxx"
          />
          <FormField
              v-model="channelEditor.secret"
              label="密钥（可选）"
              type="password"
              placeholder="用于钉钉加签或飞书签名"
          />
        </div>
      </form>

      <template #footer>
        <Button variant="secondary" @click="closeChannelEditor">取消</Button>
        <Button variant="primary" @click="saveChannelEditor">应用</Button>
      </template>
    </Modal>

    <Modal :show="mailChannelEditorVisible" :title="mailChannelEditorTitle" size="large" @close="closeMailChannelEditor">
      <form class="channel-editor-form" @submit.prevent="saveMailChannelEditor">
        <div class="editor-grid">
          <FormField
              v-model="mailChannelEditor.name"
              label="通道名称"
              type="text"
              placeholder="例如：主域名 Resend"
          />

          <div class="form-group">
            <label for="mail-channel-editor-type">类型</label>
            <select id="mail-channel-editor-type" v-model="mailChannelEditor.type" class="form-control">
              <option value="resend">Resend</option>
            </select>
          </div>

          <FormField
              v-model="mailChannelEditor.domain"
              label="发件域名"
              type="text"
              placeholder="example.com"
          />

          <div class="form-group">
            <label for="mail-channel-editor-token">API Key</label>
            <div class="token-input-wrap">
              <input
                  id="mail-channel-editor-token"
                  v-model="mailChannelEditor.token"
                  class="form-control"
                  :type="mailChannelEditor.tokenVisible ? 'text' : 'password'"
                  placeholder="re_xxxxxxxxxxxxxxxxx"
                  autocomplete="off"
              />
              <button type="button" class="token-visibility-button" @click="mailChannelEditor.tokenVisible = !mailChannelEditor.tokenVisible">
                {{ mailChannelEditor.tokenVisible ? '隐藏' : '显示' }}
              </button>
            </div>
          </div>
        </div>
      </form>

      <template #footer>
        <Button variant="secondary" @click="closeMailChannelEditor">取消</Button>
        <Button variant="primary" @click="saveMailChannelEditor">应用</Button>
      </template>
    </Modal>

    <Modal :show="logDetailVisible" title="转发日志详情" size="large" @close="closeLogDetail">
      <div v-if="detailLoading" class="empty-panel">
        <div class="empty-icon">📭</div>
        <h4>正在加载详情</h4>
      </div>
      <div v-else-if="selectedLog" class="detail-layout">
        <div class="detail-block detail-hero">
          <div class="detail-hero-main">
            <h4>{{ selectedLog.subject || '无主题' }}</h4>
            <p>{{ selectedLog.from_address || '未记录发件人' }} → {{ selectedLog.to_address || '未记录收件人' }}</p>
          </div>
          <div class="detail-hero-meta">
            <span>{{ formatDateTime(selectedLog.sent_at) }}</span>
            <strong>{{ getLogChannelLabel(selectedLog) }}</strong>
          </div>
          <span class="status-pill" :class="Number(selectedLog.status) === 0 ? 'status-live' : 'status-failed'">
              {{ Number(selectedLog.status) === 0 ? '成功' : '失败' }}
            </span>
        </div>

        <div class="detail-block">
          <h4>邮件与响应</h4>
          <div class="detail-message-grid">
            <div class="message-row">
              <span>发件人</span>
              <strong>{{ getLogDeliveryFrom(selectedLog) }}</strong>
            </div>
            <div class="message-row">
              <span>收件人</span>
              <strong>{{ getLogDeliveryTo(selectedLog) }}</strong>
            </div>
            <div class="message-row">
              <span>{{ getLogDeliveryTargetLabel(selectedLog) }}</span>
              <strong>{{ selectedLog.webhook_url || '未记录' }}</strong>
            </div>
            <div class="message-row">
              <span>响应码</span>
              <strong>{{ selectedLog.response_code ?? '未记录' }}</strong>
            </div>
            <div class="message-row">
              <span>邮件时间 ({{ configuredTimeZoneLabel }})</span>
              <strong>{{ formatDateTime(selectedLog.received_at || selectedLog.sent_at) }}</strong>
            </div>
            <div class="message-row">
              <span>邮件 ID</span>
              <strong>{{ selectedLog.email_id || '未记录' }}</strong>
            </div>
            <div v-if="selectedLog.error_message" class="message-row error-row">
              <span>错误信息</span>
              <strong>{{ selectedLog.error_message }}</strong>
            </div>
          </div>
        </div>

        <div v-if="selectedLog.content" class="detail-block">
          <h4>邮件内容</h4>
          <pre class="detail-content">{{ selectedLog.content }}</pre>
        </div>

        <div v-if="replayResult" class="detail-block">
          <h4>本次重发结果</h4>
          <div class="detail-message-grid">
            <div class="message-row" :class="{ 'error-row': !replayResult.success }">
              <span>状态</span>
              <strong>{{ replayResult.success ? '成功' : '失败' }}</strong>
            </div>
            <div class="message-row">
              <span>响应码</span>
              <strong>{{ replayResult.responseCode ?? '未返回' }}</strong>
            </div>
            <div class="message-row">
              <span>Webhook 类型</span>
              <strong>{{ replayResult.type || '未识别' }}</strong>
            </div>
            <div class="message-row">
              <span>目标</span>
              <strong>{{ replayResult.target || selectedLog.webhook_url || '未记录' }}</strong>
            </div>
            <div v-if="replayResult.errorMessage" class="message-row error-row">
              <span>错误输出</span>
              <strong>{{ replayResult.errorMessage }}</strong>
            </div>
          </div>
          <pre v-if="replayResult.debug" class="detail-content replay-output">{{
              formatReplayDebug(replayResult.debug)
            }}</pre>
        </div>
      </div>

      <template #footer>
        <Button variant="secondary" @click="replayForwardLog" :disabled="detailLoading">重发</Button>
        <Button variant="primary" @click="openEmailFromLog" :disabled="!selectedLog?.email_id">打开邮件</Button>
      </template>
    </Modal>
  </div>
</template>

<script setup lang="ts">
import {computed, onMounted, onUnmounted, ref} from 'vue'
import {useRouter} from 'vue-router'
import {PageHeader, PageStates, FormField, Button, Modal, Pagination} from '@/components'
import {api, get} from '@/composables/api-client'
import {systemApiService} from '@/composables/api-system'
import {
  API_CACHE_KEYS,
  API_CACHE_TTL,
  cachedApiRequest,
  invalidateApiCache,
  invalidateApiCacheByPrefix
} from '@/composables/api-cache'
import type {SystemConfig} from '@/types'
import {toast} from '@/utils/toast'
import {formatDateTime, getConfiguredTimeZoneLabel} from '@/utils/time'

type WebhookType = 'dingtalk' | 'feishu' | 'bark'
type MatchMode = 'all' | 'any'
type DefaultMode = 'always' | 'unmatched'
type RuleCategory = 'webhook' | 'email_forward'
type ForwardType = 'internal' | 'cf' | 'resend'
type WebhookAction = 'send' | 'ignore'
type MailChannelType = 'resend'

interface WebhookChannel {
  id: number
  name: string
  type: WebhookType
  url: string
  secret: string
  enabled: boolean
}

interface ChannelEditorState {
  id: number | null
  name: string
  type: WebhookType
  url: string
  secret: string
}

interface MailChannelRow {
  id: number
  name: string
  type: MailChannelType
  domain: string
  token: string
}

interface MailChannelEditorState {
  id: number | null
  name: string
  type: MailChannelType
  domain: string
  token: string
  tokenVisible: boolean
}

interface WebhookRule {
  id: number
  name: string
  enabled: boolean
  matchMode: MatchMode
  action: WebhookAction
  senderPattern: string
  recipientPattern: string
  subjectPattern: string
  contentPattern: string
  targetChannelIds: number[]
}

interface EmailForwardRule {
  id: number
  name: string
  enabled: boolean
  matchMode: MatchMode
  senderPattern: string
  recipientPattern: string
  subjectPattern: string
  contentPattern: string
  targetEmail: string
  targetFromAddress: string
  targetForwardType: ForwardType
}

interface RoutingRulesResponse {
  channels?: WebhookChannel[]
  mailChannels?: MailChannelRow[]
  webhookRules?: WebhookRule[]
  emailForwardRules?: EmailForwardRule[]
  defaultWebhookRule?: DefaultWebhookRule | null
  defaultEmailForwardRule?: DefaultEmailForwardRule | null
}

interface SavedRoutingRule {
  id: number
  category: RuleCategory
  name: string
  enabled: boolean
  matchMode: MatchMode
  action?: WebhookAction
  senderPattern: string
  recipientPattern: string
  subjectPattern: string
  contentPattern: string
  targetChannelIds?: number[]
  targetEmail?: string
  targetFromAddress?: string
  targetForwardType?: ForwardType
  isDefault?: boolean
  defaultMode?: DefaultMode
}

interface DefaultWebhookRule {
  id: number
  name: string
  enabled: boolean
  defaultMode: DefaultMode
  targetChannelIds: number[]
}

interface DefaultEmailForwardRule {
  id: number
  name: string
  enabled: boolean
  defaultMode: DefaultMode
  targetEmail: string
  targetFromAddress: string
  targetForwardType: ForwardType
}

interface RuleEditorState {
  id: number | null
  category: RuleCategory
  name: string
  enabled: boolean
  matchMode: MatchMode
  action: WebhookAction
  senderPattern: string
  recipientPattern: string
  subjectPattern: string
  contentPattern: string
  targetChannelIds: number[]
  targetEmail: string
  targetFromAddress: string
  targetForwardType: ForwardType
}

const router = useRouter()

const loading = ref(true)
const error = ref<string | null>(null)
const saving = ref(false)
const editorSaving = ref(false)
const logsLoading = ref(false)
const detailLoading = ref(false)
const ruleEditorVisible = ref(false)
const channelEditorVisible = ref(false)
const mailChannelEditorVisible = ref(false)
const defaultWebhookEditorVisible = ref(false)
const emailForwardDefaultEditorVisible = ref(false)
const logDetailVisible = ref(false)
const selectedLog = ref<any>(null)
const replayResult = ref<{
  success: boolean
  responseCode: number | null
  errorMessage: string | null
  target: string
  type: string
  debug: unknown
} | null>(null)
const forwardingNoticeDomains = ref<[string, string]>(['example.com', 'example.dev'])

const webhookChannels = ref<WebhookChannel[]>([])
const originalWebhookChannels = ref<WebhookChannel[]>([])
const channelEditor = ref<ChannelEditorState>(createEmptyChannelEditor())
let temporaryRoutingId = -1
let mailChannelRowId = 1

const mailChannelRows = ref<MailChannelRow[]>([])
const originalMailChannelRows = ref<MailChannelRow[]>([])
const mailChannelEditor = ref<MailChannelEditorState>(createEmptyMailChannelEditor())

const defaultWebhookRuleId = ref<number | null>(null)
const defaultEmailForwardRuleId = ref<number | null>(null)
const defaultWebhookEnabled = ref(false)
const defaultWebhookMode = ref<DefaultMode>('unmatched')
const defaultWebhookChannelIds = ref<number[]>([])
const defaultWebhookEditor = ref({
  mode: 'unmatched' as DefaultMode,
  channelIds: [] as number[]
})
const originalDefaultWebhookState = ref({
  enabled: false,
  mode: 'unmatched' as DefaultMode,
  channelIds: [] as number[]
})

const emailForwardDefault = ref({
  enabled: false,
  mode: 'unmatched' as DefaultMode,
  targetEmail: 'archive@example.com',
  targetFromAddress: '',
  targetForwardType: 'internal' as ForwardType
})
const emailForwardDefaultEditor = ref({
  mode: 'unmatched' as DefaultMode,
  targetEmail: '',
  targetFromAddress: '',
  targetForwardType: 'internal' as ForwardType
})
const originalEmailForwardDefault = ref({...emailForwardDefault.value})

const webhookRules = ref<WebhookRule[]>([])
const emailForwardRules = ref<EmailForwardRule[]>([])
const originalWebhookRules = ref<WebhookRule[]>([])
const originalEmailForwardRules = ref<EmailForwardRule[]>([])

const ruleEditor = ref<RuleEditorState>(createEmptyRuleEditor('webhook'))

const forwardStats = ref({
  total: 0,
  success: 0,
  failed: 0
})
const logs = ref<any[]>([])
const logPagination = ref({
  page: 1,
  limit: 20,
  total: 0,
  totalPages: 1
})

const selectedDefaultChannels = computed(() => (
    defaultWebhookChannelIds.value
        .map((id) => webhookChannels.value.find((channel) => channel.id === id))
        .filter((channel): channel is WebhookChannel => Boolean(channel))
))

const configuredTimeZoneLabel = computed(() => getConfiguredTimeZoneLabel())

const selectedDefaultChannelNames = computed(() => {
  if (selectedDefaultChannels.value.length === 0) {
    return '未选择通道'
  }
  return selectedDefaultChannels.value.map((channel) => channel.name).join(' / ')
})

const defaultWebhookModeLabel = computed(() => (
    defaultWebhookMode.value === 'always' ? '始终发送所有邮件' : '仅未命中时发送'
))

const emailForwardDefaultModeLabel = computed(() => (
    emailForwardDefault.value.mode === 'always' ? '始终转发所有邮件' : '仅未命中时转发'
))

const ruleEditorTitle = computed(() => (
    `${ruleEditor.value.id ? '编辑' : '新增'} ${ruleEditor.value.category === 'webhook' ? 'Webhook 规则' : '邮件转发规则'}`
))

const channelEditorTitle = computed(() => (
    `${channelEditor.value.id ? '编辑' : '新增'} Webhook 通道`
))

const mailChannelEditorTitle = computed(() => (
    `${mailChannelEditor.value.id ? '编辑' : '新增'} 邮件通道`
))

function createEmptyChannelEditor(): ChannelEditorState {
  return {
    id: null,
    name: '',
    type: 'dingtalk',
    url: '',
    secret: ''
  }
}

function createEmptyMailChannelEditor(): MailChannelEditorState {
  return {
    id: null,
    name: '',
    type: 'resend',
    domain: '',
    token: '',
    tokenVisible: false
  }
}

function createEmptyRuleEditor(category: RuleCategory): RuleEditorState {
  return {
    id: null,
    category,
    name: '',
    enabled: true,
    matchMode: 'all',
    action: 'send',
    senderPattern: '',
    recipientPattern: '',
    subjectPattern: '',
    contentPattern: '',
    targetChannelIds: [],
    targetEmail: '',
    targetFromAddress: '',
    targetForwardType: 'internal'
  }
}

const cloneChannels = (channels: WebhookChannel[]) => channels.map((channel) => ({...channel}))
const cloneWebhookRules = (rules: WebhookRule[]) => rules.map((rule) => ({
  ...rule,
  targetChannelIds: [...rule.targetChannelIds]
}))
const cloneEmailForwardRules = (rules: EmailForwardRule[]) => rules.map((rule) => ({...rule}))

const normalizeWebhookChannels = (channels: unknown): WebhookChannel[] => {
  if (!Array.isArray(channels)) return []

  const seen = new Set<number>()
  return channels
      .filter((channel): channel is Partial<WebhookChannel> => Boolean(channel) && typeof channel === 'object')
      .map((channel) => ({
        id: Number(channel.id),
        name: typeof channel.name === 'string' ? channel.name.trim() : '',
        type: (channel.type === 'feishu' || channel.type === 'bark' ? channel.type : 'dingtalk') as WebhookType,
        url: typeof channel.url === 'string' ? channel.url.trim() : '',
        secret: typeof channel.secret === 'string' ? channel.secret.trim() : '',
        enabled: true
      }))
      .filter((channel) => {
        if (!Number.isInteger(channel.id) || channel.id <= 0 || !channel.name || !channel.url || seen.has(channel.id)) {
          return false
        }
        seen.add(channel.id)
        return true
      })
}

const normalizeDomainValue = (value: string) => {
  const trimmed = value.trim().toLowerCase().replace(/^@+/, '')
  const domain = trimmed.includes('@') ? trimmed.split('@').pop() || '' : trimmed
  return domain.replace(/^@+/, '')
}

const validateDomainName = (value: string) => {
  const domain = normalizeDomainValue(value)
  const domainRegex = /^(?!-)(?:[a-z0-9-]{1,63}\.)+[a-z]{2,63}$/
  return domainRegex.test(domain) || '请输入有效域名，例如 example.com'
}

const parseMailChannels = (value: unknown): MailChannelRow[] => {
  if (!value) return []
  if (Array.isArray(value)) {
    return value
        .filter((channel): channel is Partial<MailChannelRow> => Boolean(channel) && typeof channel === 'object')
        .map((channel) => ({
          id: Number(channel.id),
          name: typeof channel.name === 'string' ? channel.name.trim() : '',
          type: 'resend' as MailChannelType,
          domain: normalizeDomainValue(typeof channel.domain === 'string' ? channel.domain : ''),
          token: typeof channel.token === 'string' ? channel.token.trim() : ''
        }))
        .filter((channel) => Number.isInteger(channel.id) && channel.id > 0 && channel.name && channel.domain && channel.token)
  }
  if (typeof value !== 'string' || !value.trim()) return []
  try {
    return parseMailChannels(JSON.parse(value))
  } catch {
    return []
  }
}

const cloneMailChannelRows = (rows: MailChannelRow[]) => rows.map((row) => ({...row}))

const getNextMailChannelId = () => Math.max(0, ...mailChannelRows.value.map((row) => row.id), mailChannelRowId - 1) + 1

const addMailChannelRow = () => {
  const nextId = getNextMailChannelId()
  mailChannelRowId = nextId + 1
  mailChannelEditor.value = {
    ...createEmptyMailChannelEditor(),
    id: nextId,
    name: `新邮件通道 ${mailChannelRows.value.length + 1}`
  }
  mailChannelEditorVisible.value = true
}

const removeMailChannelRow = (id: number) => {
  mailChannelRows.value = mailChannelRows.value.filter((row) => row.id !== id)
}

const resetMailChannels = () => {
  mailChannelRows.value = cloneMailChannelRows(originalMailChannelRows.value)
}

const openEditMailChannel = (channel: MailChannelRow) => {
  mailChannelEditor.value = {
    id: channel.id,
    name: channel.name,
    type: channel.type,
    domain: channel.domain,
    token: channel.token,
    tokenVisible: false
  }
  mailChannelEditorVisible.value = true
}

const closeMailChannelEditor = () => {
  mailChannelEditorVisible.value = false
}

const saveMailChannelEditor = () => {
  const name = mailChannelEditor.value.name.trim()
  const domain = normalizeDomainValue(mailChannelEditor.value.domain)
  const token = mailChannelEditor.value.token.trim()

  if (!name) {
    toast.error('通道名称不能为空')
    return
  }
  if (validateDomainName(domain) !== true) {
    toast.error('请输入有效域名，例如 example.com')
    return
  }
  if (!token) {
    toast.error('API Key 不能为空')
    return
  }

  const channel: MailChannelRow = {
    id: mailChannelEditor.value.id || getNextMailChannelId(),
    name,
    type: mailChannelEditor.value.type,
    domain,
    token
  }
  const index = mailChannelRows.value.findIndex((item) => item.id === channel.id)
  if (index >= 0) {
    mailChannelRows.value.splice(index, 1, channel)
  } else {
    mailChannelRows.value.unshift(channel)
  }
  closeMailChannelEditor()
}

const mailChannelTypeLabel = (type: MailChannelType) => {
  const labels: Record<MailChannelType, string> = {
    resend: 'Resend'
  }
  return labels[type] || type
}

const validateMailChannelConfig = () => {
  const invalidRow = mailChannelRows.value.find((row) => {
    const name = row.name.trim()
    const domain = normalizeDomainValue(row.domain)
    const token = row.token.trim()
    return !name || !domain || !token || validateDomainName(domain) !== true
  })

  if (invalidRow) {
    throw new Error('请补全邮件通道名称、发件域名和 API Key，并确认域名格式正确')
  }
}

const parseForwardingNoticeDomains = (value: unknown): [string, string] => {
  const fallback: [string, string] = ['example.com', 'example.dev']
  const rawDomains = Array.isArray(value)
      ? value
      : typeof value === 'string'
          ? (() => {
            try {
              const parsed = JSON.parse(value)
              return Array.isArray(parsed) ? parsed : value.split(',')
            } catch {
              return value.split(',')
            }
          })()
          : []

  const domains = Array.from(new Set(
      rawDomains
          .filter((item): item is string => typeof item === 'string')
          .map(normalizeDomainValue)
          .filter(Boolean)
  ))

  return [
    domains[0] || fallback[0],
    domains[1] || fallback[1]
  ]
}

const applySystemConfig = (config: Partial<SystemConfig> = {}) => {
  forwardingNoticeDomains.value = parseForwardingNoticeDomains(config.supported_emails)
  originalDefaultWebhookState.value = {
    enabled: defaultWebhookEnabled.value,
    mode: defaultWebhookMode.value,
    channelIds: [...defaultWebhookChannelIds.value]
  }
}

const invalidateRoutingPageCache = () => {
  invalidateApiCache([
    API_CACHE_KEYS.ROUTING_RULES,
    API_CACHE_KEYS.ROUTING_STATS
  ])
  invalidateApiCacheByPrefix('api:routing:forward_logs:')
}

const loadPageData = async (forceRefresh = false) => {
  loading.value = true
  error.value = null

  try {
    const configResponse = await systemApiService.getSystemConfig({forceRefresh})
    if (!configResponse.success) {
      throw new Error(configResponse.message || '获取系统配置失败')
    }

    const config = (configResponse.data?.config || configResponse.data || {}) as Partial<SystemConfig>
    applySystemConfig(config)
    await Promise.all([
      loadRoutingRules(forceRefresh),
      loadStats(forceRefresh),
      loadForwardLogs(1, {forceRefresh})
    ])
  } catch (err) {
    error.value = err instanceof Error ? err.message : '加载失败'
  } finally {
    loading.value = false
  }
}

const normalizeWebhookRule = (rule: WebhookRule): WebhookRule => ({
  id: Number(rule.id),
  name: rule.name || '',
  enabled: Boolean(rule.enabled),
  matchMode: rule.matchMode === 'any' ? 'any' : 'all',
  action: rule.action === 'ignore' ? 'ignore' : 'send',
  senderPattern: rule.senderPattern || '',
  recipientPattern: rule.recipientPattern || '',
  subjectPattern: rule.subjectPattern || '',
  contentPattern: rule.contentPattern || '',
  targetChannelIds: Array.isArray(rule.targetChannelIds) ? rule.targetChannelIds.map(Number).filter(Number.isInteger) : []
})

const normalizeEmailForwardRule = (rule: EmailForwardRule): EmailForwardRule => ({
  id: Number(rule.id),
  name: rule.name || '',
  enabled: Boolean(rule.enabled),
  matchMode: rule.matchMode === 'any' ? 'any' : 'all',
  senderPattern: rule.senderPattern || '',
  recipientPattern: rule.recipientPattern || '',
  subjectPattern: rule.subjectPattern || '',
  contentPattern: rule.contentPattern || '',
  targetEmail: rule.targetEmail || '',
  targetFromAddress: rule.targetFromAddress || '',
  targetForwardType: rule.targetForwardType === 'cf' || rule.targetForwardType === 'resend' ? rule.targetForwardType : 'internal'
})

const applyDefaultWebhookRule = (rule: DefaultWebhookRule | SavedRoutingRule | null | undefined) => {
  if (!rule) return

  defaultWebhookRuleId.value = Number(rule.id)
  defaultWebhookEnabled.value = Boolean(rule.enabled)
  defaultWebhookMode.value = rule.defaultMode === 'always' ? 'always' : 'unmatched'
  defaultWebhookChannelIds.value = Array.isArray(rule.targetChannelIds)
      ? rule.targetChannelIds.map(Number).filter(Number.isInteger)
      : []
  originalDefaultWebhookState.value = {
    enabled: defaultWebhookEnabled.value,
    mode: defaultWebhookMode.value,
    channelIds: [...defaultWebhookChannelIds.value]
  }
}

const applyDefaultEmailForwardRule = (rule: DefaultEmailForwardRule | SavedRoutingRule | null | undefined) => {
  if (!rule) return

  defaultEmailForwardRuleId.value = Number(rule.id)
  emailForwardDefault.value = {
    enabled: Boolean(rule.enabled),
    mode: rule.defaultMode === 'always' ? 'always' : 'unmatched',
    targetEmail: rule.targetEmail || '',
    targetFromAddress: rule.targetFromAddress || '',
    targetForwardType: rule.targetForwardType === 'cf' || rule.targetForwardType === 'resend' ? rule.targetForwardType : 'internal'
  }
  originalEmailForwardDefault.value = {...emailForwardDefault.value}
}

const loadRoutingRules = async (forceRefresh = false) => {
  const result = await cachedApiRequest(
      API_CACHE_KEYS.ROUTING_RULES,
      API_CACHE_TTL.ROUTING_RULES,
      async () => {
        const response = await api.post('/routing', {action: 'list'})
        return response.data
      },
      {forceRefresh}
  )

  if (!result.success || !result.data) {
    throw new Error(result.message || '获取消息路由规则失败')
  }

  applyRoutingData(result.data as RoutingRulesResponse)
}

const applyRoutingData = (data: RoutingRulesResponse) => {
  webhookChannels.value = normalizeWebhookChannels(data.channels)
  originalWebhookChannels.value = cloneChannels(webhookChannels.value)
  mailChannelRows.value = parseMailChannels(data.mailChannels || [])
  mailChannelRowId = getNextMailChannelId()
  originalMailChannelRows.value = cloneMailChannelRows(mailChannelRows.value)
  webhookRules.value = Array.isArray(data.webhookRules)
      ? data.webhookRules.map(normalizeWebhookRule)
      : []
  originalWebhookRules.value = cloneWebhookRules(webhookRules.value)
  emailForwardRules.value = Array.isArray(data.emailForwardRules)
      ? data.emailForwardRules.map(normalizeEmailForwardRule)
      : []
  originalEmailForwardRules.value = cloneEmailForwardRules(emailForwardRules.value)
  applyDefaultWebhookRule(data.defaultWebhookRule)
  applyDefaultEmailForwardRule(data.defaultEmailForwardRule)
}

const loadStats = async (forceRefresh = false) => {
  const response = await cachedApiRequest(
      API_CACHE_KEYS.ROUTING_STATS,
      API_CACHE_TTL.ROUTING_STATS,
      () => get('/dashboard/stats'),
      {forceRefresh}
  )

  if (response.success && response.data?.stats?.forward) {
    forwardStats.value = {
      total: response.data.stats.forward.total || 0,
      success: response.data.stats.forward.success || 0,
      failed: response.data.stats.forward.failed || 0
    }
  }
}

const loadForwardLogs = async (page = 1, options: { forceRefresh?: boolean } = {}) => {
  logsLoading.value = true
  try {
    const limit = logPagination.value.limit
    const response = await cachedApiRequest(
        API_CACHE_KEYS.routingLogs(page, limit),
        API_CACHE_TTL.ROUTING_LOGS,
        () => get('/dashboard/forward-logs', {params: {page, limit}}),
        options
    )

    if (!response.success || !response.data) {
      throw new Error(response.message || '获取日志失败')
    }

    logs.value = response.data.items || []
    logPagination.value = {
      page: response.data.page || page,
      limit: response.data.limit || 20,
      total: response.data.total || 0,
      totalPages: response.data.totalPages || 1
    }
  } catch (err) {
    toast.error(err instanceof Error ? err.message : '获取日志失败')
  } finally {
    logsLoading.value = false
  }
}

const buildDefaultWebhookPayload = () => ({
  id: defaultWebhookRuleId.value || undefined,
  name: '默认 Webhook 规则',
  enabled: defaultWebhookEnabled.value,
  isDefault: true,
  defaultMode: defaultWebhookMode.value,
  matchMode: 'all' as MatchMode,
  senderPattern: '',
  recipientPattern: '',
  subjectPattern: '',
  contentPattern: '',
  targetChannelIds: [...defaultWebhookChannelIds.value],
  targetEmail: ''
})

const buildDefaultEmailForwardPayload = () => ({
  id: defaultEmailForwardRuleId.value || undefined,
  name: '默认邮件转发规则',
  enabled: emailForwardDefault.value.enabled,
  isDefault: true,
  defaultMode: emailForwardDefault.value.mode,
  matchMode: 'all' as MatchMode,
  senderPattern: '',
  recipientPattern: '',
  subjectPattern: '',
  contentPattern: '',
  targetChannelIds: [],
  targetEmail: emailForwardDefault.value.targetEmail.trim(),
  targetFromAddress: emailForwardDefault.value.targetFromAddress.trim(),
  targetForwardType: emailForwardDefault.value.targetForwardType
})

const validateRoutingConfig = () => {
  const channels = normalizeWebhookChannels(webhookChannels.value)
  const requiresWebhookChannel = defaultWebhookEnabled.value || webhookRules.value.some(
    (rule) => rule.enabled && rule.action === 'send'
  )
  if (channels.length === 0 && requiresWebhookChannel) {
    throw new Error('至少保留一个 Webhook 通道')
  }

  const channelIds = new Set(channels.map((channel) => channel.id))
  const ensureKnownChannels = (ids: number[]) => {
    if (ids.length === 0) {
      throw new Error('至少选择一个通道')
    }
    if (ids.some((id) => !channelIds.has(id))) {
      throw new Error('规则引用了不存在的 Webhook 通道')
    }
  }

  if (defaultWebhookEnabled.value || defaultWebhookChannelIds.value.length > 0) {
    ensureKnownChannels(defaultWebhookChannelIds.value)
  }
  webhookRules.value
    .filter((rule) => rule.enabled && rule.action === 'send')
    .forEach((rule) => ensureKnownChannels(rule.targetChannelIds))

  if (!emailForwardDefault.value.targetEmail.trim()) {
    throw new Error('默认收件人不能为空')
  }
  if (
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailForwardDefault.value.targetFromAddress.trim())
  ) {
    throw new Error('请输入有效的转发发件人邮箱')
  }

  emailForwardRules.value.forEach((rule) => {
    if (!rule.name.trim()) {
      throw new Error('规则名称不能为空')
    }
    if (!rule.targetEmail.trim()) {
      throw new Error('收件人不能为空')
    }
    if (
        !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(rule.targetFromAddress.trim())
    ) {
      throw new Error('请输入有效的转发发件人邮箱')
    }
  })

  return channels
}

const saveRoutingConfig = async () => {
  saving.value = true
  try {
    const channels = validateRoutingConfig()
    validateMailChannelConfig()
    const response = await api.post('/routing', {
      action: 'replace',
      config: {
        channels,
        mailChannels: mailChannelRows.value.map((channel) => ({
          id: channel.id,
          name: channel.name.trim(),
          type: channel.type,
          domain: normalizeDomainValue(channel.domain),
          token: channel.token.trim()
        })),
        webhookRules: webhookRules.value.map((rule) => ({...rule})),
        emailForwardRules: emailForwardRules.value.map((rule) => ({...rule})),
        defaultWebhookRule: buildDefaultWebhookPayload(),
        defaultEmailForwardRule: buildDefaultEmailForwardPayload()
      }
    })

    const result = response.data
    if (!result.success || !result.data) {
      throw new Error(result.message || '保存失败')
    }

    invalidateRoutingPageCache()
    applyRoutingData(result.data)
    toast.success(result.message || '消息路由配置已保存')
  } catch (err) {
    toast.error(err instanceof Error ? err.message : '保存失败')
  } finally {
    saving.value = false
  }
}

const resetChannels = () => {
  webhookChannels.value = cloneChannels(originalWebhookChannels.value)
}

const addChannel = () => {
  channelEditor.value = {
    ...createEmptyChannelEditor(),
    name: `新通道 ${webhookChannels.value.length + 1}`
  }
  channelEditorVisible.value = true
}

const isDefaultChannel = (_channel: WebhookChannel) => false

const removeChannel = (channelId: number) => {
  const channel = webhookChannels.value.find((item) => item.id === channelId)
  if (!channel || isDefaultChannel(channel) || webhookChannels.value.length === 1) {
    return
  }
  webhookChannels.value = webhookChannels.value.filter((channel) => channel.id !== channelId)
  defaultWebhookChannelIds.value = defaultWebhookChannelIds.value.filter((id) => id !== channelId)
  webhookRules.value = webhookRules.value.map((rule) => ({
    ...rule,
    targetChannelIds: rule.targetChannelIds.filter((id) => id !== channelId)
  }))
  toast.success('已从页面移除，保存后生效')
}

const openDefaultWebhookEditor = () => {
  defaultWebhookEditor.value = {
    mode: defaultWebhookMode.value,
    channelIds: [...defaultWebhookChannelIds.value]
  }
  defaultWebhookEditorVisible.value = true
}

const closeDefaultWebhookEditor = () => {
  defaultWebhookEditorVisible.value = false
}

const toggleDefaultWebhookEditorChannel = (channelId: number) => {
  const channel = webhookChannels.value.find((item) => item.id === channelId)
  if (!channel) return

  if (defaultWebhookEditor.value.channelIds.includes(channelId)) {
    defaultWebhookEditor.value.channelIds = defaultWebhookEditor.value.channelIds.filter((id) => id !== channelId)
  } else {
    defaultWebhookEditor.value.channelIds = [...defaultWebhookEditor.value.channelIds, channelId]
  }
}

const saveDefaultWebhookEditor = () => {
  if (defaultWebhookEditor.value.channelIds.length === 0) {
    toast.error('至少选择一个通道')
    return
  }

  defaultWebhookMode.value = defaultWebhookEditor.value.mode
  defaultWebhookChannelIds.value = [...defaultWebhookEditor.value.channelIds]
  closeDefaultWebhookEditor()
}

const openEditChannel = (channel: WebhookChannel) => {
  channelEditor.value = {
    id: channel.id,
    name: channel.name,
    type: channel.type,
    url: channel.url,
    secret: channel.secret
  }
  channelEditorVisible.value = true
}

const closeChannelEditor = () => {
  channelEditorVisible.value = false
}

const saveChannelEditor = () => {
  if (!channelEditor.value.name.trim()) {
    toast.error('通道名称不能为空')
    return
  }

  if (!channelEditor.value.url.trim()) {
    toast.error('Webhook URL 不能为空')
    return
  }

  const channel: WebhookChannel = {
    id: channelEditor.value.id || temporaryRoutingId--,
    name: channelEditor.value.name.trim(),
    type: channelEditor.value.type,
    url: channelEditor.value.url.trim(),
    secret: channelEditor.value.secret.trim(),
    enabled: true
  }

  const index = webhookChannels.value.findIndex((item) => item.id === channel.id)
  if (index >= 0) {
    webhookChannels.value.splice(index, 1, channel)
  } else {
    webhookChannels.value.unshift(channel)
  }

  closeChannelEditor()
}

const toggleDefaultWebhookEnabled = () => {
  defaultWebhookEnabled.value = !defaultWebhookEnabled.value
}

const resetDefaultWebhookRule = () => {
  defaultWebhookEnabled.value = originalDefaultWebhookState.value.enabled
  defaultWebhookMode.value = originalDefaultWebhookState.value.mode
  defaultWebhookChannelIds.value = [...originalDefaultWebhookState.value.channelIds]
}

const openEmailForwardDefaultEditor = () => {
  emailForwardDefaultEditor.value = {
    mode: emailForwardDefault.value.mode,
    targetEmail: emailForwardDefault.value.targetEmail,
    targetFromAddress: emailForwardDefault.value.targetFromAddress,
    targetForwardType: emailForwardDefault.value.targetForwardType
  }
  emailForwardDefaultEditorVisible.value = true
}

const closeEmailForwardDefaultEditor = () => {
  emailForwardDefaultEditorVisible.value = false
}

const saveEmailForwardDefaultEditor = () => {
  if (!emailForwardDefaultEditor.value.targetEmail.trim()) {
    toast.error('默认收件人不能为空')
    return
  }
  if (
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailForwardDefaultEditor.value.targetFromAddress.trim())
  ) {
    toast.error('请输入有效的转发发件人邮箱')
    return
  }

  emailForwardDefault.value = {
    ...emailForwardDefault.value,
    mode: emailForwardDefaultEditor.value.mode,
    targetEmail: emailForwardDefaultEditor.value.targetEmail.trim(),
    targetFromAddress: emailForwardDefaultEditor.value.targetFromAddress.trim(),
    targetForwardType: emailForwardDefaultEditor.value.targetForwardType
  }
  closeEmailForwardDefaultEditor()
}

const toggleEmailForwardDefaultEnabled = () => {
  emailForwardDefault.value.enabled = !emailForwardDefault.value.enabled
}

const resetEmailForwardDefaultRule = () => {
  emailForwardDefault.value = {...originalEmailForwardDefault.value}
}

const openCreateRule = (category: RuleCategory) => {
  ruleEditor.value = createEmptyRuleEditor(category)
  ruleEditorVisible.value = true
}

const openEditRule = (rule: WebhookRule | EmailForwardRule) => {
  if ('targetChannelIds' in rule) {
    ruleEditor.value = {
      id: rule.id,
      category: 'webhook',
      name: rule.name,
      enabled: rule.enabled,
      matchMode: rule.matchMode,
      action: rule.action === 'ignore' ? 'ignore' : 'send',
      senderPattern: rule.senderPattern,
      recipientPattern: rule.recipientPattern,
      subjectPattern: rule.subjectPattern,
      contentPattern: rule.contentPattern,
      targetChannelIds: [...rule.targetChannelIds],
      targetEmail: '',
      targetFromAddress: '',
      targetForwardType: 'internal'
    }
  } else {
    ruleEditor.value = {
      id: rule.id,
      category: 'email_forward',
      name: rule.name,
      enabled: rule.enabled,
      matchMode: rule.matchMode,
      action: 'send',
      senderPattern: rule.senderPattern,
      recipientPattern: rule.recipientPattern,
      subjectPattern: rule.subjectPattern,
      contentPattern: rule.contentPattern,
      targetChannelIds: [],
      targetEmail: rule.targetEmail,
      targetFromAddress: rule.targetFromAddress,
      targetForwardType: rule.targetForwardType
    }
  }
  ruleEditorVisible.value = true
}

const closeRuleEditor = () => {
  ruleEditorVisible.value = false
}

const toggleRuleEditorChannel = (channelId: number) => {
  const channel = webhookChannels.value.find((item) => item.id === channelId)
  if (!channel) return

  if (ruleEditor.value.targetChannelIds.includes(channelId)) {
    ruleEditor.value.targetChannelIds = ruleEditor.value.targetChannelIds.filter((id) => id !== channelId)
  } else {
    ruleEditor.value.targetChannelIds = [...ruleEditor.value.targetChannelIds, channelId]
  }
}

const saveRuleEditor = async () => {
  if (!ruleEditor.value.name.trim()) {
    toast.error('规则名称不能为空')
    return
  }

  if (ruleEditor.value.category === 'webhook' && ruleEditor.value.action === 'send' && ruleEditor.value.targetChannelIds.length === 0) {
    toast.error('发送规则至少需要选择一个通道')
    return
  }

  if (ruleEditor.value.category === 'email_forward' && !ruleEditor.value.targetEmail.trim()) {
    toast.error('收件人不能为空')
    return
  }

  if (
      ruleEditor.value.category === 'email_forward' &&
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(ruleEditor.value.targetFromAddress.trim())
  ) {
    toast.error('请输入有效的转发发件人邮箱')
    return
  }

  const id = ruleEditor.value.id || temporaryRoutingId--
  if (ruleEditor.value.category === 'webhook') {
    const rule: WebhookRule = {
      id,
      name: ruleEditor.value.name.trim(),
      enabled: ruleEditor.value.enabled,
      matchMode: ruleEditor.value.matchMode,
      action: ruleEditor.value.action,
      senderPattern: ruleEditor.value.senderPattern.trim(),
      recipientPattern: ruleEditor.value.recipientPattern.trim(),
      subjectPattern: ruleEditor.value.subjectPattern.trim(),
      contentPattern: ruleEditor.value.contentPattern.trim(),
      targetChannelIds: [...ruleEditor.value.targetChannelIds]
    }
    const index = webhookRules.value.findIndex((item) => item.id === id)
    if (index >= 0) webhookRules.value.splice(index, 1, rule)
    else webhookRules.value.unshift(rule)
  } else {
    const rule: EmailForwardRule = {
      id,
      name: ruleEditor.value.name.trim(),
      enabled: ruleEditor.value.enabled,
      matchMode: ruleEditor.value.matchMode,
      senderPattern: ruleEditor.value.senderPattern.trim(),
      recipientPattern: ruleEditor.value.recipientPattern.trim(),
      subjectPattern: ruleEditor.value.subjectPattern.trim(),
      contentPattern: ruleEditor.value.contentPattern.trim(),
      targetEmail: ruleEditor.value.targetEmail.trim(),
      targetFromAddress: ruleEditor.value.targetFromAddress.trim(),
      targetForwardType: ruleEditor.value.targetForwardType
    }
    const index = emailForwardRules.value.findIndex((item) => item.id === id)
    if (index >= 0) emailForwardRules.value.splice(index, 1, rule)
    else emailForwardRules.value.unshift(rule)
  }
  closeRuleEditor()
  toast.success('已应用到页面，保存后生效')
}

const toggleWebhookRule = (rule: WebhookRule) => {
  rule.enabled = !rule.enabled
}

const toggleEmailForwardRule = (rule: EmailForwardRule) => {
  rule.enabled = !rule.enabled
}

const deleteWebhookRule = (id: number) => {
  webhookRules.value = webhookRules.value.filter((rule) => rule.id !== id)
  toast.success('已从页面移除，保存后生效')
}

const deleteEmailForwardRule = (id: number) => {
  emailForwardRules.value = emailForwardRules.value.filter((rule) => rule.id !== id)
  toast.success('已从页面移除，保存后生效')
}

const deleteForwardLog = async (id: number) => {
  logsLoading.value = true
  try {
    const response = await api.delete(`/dashboard/forward-logs/${id}`)
    const result = response.data
    if (!result.success) {
      throw new Error(result.message || '删除失败')
    }

    invalidateRoutingPageCache()
    toast.success(result.message || '转发日志已删除')
    const nextPage = logs.value.length === 1 && logPagination.value.page > 1
        ? logPagination.value.page - 1
        : logPagination.value.page
    await Promise.all([
      loadForwardLogs(nextPage, {forceRefresh: true}),
      loadStats(true)
    ])
  } catch (err) {
    const message = (err as any)?.response?.data?.message || (err instanceof Error ? err.message : '删除失败')
    toast.error(message)
  } finally {
    logsLoading.value = false
  }
}

const openLogDetail = async (id: number) => {
  detailLoading.value = true
  logDetailVisible.value = true
  replayResult.value = null
  try {
    const response = await get(`/dashboard/forward-logs/${id}`)
    if (!response.success || !response.data?.log) {
      throw new Error(response.message || '获取详情失败')
    }
    selectedLog.value = response.data.log
  } catch (err) {
    toast.error(err instanceof Error ? err.message : '获取详情失败')
    logDetailVisible.value = false
  } finally {
    detailLoading.value = false
  }
}

const closeLogDetail = () => {
  logDetailVisible.value = false
  selectedLog.value = null
  replayResult.value = null
}

const replayForwardLog = async () => {
  if (!selectedLog.value?.id) {
    toast.error('转发日志不存在')
    return
  }

  detailLoading.value = true
  try {
    const response = await api.post(`/dashboard/forward-logs/${selectedLog.value.id}/replay`)
    const result = response.data
    replayResult.value = {
      success: Boolean(result.success),
      responseCode: result.data?.responseCode ?? null,
      errorMessage: result.data?.errorMessage || null,
      target: result.data?.target || selectedLog.value.webhook_url || '',
      type: result.data?.type || '',
      debug: result.data?.debug || null
    }
    if (!result.success) {
      throw new Error(result.message || '重发失败')
    }

    toast.success(result.message || 'Webhook 已重发')
  } catch (err) {
    const responseData = (err as any)?.response?.data
    if (responseData?.data) {
      replayResult.value = {
        success: Boolean(responseData.success),
        responseCode: responseData.data.responseCode ?? null,
        errorMessage: responseData.data.errorMessage || responseData.message || null,
        target: responseData.data.target || selectedLog.value.webhook_url || '',
        type: responseData.data.type || '',
        debug: responseData.data.debug || null
      }
    }
    const message = responseData?.message || (err instanceof Error ? err.message : '重发失败')
    toast.error(message)
  } finally {
    detailLoading.value = false
  }
}

const openEmailFromLog = () => {
  if (!selectedLog.value?.email_id) {
    toast.warning('当前日志没有关联邮件 ID')
    return
  }

  router.push({
    path: '/inbox',
    query: {
      email: String(selectedLog.value.email_id)
    }
  })
}

const formatReplayDebug = (debug: unknown) => {
  try {
    return JSON.stringify(debug, null, 2)
  } catch {
    return String(debug)
  }
}

const changeLogPage = async (page: number) => {
  await loadForwardLogs(page)
}

const changeLogPageSize = async (limit: number) => {
  logPagination.value.limit = limit
  await loadForwardLogs(1)
}

const formatChannelNames = (channelIds: number[]) => {
  const names = channelIds
      .map((id) => webhookChannels.value.find((channel) => channel.id === id)?.name)
      .filter((name): name is string => Boolean(name))
  return names.length > 0 ? names.join(' / ') : '未选择通道'
}

const webhookTypeLabel = (type: WebhookType) => {
  const labels: Record<WebhookType, string> = {
    dingtalk: '钉钉',
    feishu: '飞书',
    bark: 'Bark'
  }
  return labels[type] || type
}

const forwardTypeLabel = (type: ForwardType) => {
  const labels: Record<ForwardType, string> = {
    internal: '站内转发',
    cf: 'CF 转发',
    resend: 'Resend 转发'
  }
  return labels[type] || type
}

const getLogChannelLabel = (log: any) => {
  const matchedChannel = webhookChannels.value.find((channel) => channel.url === log.webhook_url)
  if (matchedChannel) {
    return matchedChannel.name
  }

  try {
    return new URL(log.webhook_url).host
  } catch {
    return log.webhook_url || '未记录'
  }
}

const getMailtoAddress = (value?: string | null) => {
  if (!value?.startsWith('mailto:')) {
    return ''
  }

  return value.slice('mailto:'.length).split('?')[0]
}

const getLogDeliveryFrom = (log: any) => log.delivery_from_address || '未记录实际发件人'

const getLogDeliveryTo = (log: any) => log.delivery_to_address || getMailtoAddress(log.webhook_url) || '未记录实际收件人'

const getLogDeliveryTargetLabel = (log: any) => log.webhook_url?.startsWith('mailto:') ? '投递目标' : '实际 Webhook'

const matchModeLabel = (mode: MatchMode) => mode === 'all' ? '全部条件匹配' : '任一条件匹配'

const getRuleConditionChips = (rule: WebhookRule | EmailForwardRule) => {
  const chips: string[] = []
  if ('targetChannelIds' in rule && rule.action === 'ignore') {
    chips.push('策略：忽略')
  }
  chips.push(matchModeLabel(rule.matchMode))
  if (rule.senderPattern) chips.push(`发件人含 ${rule.senderPattern}`)
  if (rule.recipientPattern) chips.push(`收件人含 ${rule.recipientPattern}`)
  if (rule.subjectPattern) chips.push(`主题含 ${rule.subjectPattern}`)
  if (rule.contentPattern) chips.push(`正文含 ${rule.contentPattern}`)
  return chips.length > 0 ? chips : ['匹配全部邮件']
}

const refreshRoutingPage = async () => {
  await loadPageData(true)
}

onMounted(() => {
  window.refreshCurrentPage = refreshRoutingPage
  loadPageData()
})

onUnmounted(() => {
  if (window.refreshCurrentPage === refreshRoutingPage) {
    delete window.refreshCurrentPage
  }
})
</script>

<style scoped>
.routing-page {
  max-width: 1200px;
  margin: 0 auto;
  --surface: rgba(255, 255, 255, 0.96);
  --border: rgba(17, 40, 67, 0.08);
  --text-strong: #17324a;
  --text-muted: #5f7081;
  --accent: #0f7a6c;
  --accent-soft: rgba(15, 122, 108, 0.12);
  --danger: #b42318;
  --danger-soft: rgba(180, 35, 24, 0.1);
}

.routing-content {
  display: grid;
  gap: 24px;
}

.save-bar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  padding: 16px 18px;
  border: 1px solid rgba(44, 127, 184, 0.16);
  border-radius: 8px;
  background: rgba(255, 255, 255, 0.96);
}

.save-bar div {
  display: grid;
  gap: 4px;
  min-width: 0;
}

.save-bar strong {
  color: var(--text-strong);
  font-size: 15px;
}

.save-bar span {
  color: var(--text-muted);
  font-size: 13px;
  line-height: 1.5;
}

.summary-grid,
.routing-section {
  display: grid;
  gap: 16px;
}

.summary-grid {
  grid-template-columns: repeat(3, minmax(0, 1fr));
}

.summary-card,
.panel {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 12px;
  box-shadow: 0 24px 42px -38px rgba(15, 23, 42, 0.75);
}

.summary-card {
  padding: 22px;
}

.accent-card {
  background: radial-gradient(circle at top right, rgba(19, 126, 110, 0.22), transparent 52%), linear-gradient(180deg, rgba(242, 250, 248, 0.98), rgba(255, 255, 255, 0.96));
}

.summary-eyebrow {
  font-size: 12px;
  font-weight: 700;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: #6b7c8d;
}

.summary-title {
  margin-top: 10px;
  color: var(--text-strong);
  font-size: 22px;
  font-weight: 700;
  line-height: 1.2;
  word-break: break-word;
}

.summary-copy {
  margin: 8px 0 0;
  color: var(--text-muted);
  line-height: 1.6;
}

.routing-notice {
  display: flex;
  align-items: flex-start;
  gap: 14px;
  padding: 16px 18px;
  border: 1px solid rgba(44, 127, 184, 0.16);
  border-radius: 8px;
  background: linear-gradient(180deg, rgba(244, 249, 252, 0.98), rgba(255, 255, 255, 0.96));
}

.notice-mark {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  flex: 0 0 auto;
  width: 26px;
  height: 26px;
  border-radius: 999px;
  background: rgba(44, 127, 184, 0.12);
  color: #23618f;
  font-size: 14px;
  font-weight: 800;
}

.notice-content {
  display: grid;
  gap: 8px;
  min-width: 0;
}

.notice-content h3 {
  margin: 0;
  color: var(--text-strong);
  font-size: 15px;
}

.notice-content p {
  margin: 0;
  color: var(--text-muted);
  line-height: 1.6;
}

.notice-example {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}

.notice-example span {
  padding: 6px 9px;
  border-radius: 8px;
  background: rgba(17, 40, 67, 0.05);
  color: #2f5169;
  font-size: 12px;
  font-weight: 700;
}

.notice-example strong {
  color: #23618f;
}

.panel {
  padding: 24px;
  display: grid;
  gap: 16px;
}

.panel-head,
.rule-card-top,
.channel-head {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 12px;
  flex-wrap: wrap;
}

.panel-title {
  color: var(--text-strong);
  font-size: 20px;
  font-weight: 700;
}

.panel-subtitle {
  margin: 6px 0 0;
  color: var(--text-muted);
  font-size: 13px;
  line-height: 1.5;
}

.panel-actions,
.channel-actions,
.rule-inline-actions,
.form-actions,
.mode-selector,
.channel-reference-list {
  display: flex;
  gap: 10px;
  flex-wrap: wrap;
}

.action-button,
.mini-action,
.switch-button,
.mode-button,
.channel-reference-chip {
  border-radius: 8px;
  font-size: 13px;
  font-weight: 700;
  cursor: pointer;
  transition: transform 0.16s ease, background 0.16s ease, border-color 0.16s ease;
}

.action-button:hover,
.mini-action:hover,
.switch-button:hover,
.mode-button:hover,
.channel-reference-chip:hover {
  transform: translateY(-1px);
}

.action-button {
  border: none;
  padding: 11px 16px;
}

.action-button.primary {
  background: linear-gradient(135deg, #1e7f73, #0f6b61);
  color: white;
}

.action-button.secondary {
  background: rgba(17, 40, 67, 0.06);
  color: #31526b;
}

.action-button.ghost,
.mini-action,
.switch-button,
.mode-button,
.channel-reference-chip {
  border: 1px solid rgba(17, 40, 67, 0.12);
  background: rgba(17, 40, 67, 0.05);
  color: #48627a;
  padding: 9px 12px;
}

.action-button.danger,
.mini-action.danger {
  color: var(--danger);
}

.state-action.active {
  background: var(--accent-soft);
  color: var(--accent);
  border-color: rgba(15, 122, 108, 0.24);
}

.switch-button.active,
.mode-button.active,
.channel-reference-chip.active {
  background: var(--accent-soft);
  color: var(--accent);
  border-color: rgba(15, 122, 108, 0.24);
}

.channel-reference-chip.disabled {
  opacity: 0.45;
}

.channel-list,
.rules-grid,
.logs-list {
  display: grid;
  gap: 14px;
}

.channel-card,
.rule-card,
.log-card,
.default-card {
  padding: 18px;
  border: 1px solid var(--border);
  border-radius: 8px;
  background: linear-gradient(180deg, rgba(255, 255, 255, 0.98), rgba(245, 248, 251, 0.98));
}

.rule-card {
  display: grid;
  gap: 14px;
}

.clickable-card {
  cursor: pointer;
}

.channel-card.disabled,
.rule-card.disabled,
.default-card.disabled {
  opacity: 0.72;
}

.editor-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 14px;
}

.channel-name,
.rule-card h4,
.log-card h4 {
  margin: 0;
  color: var(--text-strong);
  font-size: 17px;
  font-weight: 700;
}

.rule-title-group {
  display: grid;
  gap: 8px;
  min-width: 220px;
}

.rule-summary-grid {
  display: grid;
  grid-template-columns: minmax(180px, 0.7fr) minmax(0, 1.3fr);
  gap: 12px;
}

.rule-summary-item {
  display: grid;
  align-content: start;
  gap: 8px;
  min-width: 0;
  padding: 12px;
  border: 1px solid rgba(17, 40, 67, 0.08);
  border-radius: 8px;
  background: rgba(255, 255, 255, 0.72);
}

.rule-summary-item strong {
  color: var(--text-strong);
  font-size: 14px;
  line-height: 1.5;
  word-break: break-word;
}

.rule-summary-item.conditions {
  min-width: 0;
}

.channel-title-row {
  display: flex;
  align-items: center;
  gap: 10px;
  min-width: 0;
  flex-wrap: wrap;
}

.channel-type-pill {
  display: inline-flex;
  align-items: center;
  min-height: 26px;
  padding: 0 9px;
  border-radius: 8px;
  background: rgba(17, 40, 67, 0.06);
  color: var(--text-muted);
  font-size: 12px;
  font-weight: 700;
}

.mail-channel-empty {
  display: flex;
  flex-direction: column;
  gap: 6px;
  padding: 16px;
  border-radius: 8px;
  border: 1px dashed rgba(52, 84, 117, 0.22);
  background: rgba(244, 248, 252, 0.96);
  color: var(--text-muted);
  font-size: 13px;
}

.mail-channel-empty strong {
  color: var(--text-strong);
}

.mail-channel-list {
  display: grid;
  gap: 14px;
}

.mail-channel-card {
  display: grid;
  gap: 14px;
  padding: 18px;
  border: 1px solid var(--border);
  border-radius: 8px;
  background: linear-gradient(180deg, rgba(255, 255, 255, 0.98), rgba(245, 248, 251, 0.98));
}

.token-input-wrap {
  position: relative;
  min-width: 0;
}

.token-input-wrap .form-control {
  padding-right: 64px;
}

.token-visibility-button {
  position: absolute;
  right: 6px;
  top: 50%;
  transform: translateY(-50%);
  height: 30px;
  padding: 0 9px;
  border: 0;
  border-radius: 8px;
  background: rgba(23, 78, 166, 0.08);
  color: #174ea6;
  font-size: 12px;
  font-weight: 700;
  cursor: pointer;
}

.token-visibility-button:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.form-group label {
  display: block;
  margin-bottom: 6px;
  color: var(--text-strong);
  font-weight: 600;
}

.form-control {
  width: 100%;
  padding: 12px 14px;
  border: 1px solid rgba(52, 84, 117, 0.18);
  border-radius: 14px;
  font-size: 14px;
  background: rgba(247, 250, 252, 0.92);
  box-sizing: border-box;
}

.form-control:focus {
  outline: none;
  border-color: #2c7fb8;
  box-shadow: 0 0 0 3px rgba(44, 127, 184, 0.12);
}

.rule-target {
  display: grid;
  gap: 4px;
}

.target-label,
.log-time {
  color: #6a7b8c;
  font-size: 13px;
}

.rule-target strong {
  color: var(--text-strong);
  word-break: break-word;
}

.rule-meta-row {
  display: flex;
  gap: 10px;
  flex-wrap: wrap;
}

.status-pill {
  display: inline-flex;
  align-items: center;
  padding: 6px 10px;
  border-radius: 999px;
  font-size: 12px;
  font-weight: 700;
}

.status-live {
  background: rgba(15, 122, 108, 0.12);
  color: var(--accent);
}

.status-idle {
  background: rgba(17, 40, 67, 0.08);
  color: #48627a;
}

.status-failed {
  background: var(--danger-soft);
  color: var(--danger);
}

.condition-chip-list {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
}

.condition-chip-list.compact {
  gap: 6px;
}

.condition-chip {
  padding: 7px 10px;
  border-radius: 8px;
  background: rgba(17, 40, 67, 0.05);
  color: #2f5169;
  font-size: 12px;
  font-weight: 600;
}

.log-stats {
  display: flex;
  gap: 12px;
  flex-wrap: wrap;
}

.log-stats.compact {
  margin-top: 12px;
}

.log-stat {
  display: inline-flex;
  align-items: center;
  gap: 10px;
  padding: 12px 14px;
  border-radius: 8px;
  background: rgba(17, 40, 67, 0.04);
  color: var(--text-muted);
}

.log-stat.success {
  background: rgba(15, 122, 108, 0.08);
}

.log-stat.failed {
  background: var(--danger-soft);
}

.log-stat strong {
  color: var(--text-strong);
  font-size: 18px;
}

.logs-list {
  gap: 10px;
}

.log-card {
  display: grid;
  grid-template-columns: auto minmax(220px, 1.4fr) minmax(140px, 0.75fr) minmax(170px, 0.85fr) auto;
  align-items: center;
  gap: 14px;
}

.log-main-cell {
  display: grid;
  gap: 7px;
  min-width: 0;
}

.log-main-cell h4 {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.log-address-row {
  display: flex;
  gap: 8px;
  min-width: 0;
  color: var(--text-muted);
  font-size: 13px;
}

.log-address-row span {
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.log-target-cell,
.log-time-cell {
  display: grid;
  gap: 5px;
  min-width: 0;
}

.log-target-cell strong,
.log-time-cell strong {
  color: var(--text-strong);
  font-size: 13px;
  line-height: 1.45;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.log-action-cell {
  gap: 10px;
  display: flex;
  justify-content: flex-end;
}

.empty-panel {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 34px 20px;
  text-align: center;
  border-radius: 20px;
  background: rgba(244, 248, 252, 0.96);
  border: 1px dashed rgba(47, 94, 138, 0.18);
}

.empty-icon {
  font-size: 40px;
  margin-bottom: 12px;
}

.detail-layout {
  display: grid;
  gap: 14px;
}

.detail-label {
  display: block;
  margin-bottom: 8px;
  color: #6a7b8c;
  font-size: 12px;
  font-weight: 700;
  text-transform: uppercase;
}

.detail-value {
  color: var(--text-strong);
  line-height: 1.6;
  word-break: break-word;
}

.detail-block {
  padding: 16px;
  border-radius: 8px;
  background: rgba(245, 248, 251, 0.96);
  border: 1px solid rgba(17, 40, 67, 0.08);
}

.detail-block h4 {
  margin: 0 0 12px;
  color: var(--text-strong);
  font-size: 18px;
}

.detail-hero {
  display: flex;
  justify-content: space-between;
  gap: 18px;
  align-items: flex-start;
}

.detail-hero-main {
  display: grid;
  gap: 10px;
  min-width: 0;
}

.detail-hero-main h4 {
  margin: 0;
  color: var(--text-strong);
  font-size: 20px;
  line-height: 1.35;
  word-break: break-word;
}

.detail-hero-main p,
.detail-hero-meta span {
  margin: 0;
  color: var(--text-muted);
  line-height: 1.6;
}

.detail-hero-meta {
  display: grid;
  justify-items: end;
  gap: 8px;
  min-width: 180px;
  text-align: right;
}

.detail-hero-meta strong {
  color: var(--text-strong);
  word-break: break-word;
}

.detail-target-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 14px;
}

.detail-chip-list {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
}

.detail-chip {
  display: inline-flex;
  align-items: center;
  padding: 8px 10px;
  border-radius: 12px;
  background: rgba(17, 40, 67, 0.05);
  color: #2f5169;
  font-size: 13px;
  font-weight: 600;
}

.detail-empty {
  margin: 0;
  color: var(--text-muted);
}

.detail-message-grid {
  display: grid;
  gap: 10px;
}

.message-row {
  display: flex;
  justify-content: space-between;
  gap: 16px;
  padding-bottom: 8px;
  border-bottom: 1px solid rgba(17, 40, 67, 0.08);
}

.message-row:last-child {
  border-bottom: none;
  padding-bottom: 0;
}

.message-row span {
  color: #6a7b8c;
  font-size: 13px;
}

.message-row strong {
  color: var(--text-strong);
  text-align: right;
  word-break: break-word;
}

.message-row.error-row strong {
  color: var(--danger);
}

.detail-content {
  margin: 0;
  white-space: pre-wrap;
  word-break: break-word;
  color: var(--text-strong);
  line-height: 1.7;
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  font-size: 13px;
}

.replay-output {
  margin-top: 12px;
  max-height: 360px;
  overflow: auto;
}

@media (max-width: 1024px) {
  .summary-grid,
  .rule-summary-grid,
  .editor-grid,
  .detail-layout,
  .detail-target-grid {
    grid-template-columns: 1fr;
  }

  .log-card {
    grid-template-columns: auto minmax(0, 1fr);
  }

  .log-target-cell,
  .log-time-cell,
  .log-action-cell {
    grid-column: 2;
  }

  .log-action-cell {
    justify-content: flex-start;
  }
}

@media (max-width: 720px) {
  .summary-card,
  .panel {
    padding: 18px;
    border-radius: 12px;
  }

  .summary-grid {
    grid-template-columns: 1fr;
  }

  .panel-head,
  .rule-card-top,
  .channel-head,
  .detail-hero,
  .message-row {
    flex-direction: column;
    align-items: flex-start;
  }

  .detail-hero-meta {
    justify-items: start;
    min-width: 0;
    text-align: left;
  }

  .log-card {
    grid-template-columns: 1fr;
  }

  .log-status-cell,
  .log-target-cell,
  .log-time-cell,
  .log-action-cell {
    grid-column: auto;
  }

  .log-main-cell h4,
  .log-address-row span,
  .log-target-cell strong,
  .log-time-cell strong {
    white-space: normal;
  }

  .log-stats,
  .form-actions,
  .mode-selector,
  .channel-reference-list,
  .panel-actions,
  .channel-actions,
  .rule-inline-actions {
    width: 100%;
    justify-content: flex-start;
  }

  .log-stat,
  .action-button,
  .mini-action,
  .switch-button,
  .mode-button,
  .channel-reference-chip {
    width: auto;
    max-width: 100%;
  }
}
</style>
