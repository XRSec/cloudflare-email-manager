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
          <div class="summary-eyebrow">默认通知</div>
          <div class="summary-title">{{ defaultNotificationEnabled ? selectedDefaultChannelNames : '已停用' }}</div>
          <p class="summary-copy">{{
              defaultNotificationEnabled ? defaultNotificationModeLabel : '默认通知规则未启用'
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
          <div class="summary-eyebrow">默认转发</div>
          <div class="summary-title">{{ incomingDefault.enabled ? incomingDefault.targetEmail : '已停用' }}</div>
          <p class="summary-copy">{{ incomingDefault.enabled ? incomingDefaultModeLabel : '默认转发规则未启用' }}</p>
        </article>
      </section>

      <section class="routing-section">
        <article class="panel">
          <div class="panel-head">
            <div class="panel-title">通知通道</div>
            <div class="panel-actions">
              <button type="button" class="action-button secondary" :disabled="saving" @click="addChannel">新增通道
              </button>
            </div>
          </div>

          <div class="channel-list">
            <div v-for="(channel, index) in notificationChannels" :key="channel.id" class="channel-card"
                 :class="{ disabled: !channel.enabled }">
              <div class="channel-head">
                <div class="channel-title-row">
                  <div class="channel-name">{{ channel.name || `通道 ${index + 1}` }}</div>
                  <span class="channel-type-pill">{{ webhookTypeLabel(channel.type) }}</span>
                </div>
                <div class="channel-actions">
                  <button type="button" class="mini-action state-action" :class="{ active: channel.enabled }"
                          @click="toggleChannel(channel)">
                    {{ channel.enabled ? '启用' : '停用' }}
                  </button>
                  <button type="button" class="mini-action" :disabled="saving" @click="openEditChannel(channel)">
                    编辑
                  </button>
                  <button type="button" class="mini-action"
                          :disabled="isDefaultChannel(channel) || notificationChannels.length === 1"
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
            <div class="panel-title">默认通知规则</div>
          </div>

          <article class="rule-card" :class="{ disabled: !defaultNotificationEnabled }">
            <div class="rule-card-top">
              <div class="rule-title-group">
                <h4>默认通知</h4>
              </div>
              <div class="rule-inline-actions">
                <button type="button" class="mini-action state-action" :class="{ active: defaultNotificationEnabled }"
                        @click="toggleDefaultNotificationEnabled">{{ defaultNotificationEnabled ? '启用' : '停用' }}
                </button>
                <button type="button" class="mini-action" @click="openDefaultNotificationEditor">编辑</button>
                <button type="button" class="mini-action" @click="resetDefaultNotificationRule">重置</button>
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
                  <span class="condition-chip">{{ defaultNotificationModeLabel }}</span>
                </div>
              </div>
            </div>
          </article>
        </article>

        <article class="panel">
          <div class="panel-head">
            <div class="panel-title">通知规则</div>
            <div class="panel-actions">
              <button type="button" class="action-button primary" @click="openCreateRule('notification')">新增规则
              </button>
            </div>
          </div>

          <div v-if="notificationRules.length === 0" class="empty-panel">
            <div class="empty-icon">📭</div>
            <h4>暂无通知规则</h4>
          </div>

          <div v-else class="rules-grid">
            <article v-for="rule in notificationRules" :key="rule.id" class="rule-card"
                     :class="{ disabled: !rule.enabled }">
              <div class="rule-card-top">
                <div class="rule-title-group">
                  <h4>{{ rule.name }}</h4>
                </div>
                <div class="rule-inline-actions">
                  <button type="button" class="mini-action state-action" :class="{ active: rule.enabled }"
                          @click="toggleNotificationRule(rule)">{{ rule.enabled ? '启用' : '停用' }}
                  </button>
                  <button type="button" class="mini-action" @click="openEditRule(rule)">编辑</button>
                  <button type="button" class="mini-action danger" @click="deleteNotificationRule(rule.id)">删除
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
            <div class="panel-title">默认转发规则</div>
          </div>

          <article class="rule-card" :class="{ disabled: !incomingDefault.enabled }">
            <div class="rule-card-top">
              <div class="rule-title-group">
                <h4>默认转发</h4>
              </div>
              <div class="rule-inline-actions">
                <button type="button" class="mini-action state-action" :class="{ active: incomingDefault.enabled }"
                        @click="toggleIncomingDefaultEnabled">{{ incomingDefault.enabled ? '启用' : '停用' }}
                </button>
                <button type="button" class="mini-action" @click="openIncomingDefaultEditor">编辑</button>
                <button type="button" class="mini-action" @click="resetIncomingDefaultRule">重置</button>
              </div>
            </div>

            <div class="rule-summary-grid">
              <div class="rule-summary-item">
                <span class="target-label">转发到</span>
                <strong>{{ incomingDefault.targetEmail || '未配置' }}</strong>
                <span class="condition-chip">{{ forwardTypeLabel(incomingDefault.targetForwardType) }}</span>
              </div>
              <div class="rule-summary-item conditions">
                <span class="target-label">转发策略</span>
                <div class="condition-chip-list compact">
                  <span class="condition-chip">{{ incomingDefaultModeLabel }}</span>
                </div>
              </div>
            </div>
          </article>
        </article>

        <article class="panel">
          <div class="panel-head">
            <div class="panel-title">收件转发规则</div>
            <div class="panel-actions">
              <button type="button" class="action-button primary" @click="openCreateRule('incoming')">新增规则</button>
            </div>
          </div>

          <div v-if="incomingRules.length === 0" class="empty-panel">
            <div class="empty-icon">📭</div>
            <h4>暂无收件转发规则</h4>
          </div>

          <div v-else class="rules-grid">
            <article v-for="rule in incomingRules" :key="rule.id" class="rule-card"
                     :class="{ disabled: !rule.enabled }">
              <div class="rule-card-top">
                <div class="rule-title-group">
                  <h4>{{ rule.name }}</h4>
                </div>
                <div class="rule-inline-actions">
                  <button type="button" class="mini-action state-action" :class="{ active: rule.enabled }"
                          @click="toggleIncomingRule(rule)">{{ rule.enabled ? '启用' : '停用' }}
                  </button>
                  <button type="button" class="mini-action" @click="openEditRule(rule)">编辑</button>
                  <button type="button" class="mini-action danger" @click="deleteIncomingRule(rule.id)">删除</button>
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
                <span class="target-label">发送时间</span>
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
                      @change-page="changeLogPage"/>
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

          <div v-if="ruleEditor.category === 'notification'" class="editor-wide form-group">
            <label>引用通道</label>
            <div class="channel-reference-list">
              <button
                  v-for="channel in notificationChannels"
                  :key="channel.id"
                  type="button"
                  class="channel-reference-chip"
                  :class="{ active: ruleEditor.targetChannelIds.includes(channel.id), disabled: !channel.enabled }"
                  @click="toggleRuleEditorChannel(channel.id)"
              >
                {{ channel.name }}
              </button>
            </div>
          </div>

          <template v-else>
            <FormField
                v-model="ruleEditor.targetEmail"
                label="转发邮箱"
                type="email"
                placeholder="archive@example.com"
            />
            <div class="form-group">
              <label for="editor-forward-type">转发方式</label>
              <select id="editor-forward-type" v-model="ruleEditor.targetForwardType" class="form-control">
                <option value="internal">站内转发</option>
                <option value="smtp">SMTP 转发</option>
                <option value="cf">CF 转发</option>
              </select>
            </div>
            <FormField
                v-if="ruleEditor.targetForwardType === 'cf'"
                v-model="ruleEditor.targetFromAddress"
                label="发件人"
                type="email"
                placeholder="forward@example.com"
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

    <Modal :show="incomingDefaultEditorVisible" title="编辑默认转发规则" size="large"
           @close="closeIncomingDefaultEditor">
      <form class="incoming-default-editor-form" @submit.prevent="saveIncomingDefaultEditor">
        <div class="editor-grid">
          <FormField
              v-model="incomingDefaultEditor.targetEmail"
              label="默认转发邮箱"
              type="email"
              placeholder="archive@example.com"
          />
          <div class="form-group">
            <label for="incoming-default-forward-type">转发方式</label>
            <select id="incoming-default-forward-type" v-model="incomingDefaultEditor.targetForwardType"
                    class="form-control">
              <option value="internal">站内转发</option>
              <option value="smtp">SMTP 转发</option>
              <option value="cf">CF 转发</option>
            </select>
          </div>
          <FormField
              v-if="incomingDefaultEditor.targetForwardType === 'cf'"
              v-model="incomingDefaultEditor.targetFromAddress"
              label="发件人"
              type="email"
              placeholder="forward@example.com"
          />

          <div class="editor-wide form-group">
            <label>转发策略</label>
            <div class="mode-selector">
              <button type="button" class="mode-button" :class="{ active: incomingDefaultEditor.mode === 'always' }"
                      @click="incomingDefaultEditor.mode = 'always'">
                始终转发所有邮件
              </button>
              <button type="button" class="mode-button" :class="{ active: incomingDefaultEditor.mode === 'unmatched' }"
                      @click="incomingDefaultEditor.mode = 'unmatched'">
                仅未命中时转发
              </button>
            </div>
          </div>
        </div>
      </form>

      <template #footer>
        <Button variant="secondary" @click="closeIncomingDefaultEditor">取消</Button>
        <Button variant="primary" @click="saveIncomingDefaultEditor">应用</Button>
      </template>
    </Modal>

    <Modal :show="defaultNotificationEditorVisible" title="编辑默认通知规则" size="large"
           @close="closeDefaultNotificationEditor">
      <form class="default-notification-editor-form" @submit.prevent="saveDefaultNotificationEditor">
        <div class="editor-grid">
          <div class="editor-wide form-group">
            <label>引用通道</label>
            <div class="channel-reference-list">
              <button
                  v-for="channel in notificationChannels"
                  :key="channel.id"
                  type="button"
                  class="channel-reference-chip"
                  :class="{ active: defaultNotificationEditor.channelIds.includes(channel.id), disabled: !channel.enabled }"
                  @click="toggleDefaultNotificationEditorChannel(channel.id)"
              >
                {{ channel.name }}
              </button>
            </div>
          </div>

          <div class="editor-wide form-group">
            <label>发送策略</label>
            <div class="mode-selector">
              <button type="button" class="mode-button" :class="{ active: defaultNotificationEditor.mode === 'always' }"
                      @click="defaultNotificationEditor.mode = 'always'">
                始终发送所有邮件
              </button>
              <button type="button" class="mode-button"
                      :class="{ active: defaultNotificationEditor.mode === 'unmatched' }"
                      @click="defaultNotificationEditor.mode = 'unmatched'">
                仅未命中时发送
              </button>
            </div>
          </div>
        </div>
      </form>

      <template #footer>
        <Button variant="secondary" @click="closeDefaultNotificationEditor">取消</Button>
        <Button variant="primary" @click="saveDefaultNotificationEditor">应用</Button>
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
          <h4>转发目标</h4>
          <div class="detail-target-grid">
            <div>
              <span class="detail-label">Webhook 通道</span>
              <div v-if="resolvedLogWebhookTargets.length" class="detail-chip-list">
                <span v-for="channel in resolvedLogWebhookTargets" :key="channel.id" class="detail-chip">
                  {{ channel.name }}
                </span>
              </div>
              <p v-else class="detail-empty">未匹配到已配置通道</p>
            </div>

            <div>
              <span class="detail-label">转发邮箱</span>
              <div v-if="resolvedLogForwardTargets.length" class="detail-chip-list">
                <span v-for="target in resolvedLogForwardTargets" :key="target" class="detail-chip">
                  {{ target }}
                </span>
              </div>
              <p v-else class="detail-empty">当前没有匹配到转发邮箱</p>
            </div>
          </div>
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
              <span>邮件时间</span>
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

type WebhookType = 'dingtalk' | 'feishu' | 'bark'
type MatchMode = 'all' | 'any'
type DefaultMode = 'always' | 'unmatched'
type RuleCategory = 'notification' | 'incoming'
type ForwardType = 'internal' | 'smtp' | 'cf'

interface NotificationChannel {
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

interface NotificationRule {
  id: number
  name: string
  enabled: boolean
  matchMode: MatchMode
  senderPattern: string
  recipientPattern: string
  subjectPattern: string
  contentPattern: string
  targetChannelIds: number[]
}

interface IncomingRule {
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
  channels?: NotificationChannel[]
  notificationRules?: NotificationRule[]
  incomingRules?: IncomingRule[]
  defaultNotificationRule?: DefaultNotificationRule | null
  defaultIncomingRule?: DefaultIncomingRule | null
}

interface SavedRoutingRule {
  id: number
  category: RuleCategory
  name: string
  enabled: boolean
  matchMode: MatchMode
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

interface DefaultNotificationRule {
  id: number
  name: string
  enabled: boolean
  defaultMode: DefaultMode
  targetChannelIds: number[]
}

interface DefaultIncomingRule {
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
const defaultNotificationEditorVisible = ref(false)
const incomingDefaultEditorVisible = ref(false)
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

const notificationChannels = ref<NotificationChannel[]>([])
const originalNotificationChannels = ref<NotificationChannel[]>([])
const channelEditor = ref<ChannelEditorState>(createEmptyChannelEditor())
let temporaryRoutingId = -1

const defaultNotificationRuleId = ref<number | null>(null)
const defaultIncomingRuleId = ref<number | null>(null)
const defaultNotificationEnabled = ref(false)
const defaultNotificationMode = ref<DefaultMode>('unmatched')
const defaultNotificationChannelIds = ref<number[]>([])
const defaultNotificationEditor = ref({
  mode: 'unmatched' as DefaultMode,
  channelIds: [] as number[]
})
const originalDefaultNotificationState = ref({
  enabled: false,
  mode: 'unmatched' as DefaultMode,
  channelIds: [] as number[]
})

const incomingDefault = ref({
  enabled: false,
  mode: 'unmatched' as DefaultMode,
  targetEmail: 'archive@example.com',
  targetFromAddress: '',
  targetForwardType: 'internal' as ForwardType
})
const incomingDefaultEditor = ref({
  mode: 'unmatched' as DefaultMode,
  targetEmail: '',
  targetFromAddress: '',
  targetForwardType: 'internal' as ForwardType
})
const originalIncomingDefault = ref({...incomingDefault.value})

const notificationRules = ref<NotificationRule[]>([])
const incomingRules = ref<IncomingRule[]>([])
const originalNotificationRules = ref<NotificationRule[]>([])
const originalIncomingRules = ref<IncomingRule[]>([])

const ruleEditor = ref<RuleEditorState>(createEmptyRuleEditor('notification'))

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
    defaultNotificationChannelIds.value
        .map((id) => notificationChannels.value.find((channel) => channel.id === id))
        .filter((channel): channel is NotificationChannel => Boolean(channel))
))

const resolvedLogWebhookTargets = computed(() => {
  if (!selectedLog.value) {
    return []
  }

  return resolveWebhookTargetsForLog(selectedLog.value)
})

const resolvedLogForwardTargets = computed(() => {
  if (!selectedLog.value) {
    return []
  }

  return resolveForwardTargetsForLog(selectedLog.value)
})

const selectedDefaultChannelNames = computed(() => {
  if (selectedDefaultChannels.value.length === 0) {
    return '未选择通道'
  }
  return selectedDefaultChannels.value.map((channel) => channel.name).join(' / ')
})

const defaultNotificationModeLabel = computed(() => (
    defaultNotificationMode.value === 'always' ? '始终发送所有邮件' : '仅未命中时发送'
))

const incomingDefaultModeLabel = computed(() => (
    incomingDefault.value.mode === 'always' ? '始终转发所有邮件' : '仅未命中时转发'
))

const ruleEditorTitle = computed(() => (
    `${ruleEditor.value.id ? '编辑' : '新增'}${ruleEditor.value.category === 'notification' ? '通知规则' : '收件转发规则'}`
))

const channelEditorTitle = computed(() => (
    `${channelEditor.value.id ? '编辑' : '新增'}通知通道`
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

function createEmptyRuleEditor(category: RuleCategory): RuleEditorState {
  return {
    id: null,
    category,
    name: '',
    enabled: true,
    matchMode: 'all',
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

const cloneChannels = (channels: NotificationChannel[]) => channels.map((channel) => ({...channel}))
const cloneNotificationRules = (rules: NotificationRule[]) => rules.map((rule) => ({
  ...rule,
  targetChannelIds: [...rule.targetChannelIds]
}))
const cloneIncomingRules = (rules: IncomingRule[]) => rules.map((rule) => ({...rule}))

const normalizeNotificationChannels = (channels: unknown): NotificationChannel[] => {
  if (!Array.isArray(channels)) return []

  const seen = new Set<number>()
  return channels
      .filter((channel): channel is Partial<NotificationChannel> => Boolean(channel) && typeof channel === 'object')
      .map((channel) => ({
        id: Number(channel.id),
        name: typeof channel.name === 'string' ? channel.name.trim() : '',
        type: (channel.type === 'feishu' || channel.type === 'bark' ? channel.type : 'dingtalk') as WebhookType,
        url: typeof channel.url === 'string' ? channel.url.trim() : '',
        secret: typeof channel.secret === 'string' ? channel.secret.trim() : '',
        enabled: channel.enabled !== false
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
  originalDefaultNotificationState.value = {
    enabled: defaultNotificationEnabled.value,
    mode: defaultNotificationMode.value,
    channelIds: [...defaultNotificationChannelIds.value]
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

const normalizeNotificationRule = (rule: NotificationRule): NotificationRule => ({
  id: Number(rule.id),
  name: rule.name || '',
  enabled: Boolean(rule.enabled),
  matchMode: rule.matchMode === 'any' ? 'any' : 'all',
  senderPattern: rule.senderPattern || '',
  recipientPattern: rule.recipientPattern || '',
  subjectPattern: rule.subjectPattern || '',
  contentPattern: rule.contentPattern || '',
  targetChannelIds: Array.isArray(rule.targetChannelIds) ? rule.targetChannelIds.map(Number).filter(Number.isInteger) : []
})

const normalizeIncomingRule = (rule: IncomingRule): IncomingRule => ({
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
  targetForwardType: rule.targetForwardType === 'smtp' || rule.targetForwardType === 'cf' ? rule.targetForwardType : 'internal'
})

const applyDefaultNotificationRule = (rule: DefaultNotificationRule | SavedRoutingRule | null | undefined) => {
  if (!rule) return

  defaultNotificationRuleId.value = Number(rule.id)
  defaultNotificationEnabled.value = Boolean(rule.enabled)
  defaultNotificationMode.value = rule.defaultMode === 'always' ? 'always' : 'unmatched'
  defaultNotificationChannelIds.value = Array.isArray(rule.targetChannelIds)
      ? rule.targetChannelIds.map(Number).filter(Number.isInteger)
      : []
  originalDefaultNotificationState.value = {
    enabled: defaultNotificationEnabled.value,
    mode: defaultNotificationMode.value,
    channelIds: [...defaultNotificationChannelIds.value]
  }
}

const applyDefaultIncomingRule = (rule: DefaultIncomingRule | SavedRoutingRule | null | undefined) => {
  if (!rule) return

  defaultIncomingRuleId.value = Number(rule.id)
  incomingDefault.value = {
    enabled: Boolean(rule.enabled),
    mode: rule.defaultMode === 'always' ? 'always' : 'unmatched',
    targetEmail: rule.targetEmail || '',
    targetFromAddress: rule.targetFromAddress || '',
    targetForwardType: rule.targetForwardType === 'smtp' || rule.targetForwardType === 'cf' ? rule.targetForwardType : 'internal'
  }
  originalIncomingDefault.value = {...incomingDefault.value}
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
  notificationChannels.value = normalizeNotificationChannels(data.channels)
  originalNotificationChannels.value = cloneChannels(notificationChannels.value)
  notificationRules.value = Array.isArray(data.notificationRules)
      ? data.notificationRules.map(normalizeNotificationRule)
      : []
  originalNotificationRules.value = cloneNotificationRules(notificationRules.value)
  incomingRules.value = Array.isArray(data.incomingRules)
      ? data.incomingRules.map(normalizeIncomingRule)
      : []
  originalIncomingRules.value = cloneIncomingRules(incomingRules.value)
  applyDefaultNotificationRule(data.defaultNotificationRule)
  applyDefaultIncomingRule(data.defaultIncomingRule)
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

const buildDefaultNotificationPayload = () => ({
  id: defaultNotificationRuleId.value || undefined,
  name: '默认通知规则',
  enabled: defaultNotificationEnabled.value,
  isDefault: true,
  defaultMode: defaultNotificationMode.value,
  matchMode: 'all' as MatchMode,
  senderPattern: '',
  recipientPattern: '',
  subjectPattern: '',
  contentPattern: '',
  targetChannelIds: [...defaultNotificationChannelIds.value],
  targetEmail: ''
})

const buildDefaultIncomingPayload = () => ({
  id: defaultIncomingRuleId.value || undefined,
  name: '默认转发规则',
  enabled: incomingDefault.value.enabled,
  isDefault: true,
  defaultMode: incomingDefault.value.mode,
  matchMode: 'all' as MatchMode,
  senderPattern: '',
  recipientPattern: '',
  subjectPattern: '',
  contentPattern: '',
  targetChannelIds: [],
  targetEmail: incomingDefault.value.targetEmail.trim(),
  targetFromAddress: incomingDefault.value.targetFromAddress.trim(),
  targetForwardType: incomingDefault.value.targetForwardType
})

const validateRoutingConfig = () => {
  const channels = normalizeNotificationChannels(notificationChannels.value)
  if (channels.length === 0) {
    throw new Error('至少保留一个通知通道')
  }

  const channelIds = new Set(channels.map((channel) => channel.id))
  const ensureKnownChannels = (ids: number[]) => {
    if (ids.length === 0) {
      throw new Error('至少选择一个通道')
    }
    if (ids.some((id) => !channelIds.has(id))) {
      throw new Error('规则引用了不存在的通知通道')
    }
  }

  ensureKnownChannels(defaultNotificationChannelIds.value)
  notificationRules.value.forEach((rule) => ensureKnownChannels(rule.targetChannelIds))

  if (!incomingDefault.value.targetEmail.trim()) {
    throw new Error('默认转发邮箱不能为空')
  }
  if (
      incomingDefault.value.targetForwardType === 'cf' &&
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(incomingDefault.value.targetFromAddress.trim())
  ) {
    throw new Error('请输入有效的 CF 发件人邮箱')
  }

  incomingRules.value.forEach((rule) => {
    if (!rule.name.trim()) {
      throw new Error('规则名称不能为空')
    }
    if (!rule.targetEmail.trim()) {
      throw new Error('转发邮箱不能为空')
    }
    if (
        rule.targetForwardType === 'cf' &&
        !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(rule.targetFromAddress.trim())
    ) {
      throw new Error('请输入有效的 CF 发件人邮箱')
    }
  })

  return channels
}

const saveRoutingConfig = async () => {
  saving.value = true
  try {
    const channels = validateRoutingConfig()
    const response = await api.post('/routing', {
      action: 'replace',
      config: {
        channels,
        notificationRules: notificationRules.value.map((rule) => ({...rule})),
        incomingRules: incomingRules.value.map((rule) => ({...rule})),
        defaultNotificationRule: buildDefaultNotificationPayload(),
        defaultIncomingRule: buildDefaultIncomingPayload()
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
  notificationChannels.value = cloneChannels(originalNotificationChannels.value)
}

const addChannel = () => {
  channelEditor.value = {
    ...createEmptyChannelEditor(),
    name: `新通道 ${notificationChannels.value.length + 1}`
  }
  channelEditorVisible.value = true
}

const isDefaultChannel = (_channel: NotificationChannel) => false

const removeChannel = (channelId: number) => {
  const channel = notificationChannels.value.find((item) => item.id === channelId)
  if (!channel || isDefaultChannel(channel) || notificationChannels.value.length === 1) {
    return
  }
  notificationChannels.value = notificationChannels.value.filter((channel) => channel.id !== channelId)
  defaultNotificationChannelIds.value = defaultNotificationChannelIds.value.filter((id) => id !== channelId)
  notificationRules.value = notificationRules.value.map((rule) => ({
    ...rule,
    targetChannelIds: rule.targetChannelIds.filter((id) => id !== channelId)
  }))
  toast.success('已从页面移除，保存后生效')
}

const toggleChannel = (channel: NotificationChannel) => {
  channel.enabled = !channel.enabled
}

const openDefaultNotificationEditor = () => {
  defaultNotificationEditor.value = {
    mode: defaultNotificationMode.value,
    channelIds: [...defaultNotificationChannelIds.value]
  }
  defaultNotificationEditorVisible.value = true
}

const closeDefaultNotificationEditor = () => {
  defaultNotificationEditorVisible.value = false
}

const toggleDefaultNotificationEditorChannel = (channelId: number) => {
  const channel = notificationChannels.value.find((item) => item.id === channelId)
  if (!channel || !channel.enabled) return

  if (defaultNotificationEditor.value.channelIds.includes(channelId)) {
    defaultNotificationEditor.value.channelIds = defaultNotificationEditor.value.channelIds.filter((id) => id !== channelId)
  } else {
    defaultNotificationEditor.value.channelIds = [...defaultNotificationEditor.value.channelIds, channelId]
  }
}

const saveDefaultNotificationEditor = () => {
  if (defaultNotificationEditor.value.channelIds.length === 0) {
    toast.error('至少选择一个通道')
    return
  }

  defaultNotificationMode.value = defaultNotificationEditor.value.mode
  defaultNotificationChannelIds.value = [...defaultNotificationEditor.value.channelIds]
  closeDefaultNotificationEditor()
}

const openEditChannel = (channel: NotificationChannel) => {
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

  const channel: NotificationChannel = {
    id: channelEditor.value.id || temporaryRoutingId--,
    name: channelEditor.value.name.trim(),
    type: channelEditor.value.type,
    url: channelEditor.value.url.trim(),
    secret: channelEditor.value.secret.trim(),
    enabled: true
  }

  const index = notificationChannels.value.findIndex((item) => item.id === channel.id)
  if (index >= 0) {
    channel.enabled = notificationChannels.value[index].enabled
    notificationChannels.value.splice(index, 1, channel)
  } else {
    notificationChannels.value.unshift(channel)
  }

  closeChannelEditor()
}

const toggleDefaultNotificationEnabled = () => {
  defaultNotificationEnabled.value = !defaultNotificationEnabled.value
}

const resetDefaultNotificationRule = () => {
  defaultNotificationEnabled.value = originalDefaultNotificationState.value.enabled
  defaultNotificationMode.value = originalDefaultNotificationState.value.mode
  defaultNotificationChannelIds.value = [...originalDefaultNotificationState.value.channelIds]
}

const openIncomingDefaultEditor = () => {
  incomingDefaultEditor.value = {
    mode: incomingDefault.value.mode,
    targetEmail: incomingDefault.value.targetEmail,
    targetFromAddress: incomingDefault.value.targetFromAddress,
    targetForwardType: incomingDefault.value.targetForwardType
  }
  incomingDefaultEditorVisible.value = true
}

const closeIncomingDefaultEditor = () => {
  incomingDefaultEditorVisible.value = false
}

const saveIncomingDefaultEditor = () => {
  if (!incomingDefaultEditor.value.targetEmail.trim()) {
    toast.error('默认转发邮箱不能为空')
    return
  }
  if (
      incomingDefaultEditor.value.targetForwardType === 'cf' &&
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(incomingDefaultEditor.value.targetFromAddress.trim())
  ) {
    toast.error('请输入有效的 CF 发件人邮箱')
    return
  }

  incomingDefault.value = {
    ...incomingDefault.value,
    mode: incomingDefaultEditor.value.mode,
    targetEmail: incomingDefaultEditor.value.targetEmail.trim(),
    targetFromAddress: incomingDefaultEditor.value.targetFromAddress.trim(),
    targetForwardType: incomingDefaultEditor.value.targetForwardType
  }
  closeIncomingDefaultEditor()
}

const toggleIncomingDefaultEnabled = () => {
  incomingDefault.value.enabled = !incomingDefault.value.enabled
}

const resetIncomingDefaultRule = () => {
  incomingDefault.value = {...originalIncomingDefault.value}
}

const openCreateRule = (category: RuleCategory) => {
  ruleEditor.value = createEmptyRuleEditor(category)
  ruleEditorVisible.value = true
}

const openEditRule = (rule: NotificationRule | IncomingRule) => {
  if ('targetChannelIds' in rule) {
    ruleEditor.value = {
      id: rule.id,
      category: 'notification',
      name: rule.name,
      enabled: rule.enabled,
      matchMode: rule.matchMode,
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
      category: 'incoming',
      name: rule.name,
      enabled: rule.enabled,
      matchMode: rule.matchMode,
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
  const channel = notificationChannels.value.find((item) => item.id === channelId)
  if (!channel || !channel.enabled) return

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

  if (ruleEditor.value.category === 'notification' && ruleEditor.value.targetChannelIds.length === 0) {
    toast.error('至少选择一个通道')
    return
  }

  if (ruleEditor.value.category === 'incoming' && !ruleEditor.value.targetEmail.trim()) {
    toast.error('转发邮箱不能为空')
    return
  }

  if (
      ruleEditor.value.category === 'incoming' &&
      ruleEditor.value.targetForwardType === 'cf' &&
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(ruleEditor.value.targetFromAddress.trim())
  ) {
    toast.error('请输入有效的 CF 发件人邮箱')
    return
  }

  const id = ruleEditor.value.id || temporaryRoutingId--
  if (ruleEditor.value.category === 'notification') {
    const rule: NotificationRule = {
      id,
      name: ruleEditor.value.name.trim(),
      enabled: ruleEditor.value.enabled,
      matchMode: ruleEditor.value.matchMode,
      senderPattern: ruleEditor.value.senderPattern.trim(),
      recipientPattern: ruleEditor.value.recipientPattern.trim(),
      subjectPattern: ruleEditor.value.subjectPattern.trim(),
      contentPattern: ruleEditor.value.contentPattern.trim(),
      targetChannelIds: [...ruleEditor.value.targetChannelIds]
    }
    const index = notificationRules.value.findIndex((item) => item.id === id)
    if (index >= 0) notificationRules.value.splice(index, 1, rule)
    else notificationRules.value.unshift(rule)
  } else {
    const rule: IncomingRule = {
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
    const index = incomingRules.value.findIndex((item) => item.id === id)
    if (index >= 0) incomingRules.value.splice(index, 1, rule)
    else incomingRules.value.unshift(rule)
  }
  closeRuleEditor()
  toast.success('已应用到页面，保存后生效')
}

const toggleNotificationRule = (rule: NotificationRule) => {
  rule.enabled = !rule.enabled
}

const toggleIncomingRule = (rule: IncomingRule) => {
  rule.enabled = !rule.enabled
}

const deleteNotificationRule = (id: number) => {
  notificationRules.value = notificationRules.value.filter((rule) => rule.id !== id)
  toast.success('已从页面移除，保存后生效')
}

const deleteIncomingRule = (id: number) => {
  incomingRules.value = incomingRules.value.filter((rule) => rule.id !== id)
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
    path: '/all-emails',
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

const formatChannelNames = (channelIds: number[]) => {
  const names = channelIds
      .map((id) => notificationChannels.value.find((channel) => channel.id === id)?.name)
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
    smtp: 'SMTP 转发',
    cf: 'CF 转发'
  }
  return labels[type] || type
}

const getLogChannelLabel = (log: any) => {
  const matchedChannel = notificationChannels.value.find((channel) => channel.url === log.webhook_url)
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

const matchesRule = (
    source: { from_address?: string; to_address?: string; subject?: string; content?: string },
    rule: {
      matchMode: MatchMode;
      senderPattern: string;
      recipientPattern: string;
      subjectPattern: string;
      contentPattern: string
    }
) => {
  const checks = [
    !rule.senderPattern || (source.from_address || '').toLowerCase().includes(rule.senderPattern.toLowerCase()),
    !rule.recipientPattern || (source.to_address || '').toLowerCase().includes(rule.recipientPattern.toLowerCase()),
    !rule.subjectPattern || (source.subject || '').toLowerCase().includes(rule.subjectPattern.toLowerCase()),
    !rule.contentPattern || (source.content || '').toLowerCase().includes(rule.contentPattern.toLowerCase())
  ]

  return rule.matchMode === 'all' ? checks.every(Boolean) : checks.some(Boolean)
}

const resolveWebhookTargetsForLog = (log: any) => {
  const currentChannels: NotificationChannel[] = []

  notificationRules.value
      .filter((rule) => rule.enabled && matchesRule(log, rule))
      .flatMap((rule) => rule.targetChannelIds)
      .forEach((channelId) => {
        const channel = notificationChannels.value.find((item) => item.id === channelId && item.enabled)
        if (channel && !currentChannels.some((item) => item.id === channel.id)) {
          currentChannels.push(channel)
        }
      })

  if (defaultNotificationEnabled.value) {
    const shouldUseDefault = defaultNotificationMode.value === 'always' || currentChannels.length === 0
    if (shouldUseDefault) {
      selectedDefaultChannels.value.forEach((channel) => {
        if (channel.enabled && !currentChannels.some((item) => item.id === channel.id)) {
          currentChannels.push(channel)
        }
      })
    }
  }

  if (currentChannels.length === 0) {
    const matchedByUrl = notificationChannels.value.find((channel) => channel.url === log.webhook_url)
    if (matchedByUrl) {
      currentChannels.push(matchedByUrl)
    }
  }

  return currentChannels
}

const resolveForwardTargetsForLog = (log: any) => {
  const targets = incomingRules.value
      .filter((rule) => rule.enabled && matchesRule(log, rule))
      .map((rule) => rule.targetEmail)

  if (incomingDefault.value.enabled) {
    const shouldUseDefault = incomingDefault.value.mode === 'always' || targets.length === 0
    if (shouldUseDefault && incomingDefault.value.targetEmail.trim()) {
      targets.push(incomingDefault.value.targetEmail.trim())
    }
  }

  return Array.from(new Set(targets))
}

const getRuleConditionChips = (rule: NotificationRule | IncomingRule) => {
  const chips: string[] = [matchModeLabel(rule.matchMode)]
  if (rule.senderPattern) chips.push(`发件人含 ${rule.senderPattern}`)
  if (rule.recipientPattern) chips.push(`收件人含 ${rule.recipientPattern}`)
  if (rule.subjectPattern) chips.push(`主题含 ${rule.subjectPattern}`)
  if (rule.contentPattern) chips.push(`正文含 ${rule.contentPattern}`)
  return chips.length > 0 ? chips : ['匹配全部邮件']
}

const formatDateTime = (value?: string | null) => value ? new Date(value).toLocaleString('zh-CN') : '未记录'

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
