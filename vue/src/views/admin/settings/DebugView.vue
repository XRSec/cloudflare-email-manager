<template>
  <div class="debug-page">
    <div class="page-header">
      <h1>{{ pageIcon }} {{ pageTitle }}</h1>
      <span class="debug-badge">仅调试模式可用</span>
    </div>

    <div class="debug-content">
      <!-- 系统信息 -->
      <div class="debug-section">
        <h2>系统信息</h2>
        <div class="info-grid">
          <div class="info-item">
            <label>用户信息:</label>
            <span>{{ userInfo }}</span>
          </div>
          <div class="info-item">
            <label>认证状态:</label>
            <span>{{ authStatus }}</span>
          </div>
          <div class="info-item">
            <label>用户类型:</label>
            <span>{{ userType }}</span>
          </div>
          <div class="info-item">
            <label>API 基础 URL:</label>
            <span>{{ apiBaseUrl }}</span>
          </div>
          <div class="info-item">
            <label>环境模式:</label>
            <span>{{ environment }}</span>
          </div>
          <div class="info-item">
            <label>调试模式:</label>
            <span>{{ debugMode ? '已启用' : '已禁用' }}</span>
          </div>
        </div>
      </div>

      <!-- 模拟邮件接收 -->
      <div class="debug-section">
        <div class="section-header">
          <h2>模拟邮件接收</h2>
          <button class="btn btn-sm btn-secondary" @click="showEmailForm = !showEmailForm">
            {{ showEmailForm ? '🔼 收起' : '🔽 展开' }}
          </button>
        </div>
        <p v-if="showEmailForm" class="debug-note">此功能模拟邮件接收，邮件会被系统处理并存储到数据库中</p>
        <form v-if="showEmailForm" @submit.prevent="sendTestEmail" class="email-form">
          <div class="form-group">
            <label class="form-label">发件人</label>
            <input v-model="testEmail.from" type="email" class="form-control" placeholder="sender@example.com" required>
          </div>
          <div class="form-group">
            <label class="form-label">收件人</label>
            <input v-model="testEmail.to" type="email" class="form-control" placeholder="user@example.com" required>
          </div>
          <div class="form-group">
            <label class="form-label">主题</label>
            <input v-model="testEmail.subject" type="text" class="form-control" placeholder="测试邮件主题" required>
          </div>
          <div class="form-group">
            <label class="form-label">内容</label>
            <textarea v-model="testEmail.content" class="form-control" rows="3" placeholder="测试邮件内容"
              required></textarea>
          </div>
          <button type="submit" class="btn btn-primary" :disabled="sending">
            {{ sending ? '模拟中...' : '模拟邮件接收' }}
          </button>
        </form>
      </div>

      <!-- API 测试 -->
      <div class="debug-section">
        <h2>API 测试</h2>
        <div class="api-tests">
          <button class="btn btn-secondary" @click="testSystemHealth">
            测试系统健康状态
          </button>
          <button class="btn btn-secondary" @click="testSystemConfig">
            获取系统配置
          </button>
          <button class="btn btn-secondary" @click="testUserInfo">
            获取用户信息
          </button>
          <button class="btn btn-secondary" @click="testForwardRules">
            测试转发规则
          </button>
        </div>
        <div v-if="testResult" class="test-result">
          <h3>测试结果:</h3>
          <pre>{{ testResult }}</pre>
        </div>
      </div>

      <!-- 数据库管理 -->
      <div class="debug-section">
        <h2>数据库管理</h2>
        <p class="debug-note">数据库信息：查看SQLite版本、记录总数等基本信息<br>
          数据表浏览: 查看各个数据表的结构和数据（每表显示最新10条记录）<br>
          测试数据库连接: 验证数据库连接状态和响应时间<br>
          数据库统计: 查看数据库的详细统计信息<br>
          数据库初始化: ⚠️ 完全重置数据库，删除所有数据</p>

        <!-- 操作按钮行 -->
        <div class="db-actions">
          <button v-for="operation in databaseOperations" :key="operation.id" class="btn" :class="[
            operation.danger ? 'btn-danger' : 'btn-secondary',
            { active: activeOperation === operation.id }
          ]" @click="setActiveOperation(operation.id)" :disabled="operation.loading && operation.loading()">
            {{ operation.icon }} {{ operation.title }}
            <span v-if="operation.loading && operation.loading()" class="loading-text">...</span>
          </button>
        </div>

        <!-- 提示文本 -->
        <div v-if="activeOperation" class="operation-hint">
          {{ getActiveOperationInfo()?.description }}
        </div>

        <!-- 内容区域 -->
        <div v-if="activeOperation && hasActiveOperationData()" class="operation-content">
          <!-- 数据库信息内容 -->
          <div v-if="activeOperation === 'dbInfo'" class="db-info">
            <!-- 主要布局容器 -->
            <div class="db-info-layout">
              <!-- 左侧：基本信息卡片 -->
              <div class="db-overview-cards">
                <div class="db-overview-card">
                  <div class="card-icon">🗄️</div>
                  <div class="card-content">
                    <h4>SQLite 版本</h4>
                    <p>{{ databaseInfo.sqliteVersion || 'Unknown' }}</p>
                  </div>
                </div>

                <div class="db-overview-card">
                  <div class="card-icon">📊</div>
                  <div class="card-content">
                    <h4>总记录数</h4>
                    <p>{{ databaseInfo.totalRecords?.toLocaleString() || 0 }} 条</p>
                  </div>
                </div>

                <div class="db-overview-card">
                  <div class="card-icon">📅</div>
                  <div class="card-content">
                    <h4>更新时间</h4>
                    <p>{{ formatTime(databaseInfo.timestamp) }}</p>
                  </div>
                </div>

                <div class="db-overview-card">
                  <div class="card-icon">🏷️</div>
                  <div class="card-content">
                    <h4>数据表数</h4>
                    <p>{{ getTableCount(databaseInfo.tables) }} 个</p>
                  </div>
                </div>
              </div>

              <!-- 右侧：表格详情 -->
              <div class="tables-detail">
                <h4>📋 数据表状态</h4>
                <div class="vue-table-container">
                  <table class="vue-table">
                    <thead>
                      <tr>
                        <th class="table-icon-col">图标</th>
                        <th class="table-name-col">表名</th>
                        <th class="table-records-col">记录数</th>
                        <th class="table-status-col">状态</th>
                      </tr>
                    </thead>
                    <tbody>
                      <tr v-for="(tableInfo, tableName) in databaseInfo.tables" :key="tableName" class="table-row"
                        :class="{ 'error-row': tableInfo.error }">
                        <td class="table-icon-cell">🗃️</td>
                        <td class="table-name-cell">{{ tableName }}</td>
                        <td class="table-records-cell">{{ tableInfo.recordCount?.toLocaleString() || 0 }}</td>
                        <td class="table-status-cell">
                          <span v-if="tableInfo.error" class="status-badge error" :title="tableInfo.error">
                            ❌ 错误
                          </span>
                          <span v-else class="status-badge success">
                            ✅ 正常
                          </span>
                        </td>
                      </tr>
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          </div>

          <!-- 数据表浏览内容 -->
          <div v-if="activeOperation === 'tableBrowser'">
            <div v-if="allTablesLoading" class="loading-state">
              <div class="loading-spinner">🔄</div>
              <span>加载所有数据表中...</span>
            </div>

            <div v-if="!allTablesLoading && allTablesData.length > 0" class="all-tables-container">
              <div v-for="tableData in allTablesData" :key="tableData.table" class="single-table-section">
                <!-- 有数据的表格显示完整结构 -->
                <div v-if="!tableData.error && tableData.records?.length > 0">
                  <div class="table-header-section">
                    <h4 class="table-title">
                      🗃️ {{ tableData.table }}
                      <span class="record-count">({{ tableData.total }} 条记录)</span>
                    </h4>
                  </div>
                  <div class="simple-table">
                    <div class="table-grid" :style="{ gridTemplateColumns: getSimpleGridColumns(tableData.columns) }">
                      <!-- 表头 -->
                      <div v-for="column in tableData.columns" :key="`header-${column}`" class="grid-header"
                        :class="getColumnClass(column)">
                        {{ column }}
                      </div>

                      <!-- 数据行 -->
                      <template v-for="(record, rowIndex) in tableData.records" :key="rowIndex">
                        <div v-for="column in tableData.columns" :key="`${rowIndex}-${column}`" class="grid-cell"
                          :class="getColumnClass(column)" :title="String(record[column] || '')">
                          {{ formatCellValue(record[column]) }}
                        </div>
                      </template>
                    </div>
                  </div>
                </div>

                <!-- 有错误的表格显示错误信息 -->
                <div v-else-if="tableData.error" class="error-table">
                  <div class="table-header-section">
                    <h4 class="table-title">
                      🗃️ {{ tableData.table }}
                    </h4>
                    <div class="table-error">
                      ❌ {{ tableData.error }}
                    </div>
                  </div>
                </div>

                <!-- 无数据的表格显示表结构和提示 -->
                <div v-else class="empty-table-with-structure">
                  <div class="table-header-section">
                    <h4 class="table-title">
                      🗃️ {{ tableData.table }}
                      <span class="record-count">({{ tableData.total }} 条记录)</span>
                    </h4>
                  </div>
                  <div class="empty-table-structure">
                    <div class="table-grid" :style="{ gridTemplateColumns: getSimpleGridColumns(tableData.columns) }">
                      <!-- 表头 -->
                      <div v-for="column in tableData.columns" :key="`header-${column}`" class="grid-header"
                        :class="getColumnClass(column)">
                        {{ column }}
                      </div>
                    </div>
                    <div class="empty-data-message">
                      <span class="empty-icon">📋</span>
                      <span class="empty-text">暂无数据</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <!-- 数据库连接测试内容 -->
          <div v-if="activeOperation === 'dbTest'">
            <div v-if="dbTestResult" class="test-result"
              :class="{ success: dbTestResult.success, error: !dbTestResult.success }">
              <div class="test-status">
                <span class="status-icon">{{ dbTestResult.success ? '✅' : '❌' }}</span>
                <span class="status-text">{{ dbTestResult.message }}</span>
              </div>

              <div class="test-details">
                <div class="detail-item">
                  <label>响应时间:</label>
                  <span>{{ dbTestResult.responseTime }}ms</span>
                </div>
                <div class="detail-item">
                  <label>测试时间:</label>
                  <span>{{ dbTestResult.timestamp }}</span>
                </div>
                <div v-if="dbTestResult.details" class="detail-item">
                  <label>数据库版本:</label>
                  <span>{{ dbTestResult.details.version }}</span>
                </div>
                <div v-if="dbTestResult.details" class="detail-item">
                  <label>表数量:</label>
                  <span>{{ dbTestResult.details.totalTables }}</span>
                </div>
                <div v-if="dbTestResult.error" class="detail-item">
                  <label>错误信息:</label>
                  <span class="error-text">{{ dbTestResult.error }}</span>
                </div>
              </div>
            </div>
          </div>

          <!-- 数据库统计内容 -->
          <div v-if="activeOperation === 'dbStats'">
            <div v-if="dbStats" class="db-stats">
              <!-- 总览统计 -->
              <div class="stats-overview">
                <h4>📊 数据库总览</h4>
                <div class="stats-grid">
                  <div class="stat-card">
                    <div class="stat-value">{{ dbStats.totalRecords?.toLocaleString() || '0' }}</div>
                    <div class="stat-label">总记录数</div>
                  </div>
                  <div class="stat-card">
                    <div class="stat-value">{{ dbStats.activeTableCount || '0' }}</div>
                    <div class="stat-label">活跃表数</div>
                  </div>
                  <div class="stat-card">
                    <div class="stat-value">{{ formatFileSize(dbStats.totalSize) }}</div>
                    <div class="stat-label">数据库大小</div>
                  </div>
                </div>
              </div>

              <!-- 详细统计 -->
              <div class="stats-details">
                <div class="stats-section">
                  <h5>📧 邮件统计</h5>
                  <div class="stats-list">
                    <div class="stats-item">
                      <span>总邮件数:</span>
                      <span>{{ dbStats.emailStats?.total?.toLocaleString() || '0' }}</span>
                    </div>
                    <div class="stats-item">
                      <span>今日邮件:</span>
                      <span>{{ dbStats.emailStats?.today || '0' }}</span>
                    </div>
                    <div class="stats-item">
                      <span>未读邮件:</span>
                      <span>{{ dbStats.emailStats?.unread || '0' }}</span>
                    </div>
                  </div>
                </div>

                <div class="stats-section">
                  <h5>👥 用户统计</h5>
                  <div class="stats-list">
                    <div class="stats-item">
                      <span>总用户数:</span>
                      <span>{{ dbStats.userStats?.total || '0' }}</span>
                    </div>
                    <div class="stats-item">
                      <span>管理员:</span>
                      <span>{{ dbStats.userStats?.admins || '0' }}</span>
                    </div>
                    <div class="stats-item">
                      <span>活跃用户:</span>
                      <span>{{ dbStats.userStats?.active || '0' }}</span>
                    </div>
                  </div>
                </div>

                <div class="stats-section">
                  <h5>⚙️ 系统统计</h5>
                  <div class="stats-list">
                    <div class="stats-item">
                      <span>转发规则:</span>
                      <span>{{ dbStats.systemStats?.forwardRules || '0' }}</span>
                    </div>
                    <div class="stats-item">
                      <span>邮箱地址:</span>
                      <span>{{ dbStats.systemStats?.mailboxes || '0' }}</span>
                    </div>
                    <div class="stats-item">
                      <span>上次统计:</span>
                      <span>{{ new Date().toLocaleString() }}</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <!-- 数据库初始化内容 -->
          <div v-if="activeOperation === 'dbInit'">
            <div class="danger-zone">
              <p class="danger-warning">
                ⚠️ <strong>危险操作</strong>：此操作将清空所有数据并重新初始化数据库！
              </p>
              <p class="danger-note">
                操作包括：删除所有表 → 清空序列 → 重新创建表结构 → 插入初始数据
              </p>

              <div class="form-group">
                <label class="form-label">确认文本（请输入：CONFIRM_RESET_DATABASE）</label>
                <input v-model="confirmText" type="text" class="form-control" placeholder="CONFIRM_RESET_DATABASE" />
              </div>

              <button class="btn btn-danger" @click="initializeDatabase"
                :disabled="initLoading || confirmText !== 'CONFIRM_RESET_DATABASE'">
                {{ initLoading ? '初始化中...' : '初始化数据库' }}
              </button>
            </div>

            <div v-if="initResult" class="init-result">
              <h4>初始化结果:</h4>
              <div class="init-steps">
                <div v-for="(step, index) in initResult.steps" :key="index" class="init-step"
                  :class="{ success: step.includes('✅'), error: step.includes('❌') }">
                  {{ step }}
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- 缓存管理 -->
    <div class="debug-section">
      <h2>缓存管理</h2>
      <p class="debug-note">
        管理应用存储：localStorage、sessionStorage、IndexedDB<br>
        查看缓存信息：查看所有缓存项的详细信息，包括大小、TTL、状态等<br>
        清理缓存：清理应用存储数据，支持清理其他存储或完全清理<br>
        📌 HTTP 缓存（Cache-Control）由后端 Worker 自动设置：HTML 不缓存，CSS/JS/图片等静态资源缓存 1 年<br>
        ⚠️ 注意：清理后可能需要刷新页面才能完全生效
      </p>

      <!-- 操作按钮行 -->
      <div class="db-actions">
        <button v-for="operation in cacheOperations" :key="operation.id" class="btn" :class="[
          operation.danger ? 'btn-danger' : 'btn-secondary',
          { active: activeCacheOperation === operation.id }
        ]" @click="setActiveCacheOperation(operation.id)" :disabled="operation.loading && operation.loading()">
          {{ operation.icon }} {{ operation.title }}
          <span v-if="operation.loading && operation.loading()" class="loading-text">...</span>
        </button>
      </div>

      <!-- 提示文本 -->
      <div v-if="activeCacheOperation" class="operation-hint">
        {{ getActiveCacheOperationInfo()?.description }}
      </div>

      <!-- 内容区域 -->
      <div v-if="activeCacheOperation && hasActiveCacheOperationData()" class="operation-content">
        <!-- 查看缓存信息内容 -->
        <div v-if="activeCacheOperation === 'cacheInfo'">
          <!-- 应用存储统计 -->
          <div class="cache-stats" v-if="cacheStats && cacheStats.localStorage !== undefined">
            <h3>📦 应用存储统计</h3>
            <div class="stats-grid">
              <div class="stat-item">
                <label>localStorage:</label>
                <span>{{ cacheStats.localStorage }} 项</span>
              </div>
              <div class="stat-item">
                <label>sessionStorage:</label>
                <span>{{ cacheStats.sessionStorage }} 项</span>
              </div>
              <div class="stat-item">
                <label>IndexedDB:</label>
                <span>{{ cacheStats.indexedDB }} 个数据库</span>
              </div>
              <div class="stat-item">
                <label>总大小:</label>
                <span>{{ formatBytes(cacheStats.totalSize) }}</span>
              </div>
            </div>
          </div>

          <!-- 缓存统计概览 -->
          <div v-if="cacheStats && cacheStats.totalCount !== undefined" class="cache-stats">
            <h3>📊 缓存统计概览</h3>
            <div class="stats-grid">
              <div class="stat-card">
                <div class="stat-title">📈 总体状况</div>
                <div class="stat-content">
                  <div class="stat-item">
                    <span class="stat-label">缓存总数:</span>
                    <span class="stat-value">{{ cacheStats.totalCount || 0 }}</span>
                  </div>
                  <div class="stat-item">
                    <span class="stat-label">总大小:</span>
                    <span class="stat-value">{{ formatFileSize(cacheStats.totalSize) }}</span>
                  </div>
                  <div class="stat-item">
                    <span class="stat-label">命中率:</span>
                    <span class="stat-value">{{ cacheStats.hitRate || '0%' }}</span>
                  </div>
                </div>
              </div>

              <div class="stat-card">
                <div class="stat-title">🏷️ 分类统计</div>
                <div class="stat-content">
                  <div v-for="(count, category) in cacheStats.categories" :key="category" class="stat-item">
                    <span class="stat-label">{{ category }}:</span>
                    <span class="stat-value">{{ count }}</span>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <!-- 缓存详细信息 -->
          <div v-if="cacheInfo" class="cache-result">
            <h3>📋 缓存详细信息</h3>

            <!-- 有缓存数据时显示表格 -->
            <div v-if="Object.keys(parseCacheInfo(cacheInfo)).length > 0" class="cache-table-container">
              <div class="cache-table-grid" :style="{ gridTemplateColumns: getCacheGridColumns() }">
                <!-- 表头 -->
                <div class="cache-grid-header">缓存键</div>
                <div class="cache-grid-header">类型</div>
                <div class="cache-grid-header">大小</div>
                <div class="cache-grid-header">创建时间</div>
                <div class="cache-grid-header">过期时间</div>
                <div class="cache-grid-header">剩余TTL</div>
                <div class="cache-grid-header">访问次数</div>
                <div class="cache-grid-header">状态</div>
                <div class="cache-grid-header">操作</div>

                <!-- 数据行 -->
                <template v-for="(info, key) in parseCacheInfo(cacheInfo)" :key="key">
                  <div class="cache-grid-cell cache-key-cell" :title="String(key)">
                    <span class="cache-key-text">{{ key }}</span>
                  </div>
                  <div class="cache-grid-cell cache-type-cell">
                    <span class="cache-type-badge">{{ getCacheType(String(key)) }}</span>
                  </div>
                  <div class="cache-grid-cell cache-size-cell">
                    <span class="cache-size-value">{{ formatCacheSize(info.size || 0) }}</span>
                  </div>
                  <div class="cache-grid-cell cache-time-cell">
                    <span class="cache-time-value">{{ formatCacheTime(String(info.created || new Date().toISOString()))
                      }}</span>
                  </div>
                  <div class="cache-grid-cell cache-expiry-cell">
                    <span class="cache-expiry-value">{{ formatCacheExpiry(String(info.created || new
                      Date().toISOString()),
                      String(info.ttl || '300')) }}</span>
                  </div>
                  <div class="cache-grid-cell cache-ttl-cell">
                    <span class="cache-ttl-value"
                      :class="getTTLClass(String(info.created || new Date().toISOString()), String(info.ttl || '300'))">
                      {{ formatRemainingTTL(String(info.created || new Date().toISOString()), String(info.ttl || '300'))
                      }}
                    </span>
                  </div>
                  <div class="cache-grid-cell cache-access-cell">
                    <span class="cache-access-value">{{ info.accessCount || 0 }}</span>
                  </div>
                  <div class="cache-grid-cell cache-status-cell">
                    <span class="cache-status-badge" :class="getCacheStatusClass(info)">
                      {{ getCacheStatus(info) }}
                    </span>
                  </div>
                  <div class="cache-grid-cell cache-actions-cell">
                    <button class="btn btn-sm btn-outline-danger" @click="clearSingleCache(String(key))" title="删除此缓存">
                      🗑️
                    </button>
                    <button class="btn btn-sm btn-outline-info" @click="viewCacheContent(String(key))" title="查看内容">
                      👁️
                    </button>
                  </div>
                </template>
              </div>
            </div>

            <!-- 没有缓存数据时显示提示 -->
            <div v-else class="cache-empty-state">
              <div class="empty-cache-icon">📭</div>
              <div class="empty-cache-text">暂无缓存数据</div>
              <div class="empty-cache-hint">点击"📊 查看缓存信息"按钮可以加载缓存数据</div>
            </div>
          </div>
        </div>

        <!-- 清理缓存内容 -->
        <div v-if="activeCacheOperation === 'cacheClear'">
          <!-- 应用存储清理结果 -->
          <div v-if="cacheClearResult" class="cache-result"
            :class="{ success: cacheClearResult.success, error: !cacheClearResult.success }">
            <h3>{{ cacheClearResult.success ? '✅ 清理成功' : '❌ 清理失败' }}</h3>
            <div v-if="cacheClearResult.cleared && cacheClearResult.cleared.length > 0">
              <p><strong>已清理:</strong></p>
              <ul>
                <li v-for="item in cacheClearResult.cleared" :key="item">{{ item }}</li>
              </ul>
            </div>
            <div v-if="cacheClearResult.errors && cacheClearResult.errors.length > 0">
              <p><strong>错误:</strong></p>
              <ul>
                <li v-for="error in cacheClearResult.errors" :key="error">{{ error }}</li>
              </ul>
            </div>
          </div>

          <!-- 清理操作说明 -->
          <div class="cache-clear-info">
            <p>请选择清理方式：</p>
            <ul>
              <li><strong>清理其他存储</strong>：清理 localStorage、sessionStorage、IndexedDB 中的非 CEM 数据（保留 CEM 缓存、用户信息、系统配置）</li>
              <li><strong>完全清理</strong>：清空所有数据并退出登录（包括 CEM 缓存、用户信息等）</li>
            </ul>
            <button class="btn btn-danger" @click="showClearCacheDialog" :disabled="clearingCache">
              {{ clearingCache ? '清理中...' : '🗑️ 清理缓存' }}
            </button>
          </div>
        </div>
      </div>
    </div>

    <!-- R2 文件管理 -->
    <div class="debug-section">
      <h2>R2 文件管理</h2>
      <p class="debug-note">查看 R2 存储中的文件列表，包括邮件附件和原始邮件文件。不获取文件内容，仅显示文件元数据信息。</p>

      <div class="r2-actions">
        <button class="btn btn-secondary" @click="loadR2Files" :disabled="r2Loading">
          {{ r2Loading ? '加载中...' : '📋 获取 R2 文件列表' }}
        </button>
        <button class="btn btn-secondary" @click="refreshR2Files" :disabled="r2Loading">
          🔄 刷新
        </button>
        <button class="btn btn-danger" @click="deleteSelectedR2Files"
          :disabled="r2Loading || r2Deleting || selectedR2Files.length === 0">
          {{ r2Deleting ? '删除中...' : `🗑️ 删除选中 (${selectedR2Files.length})` }}
        </button>
        <div class="r2-filter">
          <input v-model="r2Prefix" type="text" class="form-control" placeholder="前缀过滤（如：attachments/）"
            @keyup.enter="loadR2Files" />
        </div>
      </div>

      <div v-if="r2Files" class="r2-files-container">
        <div class="r2-files-header">
          <h3>📦 R2 文件列表</h3>
          <div class="r2-files-info">
            <span>共 {{ r2Files.files?.length || 0 }} 个文件</span>
            <span v-if="r2Files.truncated" class="truncated-warning">⚠️ 列表已截断，可能还有更多文件</span>
          </div>
        </div>

        <div v-if="r2Files.files && r2Files.files.length > 0" class="r2-files-table-container">
          <div class="r2-files-table-grid">
            <!-- 表头 -->
            <div class="r2-grid-header r2-checkbox-header">
              <input type="checkbox" :checked="allR2FilesSelected" @change="toggleSelectAllR2Files" />
            </div>
            <div class="r2-grid-header">文件名</div>
            <div class="r2-grid-header">大小</div>
            <div class="r2-grid-header">上传时间</div>
            <div class="r2-grid-header">操作</div>

            <!-- 数据行 -->
            <template v-for="(file, index) in r2Files.files" :key="index">
              <div class="r2-grid-cell r2-checkbox-cell">
                <input type="checkbox" :value="file.key" v-model="selectedR2Files" />
              </div>
              <div class="r2-grid-cell r2-key-cell" :title="file.key">
                <span class="r2-key-text">{{ file.key }}</span>
              </div>
              <div class="r2-grid-cell r2-size-cell">
                <span class="r2-size-value">{{ formatFileSize(file.size) }}</span>
              </div>
              <div class="r2-grid-cell r2-time-cell">
                <span class="r2-time-value">{{ formatR2Time(file.uploaded) }}</span>
              </div>
              <div class="r2-grid-cell r2-action-cell">
                <button class="btn btn-sm btn-outline-danger" @click="deleteR2File(file.key)"
                  :disabled="r2Deleting || selectedR2Files.includes(file.key)" title="删除文件">
                  🗑️ 删除
                </button>
              </div>
            </template>
          </div>
        </div>

        <!-- 没有文件时显示提示 -->
        <div v-else-if="!r2Loading" class="r2-empty-state">
          <div class="empty-r2-icon">📭</div>
          <div class="empty-r2-text">暂无 R2 文件</div>
          <div class="empty-r2-hint">R2 存储中还没有文件，或者当前前缀过滤没有匹配的文件</div>
        </div>

        <!-- 加载状态 -->
        <div v-if="r2Loading" class="r2-loading-state">
          <div class="loading-spinner">🔄</div>
          <span>加载 R2 文件列表中...</span>
        </div>
      </div>
    </div>

    <!-- 缓存内容模态框 -->
    <div v-if="cacheModalVisible" class="cache-content-modal" @click.self="closeCacheModal">
      <div class="modal-overlay">
        <div class="modal-content">
          <div class="modal-header">
            <h3>缓存内容: {{ cacheModalKey }}</h3>
            <button class="modal-close" @click="closeCacheModal">×</button>
          </div>
          <div class="modal-body">
            <pre class="cache-content-text">{{ cacheModalContent }}</pre>
          </div>
          <div class="modal-footer">
            <button class="btn btn-secondary" @click="closeCacheModal">关闭</button>
            <button class="btn btn-primary" @click="copyCacheContent">复制内容</button>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useAuthStore, useSystemStore } from '@/composables/stores'
import { systemApiService, userApiService, apiService } from '@/composables/api'
import { ElMessage, ElMessageBox } from 'element-plus'
import { cacheService, browserCacheManager } from '@/composables/cache'

const authStore = useAuthStore()
const sending = ref(false)
const testResult = ref('')
const cacheInfo = ref<any>(null)
const showEmailForm = ref(false) // 控制模拟邮件接收表单的显示

// 缓存管理
const cacheStats = ref<any>(null)
const loadingCacheStats = ref(false)
const clearingCache = ref(false)
const cacheClearResult = ref<any>(null)

// 缓存操作管理
const activeCacheOperation = ref<string | null>(null)

// 缓存操作API配置
const cacheOperations = ref([
  {
    id: 'cacheInfo',
    icon: '📊',
    title: '查看缓存信息',
    description: '查看所有缓存项的详细信息，包括大小、TTL、状态等',
    buttonText: '获取',
    buttonAction: () => loadCacheInfo(),
    loading: () => loadingCacheStats.value,
    hasData: () => !!cacheInfo.value || (cacheStats.value !== null),
    badge: () => cacheInfo.value ? `${Object.keys(parseCacheInfo(cacheInfo.value)).length} 项` : null,
    danger: false
  },
  {
    id: 'cacheClear',
    icon: '🗑️',
    title: '清理缓存',
    description: '清理应用存储数据，支持清理其他存储或完全清理',
    buttonText: null,
    buttonAction: null,
    loading: () => clearingCache.value,
    hasData: () => true, // 始终可展开
    badge: () => null,
    danger: true
  }
])

// 缓存操作方法
const setActiveCacheOperation = (operationId: string) => {
  if (activeCacheOperation.value === operationId) {
    activeCacheOperation.value = null // 如果点击同一个按钮，则关闭
  } else {
    activeCacheOperation.value = operationId
    // 自动执行操作
    const operation = cacheOperations.value.find(op => op.id === operationId)
    if (operation?.buttonAction) {
      operation.buttonAction()
    }
  }
}

const getActiveCacheOperationInfo = () => {
  return cacheOperations.value.find(op => op.id === activeCacheOperation.value)
}

const hasActiveCacheOperationData = () => {
  const operation = getActiveCacheOperationInfo()
  return operation?.hasData()
}

// 管理员权限判断
const isAdmin = computed(() => authStore.user?.user_type === 1)

// 数据库管理相关
const databaseInfo = ref<any>(null)
const dbLoading = ref(false)
const confirmText = ref('')
const initResult = ref<any>(null)
const initLoading = ref(false)

// 数据表浏览相关
const allTablesData = ref<any[]>([])
const allTablesLoading = ref(false)

// 数据库统计相关
const dbStats = ref<any>(null)
const dbStatsLoading = ref(false)

// 数据库连接测试相关
const dbTestResult = ref<any>(null)
const dbTestLoading = ref(false)

// R2 文件相关
const r2Files = ref<any>(null)
const r2Loading = ref(false)
const r2Prefix = ref('')
const r2Deleting = ref(false)
const selectedR2Files = ref<string[]>([])

// 数据库操作管理
const activeOperation = ref<string | null>(null)

// 数据库操作API配置
const databaseOperations = ref([
  {
    id: 'dbInfo',
    icon: '🗄️',
    title: '数据库信息',
    description: '查看SQLite版本、记录总数等基本信息',
    buttonText: '获取',
    buttonAction: () => loadDatabaseInfo(),
    loading: () => dbLoading.value,
    hasData: () => !!databaseInfo.value,
    badge: () => databaseInfo.value ? `${getTableCount(databaseInfo.value.tables)} 表` : null,
    danger: false
  },
  {
    id: 'tableBrowser',
    icon: '🗃️',
    title: '数据表浏览',
    description: '查看各个数据表的结构和数据（每表显示最新10条记录）',
    buttonText: '刷新',
    buttonAction: () => loadAllTablesData(),
    loading: () => allTablesLoading.value,
    hasData: () => allTablesData.value.length > 0,
    badge: () => allTablesData.value.length > 0 ? `${allTablesData.value.length} 表` : null,
    danger: false
  },
  {
    id: 'dbTest',
    icon: '🔗',
    title: '测试数据库连接',
    description: '验证数据库连接状态和响应时间',
    buttonText: '测试连接',
    buttonAction: () => testDatabaseConnection(),
    loading: () => dbTestLoading.value,
    hasData: () => !!dbTestResult.value,
    badge: () => dbTestResult.value ? (dbTestResult.value.success ? '正常' : '异常') : null,
    danger: false
  },
  {
    id: 'dbStats',
    icon: '📊',
    title: '数据库统计',
    description: '查看数据库的详细统计信息',
    buttonText: '获取统计',
    buttonAction: () => loadDatabaseStats(),
    loading: () => dbStatsLoading.value,
    hasData: () => !!dbStats.value,
    badge: () => dbStats.value ? `${dbStats.value.overview.total_records} 条` : null,
    danger: false
  },
  {
    id: 'dbInit',
    icon: '🔥',
    title: '数据库初始化',
    description: '⚠️ 完全重置数据库，删除所有数据',
    buttonText: null, // 无按钮，直接展开操作
    buttonAction: null,
    loading: () => false,
    hasData: () => true, // 始终可展开
    badge: () => '危险',
    danger: true
  }
])

// 数据库操作方法
const setActiveOperation = (operationId: string) => {
  if (activeOperation.value === operationId) {
    activeOperation.value = null // 如果点击同一个按钮，则关闭
  } else {
    activeOperation.value = operationId
    // 自动执行操作
    const operation = databaseOperations.value.find(op => op.id === operationId)
    if (operation?.buttonAction) {
      operation.buttonAction()
    }
  }
}

const getActiveOperationInfo = () => {
  return databaseOperations.value.find(op => op.id === activeOperation.value)
}

const hasActiveOperationData = () => {
  const operation = getActiveOperationInfo()
  return operation?.hasData()
}


const testEmail = ref({
  from: 'sender@example.com',
  to: 'test@example.com',
  subject: '测试邮件',
  content: '这是一封测试邮件，用于验证邮件发送功能。'
})

// 计算属性
const userInfo = computed(() => {
  if (authStore.user) {
    return `${authStore.user.username} (${authStore.user.email})`
  }
  return '未登录'
})

const authStatus = computed(() => {
  return authStore.isAuthenticated ? '已认证' : '未认证'
})

const userType = computed(() => {
  return authStore.user?.user_type || '未知'
})

const apiBaseUrl = computed(() => {
  return import.meta.env.VITE_API_BASE_URL || '/api'
})

const environment = computed(() => {
  return import.meta.env.MODE || 'development'
})

const debugMode = computed(() => {
  // 优先从 systemStore 读取数据库设置
  const systemStore = useSystemStore()
  if (systemStore.systemConfig?.debug_mode !== undefined) {
    return systemStore.systemConfig.debug_mode === 1
  }
  // 如果数据库设置不可用，则检查环境变量
  return import.meta.env.DEV || import.meta.env.VITE_DEBUG === 'true'
})

// 页面标题和图标
const pageTitle = computed(() => '调试模式')
const pageIcon = computed(() => '🐛')

// 发送测试邮件（使用调试模式模拟邮件接口）
const sendTestEmail = async () => {
  sending.value = true
  try {
    // 使用调试模式的模拟邮件接口
    const response = await fetch('/api/debug/simulate-email', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      credentials: 'include',
      body: JSON.stringify({
        from: testEmail.value.from,
        to: testEmail.value.to,
        subject: testEmail.value.subject,
        content: testEmail.value.content,
        content_type: 'markdown'
      })
    })

    const result = await response.json()

    if (result.success) {
      ElMessage.success('测试邮件模拟成功')
    } else {
      ElMessage.error(result.error || '测试邮件模拟失败')
    }
  } catch (error) {
    console.error('发送测试邮件失败:', error)
    ElMessage.error('发送测试邮件失败')
  } finally {
    sending.value = false
  }
}

// API 测试方法
const testSystemHealth = async () => {
  try {
    const response = await systemApiService.getSystemHealth()
    testResult.value = JSON.stringify(response, null, 2)
  } catch (error) {
    testResult.value = `错误: ${error}`
  }
}

const testSystemConfig = async () => {
  try {
    const response = await systemApiService.getSystemConfig()
    testResult.value = JSON.stringify(response, null, 2)
  } catch (error) {
    testResult.value = `错误: ${error}`
  }
}

const testUserInfo = async () => {
  try {
    const response = await userApiService.getUserProfile()
    testResult.value = JSON.stringify(response, null, 2)
  } catch (error) {
    testResult.value = `错误: ${error}`
  }
}

// 加载缓存信息（合并统计和详细信息）
const loadCacheInfo = async () => {
  loadingCacheStats.value = true
  try {
    // 1. 获取存储统计
    cacheStats.value = await browserCacheManager.getBrowserCacheStats()

    // 2. 获取详细缓存信息
    showCacheInfoData()

    ElMessage.success('缓存信息已加载')
  } catch (error) {
    console.error('加载缓存信息失败:', error)
    ElMessage.error('加载缓存信息失败')
  } finally {
    loadingCacheStats.value = false
  }
}

// 显示清理缓存对话框
const showClearCacheDialog = async () => {
  try {
    await ElMessageBox.confirm(
      '请选择清理方式：\n\n' +
      '• 清理其他存储：清理 localStorage、sessionStorage、IndexedDB 中的非 CEM 数据（保留 CEM 缓存、用户信息、系统配置）\n\n' +
      '• 完全清理：清空所有数据并退出登录（包括 CEM 缓存、用户信息等）',
      '清理缓存',
      {
        distinguishCancelAndClose: true,
        confirmButtonText: '清理其他存储',
        cancelButtonText: '完全清理',
        type: 'warning'
      }
    )
    // 用户点击"清理其他存储"
    clearBrowserCache()
  } catch (error: any) {
    if (error === 'cancel') {
      // 用户点击"完全清理"
      clearAllCache()
    }
    // 其他情况（关闭按钮）不做任何操作
  }
}

const clearBrowserCache = async () => {
  if (!confirm('确定要清理其他存储吗？\n\n这将清理：\n- localStorage 中的非 CEM 数据（保留应用缓存、用户信息、系统配置）\n- sessionStorage 全部数据\n- IndexedDB 全部数据\n\n不会清理：\n- CEM 应用缓存（cem_cache_ 前缀）\n- 用户登录信息\n- 系统配置\n\n注意：HTTP 缓存（CSS/JS 等静态资源）由后端控制，无法通过前端清理。')) {
    return
  }

  clearingCache.value = true
  cacheClearResult.value = null
  try {
    const result = await browserCacheManager.clearAllBrowserCache()
    cacheClearResult.value = result
    if (result.success) {
      ElMessage.success('其他存储清理成功')
      // 刷新统计
      await loadCacheInfo()
    } else {
      ElMessage.warning('其他存储清理完成，但有部分错误')
    }
  } catch (error) {
    console.error('清理其他存储失败:', error)
    ElMessage.error('清理其他存储失败')
    cacheClearResult.value = {
      success: false,
      cleared: [],
      errors: [`清理过程出错: ${error}`]
    }
  } finally {
    clearingCache.value = false
  }
}

// 注意：Cache-Control 头由后端（Worker）设置，前端无法直接设置 HTTP 响应头
// 静态资源（CSS、JS、图片等）的 Cache-Control 已在 worker/src/main.ts 中配置

const formatBytes = (bytes: number): string => {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i]
}

const testForwardRules = async () => {
  try {
    const response = await userApiService.getForwardRules()
    testResult.value = JSON.stringify(response, null, 2)
  } catch (error) {
    testResult.value = `错误: ${error}`
  }
}


// 缓存管理
const clearAllCache = () => {
  if (!confirm('⚠️ 确定要完全清理并退出登录吗？\n\n这将：\n- 清空所有 CEM 应用缓存（cem_cache_ 前缀）\n- 清空所有 localStorage 数据（包括用户信息、系统配置）\n- 清空所有 sessionStorage 数据\n- 清空所有 Cookies\n- 退出登录并跳转到登录页\n\n此操作不可恢复！')) {
    return
  }

  // 清空内存缓存
  cacheService.clear()

  // 清空认证状态
  const authStore = useAuthStore()
  authStore.logout()

  // 清空localStorage中的所有数据
  localStorage.clear()

  // 清空sessionStorage中的所有数据（项目不再使用sessionStorage）
  sessionStorage.clear()

  // 清空所有Cookies
  const cookies = document.cookie.split(';')
  cookies.forEach(cookie => {
    const eqPos = cookie.indexOf('=')
    const name = eqPos > -1 ? cookie.substr(0, eqPos).trim() : cookie.trim()
    if (name) {
      // 删除cookie（设置过期时间为过去）
      document.cookie = `${name}=;expires=Thu, 01 Jan 1970 00:00:00 GMT;path=/`
      document.cookie = `${name}=;expires=Thu, 01 Jan 1970 00:00:00 GMT;path=/;domain=${window.location.hostname}`
      document.cookie = `${name}=;expires=Thu, 01 Jan 1970 00:00:00 GMT;path=/;domain=.${window.location.hostname}`
    }
  })

  // 重新初始化系统配置
  setTimeout(async () => {
    try {
      // 重新获取系统配置
      const systemStore = useSystemStore()
      await systemStore.fetchSystemConfig()

      // 刷新当前页面以重新加载数据
      window.location.reload()
    } catch (error) {
      console.error('重新初始化系统配置失败:', error)
      alert('缓存已清空！请手动刷新页面以重新加载系统配置。')
    }
  }, 100)

  alert('所有缓存已清空！系统将自动重新加载...')
}


// 显示所有存储数据
// 注意：showAllStorage 功能已合并到 loadCacheInfo 中，已删除


const showCacheInfoData = () => {
  const cacheData: Record<string, any> = {}

  // 获取所有localStorage中的数据
  const allLocalStorageKeys = Object.keys(localStorage)

  console.log('所有localStorage键:', allLocalStorageKeys)
  console.log('localStorage总数量:', allLocalStorageKeys.length)
  console.log('所有cookies:', document.cookie)

  // 先显示所有localStorage数据，不进行过滤
  const cemKeys = allLocalStorageKeys

  // 处理每个CEM相关的键
  cemKeys.forEach(key => {
    const item = localStorage.getItem(key);

    if (item) {
      try {
        // 尝试解析为JSON
        const parsedItem = JSON.parse(item)

        // 如果是缓存条目格式（有value, expiry, size）
        if (parsedItem.value !== undefined && parsedItem.expiry !== undefined) {
          const now = Date.now()
          const remainingTtl = Math.max(0, parsedItem.expiry - now)

          cacheData[key] = {
            value: parsedItem.value,
            size: parsedItem.size || JSON.stringify(parsedItem.value || '').length,
            created: new Date(parsedItem.expiry - (parsedItem.expiry - now)).toISOString(),
            ttl: Math.floor(remainingTtl / 1000), // 剩余秒数
            expiry: parsedItem.expiry,
            accessCount: 0
          }
        } else {
          // 如果是普通数据格式
          cacheData[key] = {
            value: parsedItem,
            size: item.length,
            created: new Date().toISOString(),
            ttl: 'persistent', // 持久化数据
            accessCount: 0
          }
        }
      } catch (e) {
        // 如果不是JSON格式，当作字符串处理
        cacheData[key] = {
          value: item,
          size: item.length,
          created: new Date().toISOString(),
          ttl: 'persistent',
          accessCount: 0
        }
      }
    }
  })

  // 获取缓存统计信息
  const stats = cacheService.getStats()

  // 如果没有找到任何缓存，显示空状态
  if (Object.keys(cacheData).length === 0) {
    console.log('没有找到任何缓存数据')
  }

  // 添加缓存统计信息
  const info = {
    cacheSize: Object.keys(cacheData).length,
    cacheKeys: Object.keys(cacheData),
    memoryUsage: (performance as any).memory ? {
      used: Math.round((performance as any).memory.usedJSHeapSize / 1024 / 1024) + ' MB',
      total: Math.round((performance as any).memory.totalJSHeapSize / 1024 / 1024) + ' MB',
      limit: Math.round((performance as any).memory.jsHeapSizeLimit / 1024 / 1024) + ' MB'
    } : '不支持',
    cacheData: cacheData,
    debugInfo: {
      totalCacheSize: Math.round(stats.totalSize / 1024) + ' KB',
      itemCount: stats.itemCount,
      averageSize: Math.round(stats.averageSize) + ' bytes',
      maxTotalSize: '50 MB'
    }
  }

  console.log('缓存信息:', info)
  cacheInfo.value = info
}



// 数据库管理方法
const loadDatabaseInfo = async () => {
  dbLoading.value = true
  try {
    const response = await fetch('/api/database/info', {
      method: 'GET',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json'
      }
    })

    const result = await response.json()

    if (result.success) {
      databaseInfo.value = result.data
    } else {
      throw new Error(result.message || '获取数据库信息失败')
    }
  } catch (error) {
    console.error('获取数据库信息失败:', error)
    ElMessage.error('获取数据库信息失败: ' + (error as Error).message)
    databaseInfo.value = null
  } finally {
    dbLoading.value = false
  }
}

// 加载所有表的数据
const loadAllTablesData = async () => {
  allTablesLoading.value = true
  allTablesData.value = []

  try {
    const response = await fetch('/api/database/tables', {
      method: 'GET',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json'
      }
    })

    const result = await response.json()

    if (result.success) {
      allTablesData.value = result.data
    } else {
      throw new Error(result.message || '获取表数据失败')
    }
  } catch (error) {
    console.error('加载表数据失败:', error)
    // 显示错误状态
    allTablesData.value = [{
      table: 'error',
      error: (error as Error).message,
      columns: [],
      records: [],
      total: 0
    }]
  } finally {
    allTablesLoading.value = false
  }
}


// 格式化单元格值
const formatCellValue = (value: any): string => {
  if (value === null || value === undefined) return '-'
  if (typeof value === 'boolean') return value ? '✅' : '❌'
  if (typeof value === 'string' && value.length > 50) {
    return value.substring(0, 50) + '...'
  }
  return String(value)
}

// 简化的列宽配置函数
const getSimpleGridColumns = (columns: string[]): string => {
  return columns.map(column => {
    // 根据列名设置合适的宽度
    if (column.includes('id') || column === 'size_bytes') {
      return 'max-content' // ID和数字字段保持最小宽度
    } else if (column.includes('created_at') || column.includes('updated_at')) {
      return 'minmax(max-content, 160px)' // 时间字段固定宽度
    } else if (column.includes('filename') || column.includes('content_type') || column.includes('r2_key')) {
      return 'minmax(max-content, 200px)' // 文件名等字段适中宽度
    } else {
      return 'minmax(max-content, 150px)' // 其他字段默认宽度
    }
  }).join(' ')
}

// 根据列名获取CSS类
const getColumnClass = (column: string): string => {
  const classes = []

  // 文本对齐
  if (['id', 'user_id', 'is_active', 'is_read'].includes(column)) {
    classes.push('text-center')
  }

  // 特殊样式
  if (['email', 'from_address', 'to_address', 'address'].includes(column)) {
    classes.push('text-email')
  }

  if (['created_at', 'updated_at'].includes(column)) {
    classes.push('text-time')
  }

  return classes.join(' ')
}

const initializeDatabase = async () => {
  if (confirmText.value !== 'CONFIRM_RESET_DATABASE') {
    ElMessage.warning('请输入正确的确认文本')
    return
  }

  if (!confirm('确定要初始化数据库吗？这将删除所有现有数据！')) {
    return
  }

  initLoading.value = true
  initResult.value = null

  try {
    const response = await fetch('/api/database/init', {
      method: 'POST',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ confirmText: confirmText.value })
    })

    const result = await response.json()

    if (result.success) {
      initResult.value = result.data
      confirmText.value = '' // 清空确认文本
      alert('数据库初始化成功！系统将重新验证登录状态...')

      // 重新验证登录状态
      await revalidateAuth()

      // 清空当前缓存的数据
      databaseInfo.value = null
      allTablesData.value = []
    } else {
      throw new Error(result.message || '数据库初始化失败')
    }
  } catch (error) {
    console.error('数据库初始化失败:', error)
    initResult.value = {
      steps: [`❌ 数据库初始化失败: ${(error as Error).message}`],
      success: false
    }
  } finally {
    initLoading.value = false
  }
}

// 重新验证登录状态
const revalidateAuth = async () => {
  try {
    // 重新获取用户信息来验证登录状态
    await authStore.fetchCurrentUser()

    // 如果验证失败，可能需要重新登录
    if (!authStore.isAuthenticated) {
      alert('数据库初始化完成，但登录状态已失效，请重新登录')
      window.location.href = '/login'
    } else {
      console.log('登录状态验证成功')
    }
  } catch (error) {
    console.error('重新验证登录状态失败:', error)
    alert('数据库初始化完成，但验证登录状态时出现错误，建议刷新页面')
  }
}

// 格式化时间
const formatTime = (timestamp: string) => {
  if (!timestamp) return 'N/A'
  return new Date(timestamp).toLocaleString('zh-CN')
}

// 获取表格数量
const getTableCount = (tables: any) => {
  if (!tables) return 0
  return Object.keys(tables).length
}

// 数据库统计方法
const loadDatabaseStats = async () => {
  if (!isAdmin.value) {
    ElMessage.warning('此功能需要管理员权限')
    return
  }

  dbStatsLoading.value = true
  try {
    const response = await fetch('/api/database/stats', {
      method: 'GET',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json'
      }
    })

    const result = await response.json()

    if (result.success) {
      dbStats.value = result.data
      console.log('✅ 数据库统计获取成功:', dbStats.value)
      ElMessage.success('数据库统计获取成功')
    } else {
      throw new Error(result.message || '获取数据库统计失败')
    }
  } catch (error) {
    console.error('获取数据库统计失败:', error)
    ElMessage.error('获取数据库统计失败: ' + (error as Error).message)
    dbStats.value = null
  } finally {
    dbStatsLoading.value = false
  }
}

// 测试数据库连接
const testDatabaseConnection = async () => {
  dbTestLoading.value = true
  const startTime = Date.now()

  try {
    const response = await apiService.getDatabaseInfo()
    const responseTime = Date.now() - startTime

    if (response.success) {
      dbTestResult.value = {
        success: true,
        message: '数据库连接正常',
        responseTime: responseTime,
        timestamp: new Date().toLocaleString(),
        details: {
          version: response.data.version?.version || 'Unknown',
          totalTables: response.data.tables?.length || 0
        }
      }
      console.log('🔗 数据库连接测试成功:', dbTestResult.value)
      ElMessage.success('数据库连接测试成功')
    } else {
      dbTestResult.value = {
        success: false,
        message: `连接失败: ${response.message || '未知错误'}`,
        responseTime: responseTime,
        timestamp: new Date().toLocaleString(),
        error: response.message
      }
      console.error('数据库连接测试失败:', response.message)
      ElMessage.error(`数据库连接测试失败: ${response.message || '未知错误'}`)
    }
  } catch (error) {
    const responseTime = Date.now() - startTime
    dbTestResult.value = {
      success: false,
      message: '连接超时或网络错误',
      responseTime: responseTime,
      timestamp: new Date().toLocaleString(),
      error: error instanceof Error ? error.message : '未知错误'
    }
    console.error('数据库连接测试失败:', error)
    ElMessage.error('数据库连接测试失败')
  } finally {
    dbTestLoading.value = false
  }
}

// 文件大小格式化
const formatFileSize = (bytes: number | undefined): string => {
  if (!bytes) return '0 B'
  const sizes = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(1024))
  return Math.round(bytes / Math.pow(1024, i) * 100) / 100 + ' ' + sizes[i]
}

// 注意：getCacheStats 功能已合并到 loadCacheInfo 中，已删除

// 解析缓存信息
const parseCacheInfo = (info: any) => {
  try {
    // 如果info是对象且包含cacheData，直接返回cacheData
    if (typeof info === 'object' && info !== null && info.cacheData) {
      return info.cacheData
    }

    // 如果info是字符串，按原来的方式解析
    if (typeof info === 'string') {
      const lines = info.split('\n').filter(line => line.trim())
      const parsed: Record<string, any> = {}

      lines.forEach(line => {
        const [key, ...valueParts] = line.split(':')
        if (key && valueParts.length > 0) {
          const value = valueParts.join(':').trim()
          parsed[key.trim()] = {
            size: value.length,
            created: new Date().toISOString(),
            ttl: '30min'
          }
        }
      })

      return parsed
    }

    // 如果info是对象，直接返回
    if (typeof info === 'object' && info !== null) {
      return info
    }

    return {}
  } catch (error) {
    return { 'cache_info': { size: JSON.stringify(info || '').length, created: new Date().toISOString(), ttl: 'unknown' } }
  }
}

// 缓存大小格式化
const formatCacheSize = (size: number | string): string => {
  const numSize = typeof size === 'string' ? parseInt(size) || 0 : size
  if (numSize < 1024) return numSize + ' B'
  if (numSize < 1024 * 1024) return Math.round(numSize / 1024) + ' KB'
  return Math.round(numSize / 1024 / 1024 * 100) / 100 + ' MB'
}

// 缓存时间格式化
const formatCacheTime = (time: string): string => {
  return new Date(time).toLocaleString('zh-CN')
}


// 获取缓存类型
const getCacheType = (key: string): string => {
  if (key.includes('email')) return '📧 邮件'
  if (key.includes('user')) return '👤 用户'
  if (key.includes('mailbox')) return '📮 邮箱'
  if (key.includes('admin')) return '🔧 管理'
  if (key.includes('system')) return '⚙️ 系统'
  return '📄 其他'
}

// 获取缓存状态
const getCacheStatus = (_info: any): string => {
  // 这里可以根据TTL和创建时间计算状态
  return '✅ 活跃'
}

// 获取缓存状态样式类
const getCacheStatusClass = (_info: any): string => {
  return 'status-active'
}

// 获取缓存表格列配置
const getCacheGridColumns = (): string => {
  return 'minmax(max-content, 200px) minmax(max-content, 100px) minmax(max-content, 80px) minmax(max-content, 160px) minmax(max-content, 160px) minmax(max-content, 100px) minmax(max-content, 80px) minmax(max-content, 100px) minmax(max-content, 120px)'
}

// 格式化缓存过期时间
const formatCacheExpiry = (created: string | number, ttl: string | number): string => {
  try {
    const createdTime = new Date(created)
    const ttlSeconds = typeof ttl === 'string' ? parseInt(ttl) || 0 : ttl || 0
    const expiryTime = new Date(createdTime.getTime() + ttlSeconds * 1000)
    return expiryTime.toLocaleString('zh-CN')
  } catch {
    return '未知'
  }
}

// 格式化剩余TTL
const formatRemainingTTL = (created: string | number, ttl: string | number): string => {
  try {
    const createdTime = new Date(created)
    const ttlSeconds = typeof ttl === 'string' ? parseInt(ttl) || 0 : ttl || 0
    const expiryTime = new Date(createdTime.getTime() + ttlSeconds * 1000)
    const now = new Date()
    const remainingMs = expiryTime.getTime() - now.getTime()

    if (remainingMs <= 0) return '已过期'

    const remainingSeconds = Math.floor(remainingMs / 1000)
    if (remainingSeconds < 60) return `${remainingSeconds}秒`
    if (remainingSeconds < 3600) return `${Math.floor(remainingSeconds / 60)}分钟`
    if (remainingSeconds < 86400) return `${Math.floor(remainingSeconds / 3600)}小时`
    return `${Math.floor(remainingSeconds / 86400)}天`
  } catch {
    return '未知'
  }
}

// 获取TTL样式类
const getTTLClass = (created: string | number, ttl: string | number): string => {
  try {
    const createdTime = new Date(created)
    const ttlSeconds = typeof ttl === 'string' ? parseInt(ttl) || 0 : ttl || 0
    const expiryTime = new Date(createdTime.getTime() + ttlSeconds * 1000)
    const now = new Date()
    const remainingMs = expiryTime.getTime() - now.getTime()

    if (remainingMs <= 0) return 'ttl-expired'
    if (remainingMs < 60000) return 'ttl-critical' // 小于1分钟
    if (remainingMs < 300000) return 'ttl-warning' // 小于5分钟
    return 'ttl-normal'
  } catch {
    return 'ttl-unknown'
  }
}

// 清空单个缓存
const clearSingleCache = (key: string) => {
  if (confirm(`确定要删除缓存 "${key}" 吗？`)) {
    // 尝试从cacheService删除
    cacheService.delete(key)

    // 直接从localStorage删除
    localStorage.removeItem(key)

    showCacheInfoData() // 刷新缓存信息
  }
}

// 查看缓存内容
const viewCacheContent = (key: string) => {
  // 直接从localStorage获取原始数据
  const item = localStorage.getItem(key)

  let contentStr = ''

  if (!item) {
    contentStr = '缓存内容为空或已过期'
  } else {
    try {
      const parsedItem = JSON.parse(item)
      console.log(`[viewCacheContent] 处理键: ${key}`)
      console.log(`[viewCacheContent] 解析后的数据:`, parsedItem)
      console.log(`[viewCacheContent] 数据类型:`, typeof parsedItem)

      // 如果是缓存条目格式（有value, expiry, size）
      if (parsedItem.value !== undefined && parsedItem.expiry !== undefined) {
        const content = parsedItem.value
        console.log(`[viewCacheContent] 缓存条目内容:`, content)
        console.log(`[viewCacheContent] 内容类型:`, typeof content)

        if (content === undefined || content === null) {
          contentStr = '缓存内容为空'
        } else if (typeof content === 'object' && content !== null) {
          // 如果是对象，格式化显示
          if (key.includes('system') || key.includes('config')) {
            // 特殊处理系统配置
            contentStr = formatSystemConfig(content)
          } else {
            contentStr = JSON.stringify(content, null, 2)
          }
        } else {
          contentStr = String(content)
        }
      } else {
        // 如果是普通数据格式
        if (typeof parsedItem === 'object' && parsedItem !== null) {
          if (key.includes('system') || key.includes('config')) {
            contentStr = formatSystemConfig(parsedItem)
          } else {
            contentStr = JSON.stringify(parsedItem, null, 2)
          }
        } else {
          contentStr = String(parsedItem)
        }
      }
    } catch (error) {
      console.error(`[viewCacheContent] 解析JSON失败:`, error)
      // 如果不是JSON格式，直接显示字符串
      contentStr = item
    }
  }

  // 创建模态框显示内容
  showCacheContentModal(key, contentStr)
}

// 格式化系统配置显示 - 直接返回原始JSON
const formatSystemConfig = (config: any): string => {
  console.log(`[formatSystemConfig] 输入配置:`, config)
  console.log(`[formatSystemConfig] 配置类型:`, typeof config)

  if (config === null || config === undefined) {
    return 'null'
  }

  if (typeof config === 'string') {
    return config
  }

  if (typeof config === 'object') {
    try {
      return JSON.stringify(config, null, 2)
    } catch (error: any) {
      console.error(`[formatSystemConfig] JSON序列化失败:`, error)
      return `[无法序列化的对象: ${error?.message || '未知错误'}]`
    }
  }

  return String(config)
}

// 缓存内容模态框状态
const cacheModalVisible = ref(false)
const cacheModalKey = ref('')
const cacheModalContent = ref('')

// 显示缓存内容模态框
const showCacheContentModal = (key: string, content: string) => {
  cacheModalKey.value = key
  cacheModalContent.value = content
  cacheModalVisible.value = true
}

// 关闭缓存内容模态框
const closeCacheModal = () => {
  cacheModalVisible.value = false
  cacheModalKey.value = ''
  cacheModalContent.value = ''
}

// 复制缓存内容
const copyCacheContent = async () => {
  try {
    await navigator.clipboard.writeText(cacheModalContent.value)
    ElMessage.success('已复制到剪贴板')
  } catch (err) {
    // 降级方案
    const textArea = document.createElement('textarea')
    textArea.value = cacheModalContent.value
    document.body.appendChild(textArea)
    textArea.select()
    document.execCommand('copy')
    document.body.removeChild(textArea)
    ElMessage.success('已复制到剪贴板')
  }
}


// R2 文件管理方法
const loadR2Files = async () => {
  r2Loading.value = true
  try {
    const params = new URLSearchParams()
    if (r2Prefix.value) {
      params.append('prefix', r2Prefix.value)
    }
    params.append('limit', '100')

    const response = await fetch(`/api/database/r2-files?${params.toString()}`, {
      method: 'GET',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json'
      }
    })

    const result = await response.json()

    if (result.success) {
      r2Files.value = result.data
      ElMessage.success('R2 文件列表获取成功')
    } else {
      throw new Error(result.message || '获取 R2 文件列表失败')
    }
  } catch (error) {
    console.error('获取 R2 文件列表失败:', error)
    ElMessage.error('获取 R2 文件列表失败: ' + (error as Error).message)
    r2Files.value = null
  } finally {
    r2Loading.value = false
  }
}

const refreshR2Files = () => {
  selectedR2Files.value = [] // 清空选择
  loadR2Files()
}

// 全选/取消全选
const allR2FilesSelected = computed(() => {
  return r2Files.value?.files?.length > 0 && selectedR2Files.value.length === r2Files.value.files.length
})

const toggleSelectAllR2Files = (event: Event) => {
  const checked = (event.target as HTMLInputElement).checked
  if (checked) {
    selectedR2Files.value = r2Files.value?.files?.map((f: any) => f.key) || []
  } else {
    selectedR2Files.value = []
  }
}

// 删除单个 R2 文件
const deleteR2File = async (key: string) => {
  if (!confirm(`确定要删除文件 "${key}" 吗？\n\n注意：如果是邮件文件，将同时删除对应的 meta.json 和数据库记录。`)) {
    return
  }

  await deleteR2Files([key])
}

// 批量删除 R2 文件
const deleteSelectedR2Files = async () => {
  if (selectedR2Files.value.length === 0) {
    ElMessage.warning('请先选择要删除的文件')
    return
  }

  const fileCount = selectedR2Files.value.length
  if (!confirm(`确定要删除选中的 ${fileCount} 个文件吗？\n\n注意：如果是邮件文件，将同时删除对应的 meta.json 和数据库记录。`)) {
    return
  }

  await deleteR2Files([...selectedR2Files.value])
}

// 执行删除操作
const deleteR2Files = async (keys: string[]) => {
  r2Deleting.value = true
  try {
    const response = await fetch('/api/database/r2-files', {
      method: 'DELETE',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ keys })
    })

    const result = await response.json()

    if (result.success) {
      ElMessage.success(result.message || '文件删除成功')
      // 清空选择并刷新文件列表
      selectedR2Files.value = []
      await loadR2Files()
    } else {
      throw new Error(result.message || '删除文件失败')
    }
  } catch (error) {
    console.error('删除 R2 文件失败:', error)
    ElMessage.error('删除文件失败: ' + (error as Error).message)
  } finally {
    r2Deleting.value = false
  }
}

// 格式化 R2 时间
const formatR2Time = (time: string | null): string => {
  if (!time) return '-'
  try {
    return new Date(time).toLocaleString('zh-CN')
  } catch {
    return time
  }
}


// 键盘事件处理
const handleKeydown = (event: KeyboardEvent) => {
  if (event.key === 'Escape' && cacheModalVisible.value) {
    closeCacheModal()
  }
}

onMounted(() => {
  // 初始化测试邮件收件人
  if (authStore.user?.email) {
    testEmail.value.to = authStore.user.email
  }

  // 注意：数据库信息和表数据现在都需要用户手动点击获取
  // 这样可以避免页面加载时的不必要请求

  // 添加键盘事件监听
  document.addEventListener('keydown', handleKeydown)
})

onUnmounted(() => {
  // 移除键盘事件监听
  document.removeEventListener('keydown', handleKeydown)
})
</script>

<style scoped>
.debug-page {
  padding: 20px;
  background: #f8f9fa;
  min-height: 100%;
}

.page-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 30px;
}

.page-header h1 {
  margin: 0;
  color: #2c3e50;
  font-size: 24px;
  font-weight: 600;
}

.debug-badge {
  background: #dc3545;
  color: white;
  padding: 4px 8px;
  border-radius: 12px;
  font-size: 12px;
  font-weight: 500;
}

.debug-content {
  display: flex;
  flex-direction: column;
  gap: 20px;
}

.debug-section {
  background: white;
  border-radius: 10px;
  padding: 20px;
  box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
}

.debug-section h2 {
  margin: 0 0 20px 0;
  color: #2c3e50;
  font-size: 18px;
  font-weight: 600;
  padding-bottom: 10px;
  border-bottom: 1px solid #e9ecef;
}

.debug-note {
  background: #e3f2fd;
  border: 1px solid #bbdefb;
  border-radius: 5px;
  padding: 10px;
  margin-bottom: 20px;
  color: #1565c0;
  font-size: 14px;
  line-height: 1.4;
}

.info-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
  gap: 15px;
}

.info-item {
  display: flex;
  flex-direction: column;
  gap: 5px;
}

.info-item label {
  font-weight: 500;
  color: #555;
  font-size: 14px;
}

.info-item span {
  color: #2c3e50;
  font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
  font-size: 13px;
}

/* 邮件表单样式 */
.email-form {
  max-width: 500px;
  /* 限制表单最大宽度 */
  width: 100%;
}

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
  font-family: inherit;
}

.form-control:focus {
  outline: none;
  border-color: #3498db;
  box-shadow: 0 0 0 3px rgba(52, 152, 219, 0.1);
}

.api-tests,
.cache-actions,
.db-tests {
  display: flex;
  gap: 10px;
  margin-bottom: 20px;
  flex-wrap: wrap;
}

.btn {
  padding: 8px 16px;
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

.btn-primary:hover:not(:disabled) {
  background: #2980b9;
}

.btn-secondary {
  background: #6c757d;
  color: white;
}

.btn-secondary:hover {
  background: #5a6268;
}

.btn-warning {
  background: #ffc107;
  color: #212529;
}

.btn-warning:hover {
  background: #e0a800;
}

.btn-info {
  background: #17a2b8;
  color: white;
}

.btn-info:hover {
  background: #138496;
}

.btn:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.test-result,
.cache-info {
  background: #f8f9fa;
  border-radius: 5px;
  padding: 15px;
  border: 1px solid #e9ecef;
  max-width: 600px;
  /* 限制API测试结果最大宽度 */
  width: fit-content;
  /* 根据内容调整 */
}

.test-result h3,
.cache-info h3 {
  margin: 0 0 10px 0;
  color: #2c3e50;
  font-size: 14px;
}

.test-result pre,
.cache-info pre {
  margin: 0;
  font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
  font-size: 12px;
  color: #2c3e50;
  white-space: pre-wrap;
  word-break: break-all;
}

@media (max-width: 768px) {
  .page-header {
    flex-direction: column;
    gap: 10px;
    align-items: flex-start;
  }

  .info-grid {
    grid-template-columns: 1fr;
  }

  .api-tests,
  .cache-actions,
  .db-tests {
    flex-direction: column;
  }
}

/* 数据库管理样式 */
.db-info-section,
.sql-query-section,
.db-init-section {
  margin-bottom: 30px;
  padding: 20px;
  background: #f8f9fa;
  border-radius: 8px;
  border: 1px solid #e9ecef;
}

.db-info {
  margin-top: 15px;
}

.tables-info {
  margin-top: 20px;
}

.table-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
  gap: 15px;
  margin-top: 10px;
}

.table-item {
  background: white;
  border: 1px solid #dee2e6;
  border-radius: 6px;
  padding: 12px;
}

.table-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.table-name {
  font-weight: 600;
  color: #495057;
}

.table-count {
  background: #007bff;
  color: white;
  padding: 2px 8px;
  border-radius: 12px;
  font-size: 12px;
}

.table-error {
  margin-top: 8px;
  color: #dc3545;
  font-size: 14px;
}

.sql-result,
.init-result {
  margin-top: 15px;
  padding: 15px;
  background: #f8f9fa;
  border: 1px solid #dee2e6;
  border-radius: 6px;
}

.sql-result pre {
  margin: 0;
  white-space: pre-wrap;
  word-break: break-all;
  font-size: 12px;
  max-height: 400px;
  overflow: auto;
}

.danger-zone {
  border: 2px solid #dc3545;
  border-radius: 8px;
  padding: 20px;
  background: #f8d7da;
  max-width: 600px;
  /* 限制危险操作区域最大宽度 */
  width: fit-content;
  /* 根据内容调整宽度 */
}

.danger-warning {
  color: #721c24;
  font-size: 16px;
  margin-bottom: 10px;
}

.danger-note {
  color: #721c24;
  margin-bottom: 20px;
}

.init-steps {
  max-height: 300px;
  overflow-y: auto;
}

.init-step {
  padding: 8px 12px;
  margin-bottom: 5px;
  border-radius: 4px;
  font-family: monospace;
  font-size: 14px;
  background: #f8f9fa;
  border-left: 4px solid #6c757d;
}

.init-step.success {
  background: #d4edda;
  border-left-color: #28a745;
  color: #155724;
}

.init-step.error {
  background: #f8d7da;
  border-left-color: #dc3545;
  color: #721c24;
}

/* 数据表浏览样式 */
.table-browser-section {
  margin-top: 30px;
}

/* 所有表格容器 */
.all-tables-container {
  margin-top: 20px;
}

.single-table-section {
  margin-bottom: 20px;
  border: 1px solid #e9ecef;
  border-radius: 8px;
  overflow: hidden;
}

.single-table-section:has(.empty-table) {
  margin-bottom: 8px;
}

.single-table-section:has(.empty-table-simple) {
  margin-bottom: 2px;
}

.single-table-section:has(.empty-table-with-structure) {
  margin-bottom: 12px;
}

/* 无数据表格的容器样式 */
.all-tables-container:has(.empty-table-simple) {
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.table-header-section {
  background: #f8f9fa;
  padding: 15px 20px;
  border-bottom: 1px solid #e9ecef;
}

.single-table-section:has(.empty-table) .table-header-section {
  padding: 8px 20px;
}

.table-title {
  margin: 0;
  font-size: 18px;
  color: #333;
  display: flex;
  align-items: center;
  gap: 10px;
}

.record-count {
  font-size: 14px;
  color: #666;
  font-weight: normal;
}

.table-error {
  margin-top: 10px;
  padding: 10px;
  background: #f8d7da;
  border: 1px solid #f5c6cb;
  border-radius: 4px;
  color: #721c24;
  font-size: 14px;
}

.table-actions {
  display: flex;
  align-items: center;
  gap: 15px;
  margin-bottom: 20px;
  padding: 10px;
  background: #f8f9fa;
  border-radius: 6px;
}

.table-info {
  font-size: 14px;
  color: #666;
}

.loading-state {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 20px;
  text-align: center;
  color: #666;
}

.loading-spinner {
  animation: spin 1s linear infinite;
}

@keyframes spin {
  from {
    transform: rotate(0deg);
  }

  to {
    transform: rotate(360deg);
  }
}

.error-message {
  padding: 15px;
  background: #f8d7da;
  border: 1px solid #f5c6cb;
  border-radius: 6px;
  color: #721c24;
  margin-bottom: 15px;
}

/* 简洁的Grid表格样式 */
.simple-table {
  border: 1px solid #e9ecef;
  border-radius: 8px;
  overflow: hidden;
  margin-top: 15px;
  overflow-x: auto;
  /* 添加水平滚动 */
}

.table-grid {
  display: grid;
  gap: 0;
  font-size: 14px;
  width: fit-content;
  /* 表格宽度根据内容自适应 */
  min-width: 100%;
  /* 至少占满容器宽度 */
}

.grid-header {
  background: #f8f9fa;
  padding: 12px 15px;
  font-weight: 600;
  color: #495057;
  border-bottom: 2px solid #dee2e6;
  border-right: 1px solid #dee2e6;
  display: flex;
  align-items: center;
}

.grid-header:last-child {
  border-right: none;
}

.grid-cell {
  padding: 10px 15px;
  border-bottom: 1px solid #f1f3f4;
  border-right: 1px solid #f1f3f4;
  display: flex;
  align-items: center;
  min-height: 40px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  transition: background-color 0.2s ease;
}

.grid-cell:last-child {
  border-right: none;
}

/* 斑马纹效果 */
.table-grid>.grid-cell:nth-child(n+1) {
  background: white;
}

/* 每行的背景色 - 需要根据列数计算 */
.table-grid[style*="repeat(6,"]>.grid-cell:nth-child(6n+7),
.table-grid[style*="repeat(6,"]>.grid-cell:nth-child(6n+8),
.table-grid[style*="repeat(6,"]>.grid-cell:nth-child(6n+9),
.table-grid[style*="repeat(6,"]>.grid-cell:nth-child(6n+10),
.table-grid[style*="repeat(6,"]>.grid-cell:nth-child(6n+11),
.table-grid[style*="repeat(6,"]>.grid-cell:nth-child(6n+12) {
  background: #f8f9fa;
}

.table-grid[style*="repeat(4,"]>.grid-cell:nth-child(4n+5),
.table-grid[style*="repeat(4,"]>.grid-cell:nth-child(4n+6),
.table-grid[style*="repeat(4,"]>.grid-cell:nth-child(4n+7),
.table-grid[style*="repeat(4,"]>.grid-cell:nth-child(4n+8) {
  background: #f8f9fa;
}

/* 悬停效果 */
.grid-cell:hover {
  background: #e3f2fd !important;
  cursor: default;
}

/* 列样式类 */
.text-center {
  justify-content: center !important;
  text-align: center;
}

.text-email {
  font-family: 'Monaco', 'Consolas', monospace;
  font-size: 13px;
  color: #0066cc;
}

.text-time {
  font-size: 13px;
  color: #666;
  font-variant-numeric: tabular-nums;
}

.empty-table {
  padding: 6px 20px;
  background: #f8f9fa;
  border-top: 1px solid #e9ecef;
  min-height: auto;
}

.empty-table-content {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 6px;
  color: #6c757d;
  font-size: 12px;
  font-style: italic;
  padding: 2px 0;
}

.empty-icon {
  font-size: 14px;
  opacity: 0.7;
}

.empty-text {
  font-weight: 500;
}

/* 简化的无数据表格样式 */
.empty-table-simple {
  padding: 8px 20px;
  background: #f8f9fa;
  border: 1px solid #e9ecef;
  border-radius: 4px;
  margin-bottom: 2px;
  display: flex;
  align-items: center;
  min-height: 36px;
  transition: background-color 0.2s ease;
}

.empty-table-simple:hover {
  background: #e9ecef;
}

.empty-table-simple .empty-table-content {
  display: flex;
  align-items: center;
  gap: 10px;
  color: #6c757d;
  font-size: 13px;
  font-style: italic;
  padding: 0;
  width: 100%;
}

.empty-table-simple .empty-icon {
  font-size: 16px;
  opacity: 0.7;
  flex-shrink: 0;
}

.empty-table-simple .empty-text {
  font-weight: 500;
  color: #495057;
  flex: 1;
}

/* 带结构的无数据表格样式 */
.empty-table-with-structure {
  border: 1px solid #e9ecef;
  border-radius: 8px;
  overflow: hidden;
}

.empty-table-structure {
  background: #f8f9fa;
}

.empty-table-structure .table-grid {
  border-bottom: 1px solid #e9ecef;
}

.empty-data-message {
  padding: 12px 20px;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  color: #6c757d;
  font-size: 13px;
  font-style: italic;
  background: #ffffff;
}

.empty-data-message .empty-icon {
  font-size: 14px;
  opacity: 0.7;
}

.empty-data-message .empty-text {
  font-weight: 500;
}

/* 数据库动作按钮 */
.db-action-buttons {
  display: flex;
  gap: 10px;
  margin-bottom: 20px;
}

.db-action-buttons .btn {
  display: flex;
  align-items: center;
  gap: 5px;
}

/* 数据库信息布局 */
.db-info-layout {
  display: grid;
  gap: 30px;
  grid-template-columns: 1fr 3fr;
  align-items: flex-start;
  flex-wrap: wrap;
}

/* 数据库信息概览卡片 */
.db-overview-cards {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 20px;
  flex: 0 0 auto;
  min-width: 440px;
  /* 确保至少能放下2列卡片 */
}

.db-overview-card {
  border-radius: 12px;
  padding: 20px;
  color: #2c3e50;
  box-shadow: 0 4px 15px rgba(102, 126, 234, 0.3);
  transition: transform 0.2s ease, box-shadow 0.2s ease;
}

.db-overview-card:hover {
  transform: translateY(-2px);
  box-shadow: 0 6px 20px rgba(102, 126, 234, 0.4);
}

.db-overview-card .card-icon {
  font-size: 32px;
  margin-bottom: 10px;
  display: block;
}

.db-overview-card .card-content h4 {
  margin: 0 0 8px 0;
  font-size: 14px;
  opacity: 0.9;
  font-weight: 500;
}

.db-overview-card .card-content p {
  margin: 0;
  font-size: 24px;
  font-weight: 700;
  line-height: 1.2;
}

/* 表格状态详情 */
.tables-detail {
  flex: 1 1 auto;
  min-width: 400px;
}

.tables-detail h4 {
  margin: 0 0 15px 0;
  color: #495057;
}

.tables-status-list {
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.table-status-item {
  background: white;
  border: 1px solid #e9ecef;
  border-radius: 8px;
  padding: 15px;
  transition: border-color 0.2s ease, box-shadow 0.2s ease;
}

.table-status-item:hover {
  border-color: #007bff;
  box-shadow: 0 2px 8px rgba(0, 123, 255, 0.1);
}

.table-status-item.has-error {
  border-color: #dc3545;
  background: #fff5f5;
}

.table-status-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.table-status-left {
  display: flex;
  align-items: center;
  gap: 10px;
}

.table-icon {
  font-size: 18px;
}

.table-name {
  font-weight: 600;
  color: #333;
  font-family: 'Monaco', 'Consolas', monospace;
}

.table-status-badge {
  padding: 2px 8px;
  border-radius: 12px;
  font-size: 12px;
  font-weight: 500;
}

.table-status-badge.success {
  background: #d4edda;
  color: #155724;
}

.table-status-badge.error {
  background: #f8d7da;
  color: #721c24;
}

.table-status-right {
  color: #666;
  font-size: 14px;
}

.record-count {
  font-weight: 500;
}

.table-error-detail {
  margin-top: 10px;
  padding: 8px 12px;
  background: #f8d7da;
  border: 1px solid #f5c6cb;
  border-radius: 4px;
  color: #721c24;
  font-size: 13px;
}

/* 数据库统计样式 */
.db-stats {
  margin-top: 30px;
  padding: 20px;
  background: #f8f9fa;
  border-radius: 8px;
  border: 1px solid #e9ecef;
}

.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
  gap: 20px;
  margin-top: 15px;
}

.stat-card {
  background: white;
  border-radius: 8px;
  padding: 20px;
  border: 1px solid #e9ecef;
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
}

.stat-title {
  font-size: 16px;
  font-weight: 600;
  margin-bottom: 15px;
  color: #495057;
  display: flex;
  align-items: center;
  gap: 8px;
}

/* .stat-content 暂时不需要特殊样式 */

.stat-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 8px;
  padding: 8px 0;
  border-bottom: 1px solid #f1f3f4;
}

.stat-label {
  font-size: 14px;
  color: #666;
}

.stat-value {
  font-size: 16px;
  font-weight: 600;
  color: #333;
}

/* 缓存详细信息样式 */
.cache-details {
  background: #f8f9fa;
  border-radius: 6px;
  padding: 15px;
  margin-top: 10px;
}

.cache-item {
  margin-bottom: 15px;
  padding: 10px;
  background: white;
}

/* 缓存表格网格样式 */
.cache-table-grid {
  display: grid;
  gap: 0;
  font-size: 13px;
  border: 1px solid #e9ecef;
  border-radius: 6px;
  overflow: hidden;
  margin-top: 10px;
}

.cache-grid-header {
  background: #f8f9fa;
  padding: 12px 8px;
  font-weight: 600;
  color: #495057;
  border-bottom: 1px solid #e9ecef;
  border-right: 1px solid #e9ecef;
  text-align: center;
  font-size: 12px;
}

.cache-grid-header:last-child {
  border-right: none;
}

.cache-grid-cell {
  padding: 10px 8px;
  border-bottom: 1px solid #f1f3f4;
  border-right: 1px solid #f1f3f4;
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: 40px;
}

.cache-grid-cell:last-child {
  border-right: none;
}

/* 缓存键样式 */
.cache-key-cell {
  justify-content: flex-start;
  text-align: left;
}

.cache-key-text {
  font-family: 'Courier New', monospace;
  font-size: 11px;
  color: #495057;
  word-break: break-all;
}

/* 缓存类型样式 */
.cache-type-badge {
  background: #e3f2fd;
  color: #1976d2;
  padding: 2px 6px;
  border-radius: 4px;
  font-size: 11px;
  font-weight: 500;
}

/* 缓存大小样式 */
.cache-size-value {
  font-family: 'Courier New', monospace;
  font-size: 12px;
  color: #666;
}

/* 缓存时间样式 */
.cache-time-value,
.cache-expiry-value {
  font-size: 11px;
  color: #666;
  font-family: 'Courier New', monospace;
}

/* TTL样式 */
.cache-ttl-value {
  font-size: 11px;
  font-weight: 500;
  padding: 2px 6px;
  border-radius: 4px;
}

.ttl-normal {
  background: #d4edda;
  color: #155724;
}

.ttl-warning {
  background: #fff3cd;
  color: #856404;
}

.ttl-critical {
  background: #f8d7da;
  color: #721c24;
}

.ttl-expired {
  background: #f5c6cb;
  color: #721c24;
}

.ttl-unknown {
  background: #e2e3e5;
  color: #383d41;
}

/* 访问次数样式 */
.cache-access-value {
  font-family: 'Courier New', monospace;
  font-size: 12px;
  color: #666;
}

/* 缓存状态样式 */
.cache-status-badge {
  padding: 2px 6px;
  border-radius: 4px;
  font-size: 11px;
  font-weight: 500;
}

.status-active {
  background: #d4edda;
  color: #155724;
}

/* 操作按钮样式 */
.cache-actions-cell {
  gap: 4px;
}

.cache-actions-cell .btn {
  padding: 2px 6px;
  font-size: 10px;
  min-width: auto;
}

/* 缓存内容模态框样式 */
.cache-content-modal {
  position: fixed;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  z-index: 9999;
}

.modal-overlay {
  position: absolute;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  background: rgba(0, 0, 0, 0.5);
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 20px;
}

.modal-content {
  background: white;
  border-radius: 8px;
  box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
  max-width: 80%;
  max-height: 80%;
  width: 600px;
  display: flex;
  flex-direction: column;
}

.modal-header {
  padding: 20px 20px 0 20px;
  display: flex;
  justify-content: space-between;
  align-items: center;
  border-bottom: 1px solid #e9ecef;
  margin-bottom: 20px;
}

.modal-header h3 {
  margin: 0;
  color: #333;
  font-size: 18px;
}

.modal-close {
  background: none;
  border: none;
  font-size: 24px;
  cursor: pointer;
  color: #666;
  padding: 0;
  width: 30px;
  height: 30px;
  display: flex;
  align-items: center;
  justify-content: center;
  border-radius: 4px;
}

.modal-close:hover {
  background: #f8f9fa;
  color: #333;
}

.modal-body {
  flex: 1;
  padding: 0 20px;
  overflow: auto;
}

.cache-content-text {
  background: #f8f9fa;
  border: 1px solid #e9ecef;
  border-radius: 4px;
  padding: 15px;
  font-family: 'Courier New', monospace;
  font-size: 12px;
  line-height: 1.4;
  color: #333;
  white-space: pre-wrap;
  word-break: break-word;
  max-height: 400px;
  overflow: auto;
}

.modal-footer {
  padding: 20px;
  border-top: 1px solid #e9ecef;
  display: flex;
  gap: 10px;
  justify-content: flex-end;
}

.cache-key {
  font-weight: 600;
  color: #333;
  margin-bottom: 5px;
  font-family: 'Courier New', monospace;
}

.cache-meta {
  display: flex;
  gap: 15px;
  font-size: 12px;
  color: #666;
}

.cache-size,
.cache-time,
.cache-ttl {
  background: #e9ecef;
  padding: 2px 6px;
  border-radius: 3px;
}

/* 缓存表格样式 */
.cache-table-container {
  overflow-x: auto;
  border: 1px solid #e9ecef;
  border-radius: 8px;
  margin-top: 15px;
}

.cache-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 14px;
  background: white;
}

.cache-table th {
  background: #f8f9fa;
  padding: 12px 10px;
  text-align: left;
  font-weight: 600;
  color: #495057;
  border-bottom: 2px solid #dee2e6;
  white-space: nowrap;
}

.cache-table td {
  padding: 10px;
  border-bottom: 1px solid #f1f3f4;
  vertical-align: middle;
}

.cache-row:hover {
  background: #f8f9fa;
}

.cache-key-cell {
  font-family: 'Monaco', 'Consolas', monospace;
  font-size: 13px;
  color: #0066cc;
  max-width: 200px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.cache-type-cell {
  font-size: 13px;
  font-weight: 500;
}

.cache-size-cell {
  font-family: 'Monaco', 'Consolas', monospace;
  font-size: 13px;
  color: #666;
}

.cache-time-cell {
  font-size: 12px;
  color: #666;
  white-space: nowrap;
}

.cache-ttl-cell {
  font-size: 13px;
  color: #333;
}

.cache-status-cell {
  text-align: center;
}

.cache-status-badge {
  padding: 4px 8px;
  border-radius: 12px;
  font-size: 12px;
  font-weight: 500;
}

.cache-status-badge.status-active {
  background: #d4edda;
  color: #155724;
}

.cache-status-badge.status-expired {
  background: #f8d7da;
  color: #721c24;
}

.cache-status-badge.status-warning {
  background: #fff3cd;
  color: #856404;
}

/* 数据库操作列表样式 */
.db-operations-list {
  display: flex;
  flex-direction: column;
  gap: 10px;
  margin-top: 20px;
}

.operation-item {
  border: 1px solid #e9ecef;
  border-radius: 8px;
  background: white;
  overflow: hidden;
  transition: border-color 0.2s ease, box-shadow 0.2s ease;
}

.operation-item:hover {
  border-color: #007bff;
  box-shadow: 0 2px 8px rgba(0, 123, 255, 0.1);
}

.operation-item.danger {
  border-color: #dc3545;
}

.operation-item.danger:hover {
  border-color: #c82333;
  box-shadow: 0 2px 8px rgba(220, 53, 69, 0.15);
}

.operation-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 15px 20px;
  cursor: pointer;
  background: #f8f9fa;
  user-select: none;
}

.operation-header:hover {
  background: #e9ecef;
}

.operation-item.danger .operation-header {
  background: #fff5f5;
}

.operation-item.danger .operation-header:hover {
  background: #ffe6e6;
}

.operation-left {
  display: flex;
  align-items: center;
  gap: 12px;
  flex: 1;
}

.operation-icon {
  font-size: 20px;
  width: 24px;
  text-align: center;
}

.operation-title {
  font-weight: 600;
  color: #333;
  font-size: 16px;
}

.operation-description {
  color: #666;
  font-size: 14px;
  margin-left: 8px;
}

.operation-right {
  display: flex;
  align-items: center;
  gap: 10px;
}

.operation-badge {
  padding: 2px 8px;
  border-radius: 12px;
  font-size: 12px;
  font-weight: 500;
  background: #e9ecef;
  color: #495057;
}

.operation-badge.danger {
  background: #f8d7da;
  color: #721c24;
}

.expand-icon {
  font-size: 12px;
  transition: transform 0.2s ease;
  color: #666;
}

.expand-icon.expanded {
  transform: rotate(180deg);
}

/* 数据库连接测试样式 */
.test-result {
  margin-top: 1rem;
  padding: 1rem;
  border-radius: 8px;
  border: 1px solid #e0e0e0;
  max-width: 600px;
  /* 限制最大宽度 */
  width: fit-content;
  /* 根据内容调整宽度 */
}

.test-result.success {
  border-color: #4caf50;
  background-color: #f1f8e9;
}

.test-result.error {
  border-color: #f44336;
  background-color: #ffebee;
}

.test-status {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  margin-bottom: 1rem;
  font-weight: 600;
}

.status-icon {
  font-size: 1.2rem;
}

.test-details {
  display: grid;
  gap: 0.5rem;
}

.detail-item {
  display: flex;
  justify-content: space-between;
  padding: 0.25rem 0;
}

.detail-item label {
  font-weight: 500;
  color: #666;
}

.error-text {
  color: #f44336;
  font-family: monospace;
}

/* 数据库统计样式 */
.db-stats {
  margin-top: 1rem;
  max-width: 900px;
  /* 限制统计容器最大宽度 */
}

.stats-overview {
  margin-bottom: 1.5rem;
}

.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 200px));
  /* 限制最大列宽 */
  gap: 1rem;
  margin-top: 1rem;
  justify-content: start;
  /* 左对齐而不是拉伸 */
}

.stat-card {
  background: #f8f9fa;
  border: 1px solid #e9ecef;
  border-radius: 8px;
  padding: 1rem;
  text-align: center;
}

.stat-value {
  font-size: 1.5rem;
  font-weight: bold;
  color: #2196f3;
  margin-bottom: 0.25rem;
}

.stat-label {
  font-size: 0.875rem;
  color: #666;
}

.stats-details {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 350px));
  /* 限制最大列宽 */
  gap: 1.5rem;
  justify-content: start;
  /* 左对齐而不是拉伸 */
}

.stats-section h5 {
  margin: 0 0 1rem 0;
  padding-bottom: 0.5rem;
  border-bottom: 2px solid #e9ecef;
  color: #333;
}

.stats-list {
  display: grid;
  gap: 0.5rem;
}

.stats-item {
  display: flex;
  justify-content: space-between;
  padding: 0.5rem;
  background: #f8f9fa;
  border-radius: 4px;
}

.stats-item span:first-child {
  color: #666;
}

.stats-item span:last-child {
  font-weight: 600;
  color: #333;
}

/* 节标题样式 */
.section-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 1rem;
}

.section-header h2 {
  margin: 0;
}

/* 数据库操作按钮行 */
.db-actions {
  display: flex;
  gap: 8px;
  margin: 1rem 0;
  flex-wrap: wrap;
}

.db-actions .btn {
  border-radius: 4px;
  font-size: 0.875rem;
  padding: 8px 12px;
}

.db-actions .btn.active {
  box-shadow: 0 0 0 2px rgba(0, 123, 255, 0.25);
}

.db-actions .loading-text {
  color: #666;
}

/* 操作提示文本 */
.operation-hint {
  margin: 1rem 0;
  padding: 12px;
  background: #f8f9fa;
  border-left: 4px solid #007bff;
  color: #666;
  font-size: 0.875rem;
  border-radius: 0 4px 4px 0;
}

/* 紧凑的表格样式 */
.vue-table-container {
  margin-top: 1rem;
  border: 1px solid #dee2e6;
  border-radius: 4px;
  overflow: hidden;
  max-width: 400px;
  /* 限制表格最大宽度 */
}

.vue-table {
  width: auto;
  /* 改为自动宽度，不占用100% */
  min-width: 400px;
  /* 设置最小宽度保证可读性 */
  border-collapse: collapse;
  font-size: 0.875rem;
}

.vue-table th {
  background: #f8f9fa;
  padding: 8px 12px;
  text-align: left;
  font-weight: 600;
  border-bottom: 1px solid #dee2e6;
}

.vue-table td {
  padding: 8px 12px;
  border-bottom: 1px solid #f0f0f0;
}

.vue-table .table-icon-col {
  width: 40px;
  text-align: center;
}

.vue-table .table-name-col {
  min-width: 120px;
}

.vue-table .table-records-col {
  width: 80px;
  text-align: right;
}

.vue-table .table-status-col {
  width: 80px;
  text-align: center;
}

.vue-table .table-row:hover {
  background: #f8f9fa;
}

.vue-table .error-row {
  background: #fff5f5;
}

.vue-table .table-name-cell {
  font-family: monospace;
  font-weight: 500;
}

.vue-table .status-badge {
  padding: 2px 8px;
  border-radius: 12px;
  font-size: 0.75rem;
  font-weight: 500;
}

.vue-table .status-badge.success {
  background: #d4edda;
  color: #155724;
}

.vue-table .status-badge.error {
  background: #f8d7da;
  color: #721c24;
}

.operation-content {
  padding: 20px;
  border-top: 1px solid #e9ecef;
  background: white;
}

.btn-sm {
  padding: 4px 12px;
  font-size: 13px;
  border-radius: 4px;
}

/* 缓存空状态样式 */
.cache-empty-state {
  text-align: center;
  padding: 40px 20px;
  background: #f8f9fa;
  border: 2px dashed #dee2e6;
  border-radius: 8px;
  margin-top: 15px;
}

.empty-cache-icon {
  font-size: 48px;
  margin-bottom: 15px;
  opacity: 0.6;
}

.empty-cache-text {
  font-size: 18px;
  font-weight: 600;
  color: #6c757d;
  margin-bottom: 8px;
}

.empty-cache-hint {
  font-size: 14px;
  color: #868e96;
  line-height: 1.4;
}

/* R2 文件管理样式 */
.r2-actions {
  display: flex;
  gap: 10px;
  margin-bottom: 20px;
  align-items: center;
  flex-wrap: wrap;
}

.r2-filter {
  flex: 1;
  min-width: 200px;
  max-width: 400px;
}

.r2-filter .form-control {
  width: 100%;
}

.r2-files-container {
  margin-top: 20px;
}

.r2-files-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 15px;
  padding-bottom: 10px;
  border-bottom: 1px solid #e9ecef;
}

.r2-files-header h3 {
  margin: 0;
  color: #2c3e50;
  font-size: 16px;
}

.r2-files-info {
  display: flex;
  gap: 15px;
  align-items: center;
  font-size: 14px;
  color: #666;
}

.truncated-warning {
  color: #ff9800;
  font-weight: 500;
}

.r2-files-table-container {
  border: 1px solid #e9ecef;
  border-radius: 8px;
  overflow: hidden;
  overflow-x: auto;
}

.r2-files-table-grid {
  display: grid;
  grid-template-columns: 40px 2fr 120px 160px 120px;
  gap: 0;
  font-size: 13px;
  min-width: 660px;
}

.r2-grid-header {
  background: #f8f9fa;
  padding: 12px 15px;
  font-weight: 600;
  color: #495057;
  border-bottom: 2px solid #dee2e6;
  border-right: 1px solid #e9ecef;
  text-align: left;
}

.r2-grid-header:last-child {
  border-right: none;
}

.r2-grid-cell {
  padding: 10px 15px;
  border-bottom: 1px solid #f1f3f4;
  border-right: 1px solid #f1f3f4;
  display: flex;
  align-items: center;
  min-height: 40px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.r2-grid-cell:last-child {
  border-right: none;
}

/* 斑马纹效果 */
.r2-files-table-grid>.r2-grid-cell:nth-child(5n+1),
.r2-files-table-grid>.r2-grid-cell:nth-child(5n+2),
.r2-files-table-grid>.r2-grid-cell:nth-child(5n+3),
.r2-files-table-grid>.r2-grid-cell:nth-child(5n+4),
.r2-files-table-grid>.r2-grid-cell:nth-child(5n+5) {
  background: white;
}

.r2-files-table-grid>.r2-grid-cell:nth-child(10n+6),
.r2-files-table-grid>.r2-grid-cell:nth-child(10n+7),
.r2-files-table-grid>.r2-grid-cell:nth-child(10n+8),
.r2-files-table-grid>.r2-grid-cell:nth-child(10n+9),
.r2-files-table-grid>.r2-grid-cell:nth-child(10n+10) {
  background: #f8f9fa;
}

/* 悬停效果 */
.r2-grid-cell:hover {
  background: #e3f2fd !important;
  cursor: default;
}

.r2-key-cell {
  font-family: 'Monaco', 'Consolas', monospace;
  font-size: 12px;
  color: #0066cc;
}

.r2-key-text {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.r2-size-cell {
  font-family: 'Monaco', 'Consolas', monospace;
  font-size: 12px;
  color: #666;
  justify-content: flex-end;
}

.r2-time-cell {
  font-size: 12px;
  color: #666;
  font-variant-numeric: tabular-nums;
}

.r2-type-cell {
  font-size: 12px;
  color: #666;
}

.r2-etag-cell {
  font-family: 'Monaco', 'Consolas', monospace;
  font-size: 11px;
  color: #999;
}

.r2-action-cell {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 4px;
}

.r2-action-cell .btn {
  padding: 4px 8px;
  font-size: 12px;
}

.btn-outline-danger {
  background: transparent;
  border: 1px solid #dc3545;
  color: #dc3545;
}

.btn-outline-danger:hover:not(:disabled) {
  background: #dc3545;
  color: white;
}

.btn-outline-danger:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.r2-checkbox-header,
.r2-checkbox-cell {
  display: flex;
  align-items: center;
  justify-content: center;
}

.r2-checkbox-header input[type="checkbox"],
.r2-checkbox-cell input[type="checkbox"] {
  cursor: pointer;
  width: 18px;
  height: 18px;
}

.r2-actions {
  display: flex;
  gap: 10px;
  margin-bottom: 20px;
  align-items: center;
  flex-wrap: wrap;
}

.btn-danger {
  background: #dc3545;
  color: white;
  border: none;
}

.btn-danger:hover:not(:disabled) {
  background: #c82333;
}

.btn-danger:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.r2-meta-cell {
  font-size: 12px;
  color: #666;
}

.r2-meta-value {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  cursor: help;
}

.r2-empty-state {
  text-align: center;
  padding: 40px 20px;
  background: #f8f9fa;
  border: 2px dashed #dee2e6;
  border-radius: 8px;
  margin-top: 15px;
}

.empty-r2-icon {
  font-size: 48px;
  margin-bottom: 15px;
  opacity: 0.6;
}

.empty-r2-text {
  font-size: 18px;
  font-weight: 600;
  color: #6c757d;
  margin-bottom: 8px;
}

.empty-r2-hint {
  font-size: 14px;
  color: #868e96;
  line-height: 1.4;
}

.r2-loading-state {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 20px;
  text-align: center;
  color: #666;
  justify-content: center;
}

/* 浏览器缓存管理样式 */
.cache-management {
  margin-top: 15px;
}

.cache-stats {
  background: #f8f9fa;
  border-radius: 8px;
  padding: 15px;
  margin-bottom: 15px;
}

.cache-stats h3 {
  margin: 0 0 15px 0;
  font-size: 16px;
  color: #495057;
}

.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 10px;
}

.stat-item {
  display: flex;
  justify-content: space-between;
  padding: 8px 12px;
  background: white;
  border-radius: 4px;
  border: 1px solid #dee2e6;
}

.stat-item label {
  font-weight: 600;
  color: #6c757d;
}

.stat-item span {
  color: #495057;
}

.cache-actions {
  display: flex;
  gap: 10px;
  flex-wrap: wrap;
  margin-bottom: 15px;
}

.cache-result {
  padding: 15px;
  border-radius: 8px;
  margin-top: 15px;
}

.cache-result.success {
  background: #d4edda;
  border: 1px solid #c3e6cb;
  color: #155724;
}

.cache-result.error {
  background: #f8d7da;
  border: 1px solid #f5c6cb;
  color: #721c24;
}

.cache-result h3 {
  margin: 0 0 10px 0;
  font-size: 16px;
}

.cache-result ul {
  margin: 10px 0 0 20px;
  padding: 0;
}

.cache-result li {
  margin: 5px 0;
}

/* 缓存清理信息样式 */
.cache-clear-info {
  padding: 20px;
  background: #f8f9fa;
  border-radius: 8px;
  border: 1px solid #e9ecef;
}

.cache-clear-info p {
  margin: 0 0 15px 0;
  font-weight: 500;
  color: #495057;
}

.cache-clear-info ul {
  margin: 0 0 20px 20px;
  padding: 0;
  list-style: disc;
}

.cache-clear-info li {
  margin: 8px 0;
  color: #666;
  line-height: 1.6;
}

.cache-clear-info .btn {
  margin-top: 10px;
}
</style>
