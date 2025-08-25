/**
 * API端点扩展 - 邮件和附件的完整API
 * 继续添加到new_worker.ts中
 */

// JWT中间件
const jwtMiddleware = jwt({
  secret: (c) => c.env.JWT_SECRET,
});

/**
 * 需要认证的API路由
 */
app.use('/api/protected/*', jwtMiddleware);

/**
 * 获取用户邮件列表
 */
app.get('/api/protected/emails', async (c) => {
  try {
    const payload = c.get('jwtPayload') as any;
    const { page = 1, limit = 20, sender, keyword, start_date, end_date } = c.req.query();
    
    const userId = payload.user_id;
    const userType = payload.user_type;
    
    let whereClause = '';
    let bindings: any[] = [];
    
    // 普通用户只能查看自己的邮件，管理员可以查看所有邮件
    if (userType !== 'admin') {
      whereClause = 'WHERE e.user_id = ?';
      bindings.push(userId);
    } else {
      whereClause = 'WHERE 1=1';
    }
    
    // 添加过滤条件
    if (sender) {
      whereClause += ` AND e.sender_email LIKE ?`;
      bindings.push(`%${sender}%`);
    }
    
    if (keyword) {
      whereClause += ` AND (e.subject LIKE ? OR e.text_content LIKE ?)`;
      bindings.push(`%${keyword}%`, `%${keyword}%`);
    }
    
    if (start_date) {
      whereClause += ` AND e.received_at >= ?`;
      bindings.push(start_date);
    }
    
    if (end_date) {
      whereClause += ` AND e.received_at <= ?`;
      bindings.push(end_date);
    }
    
    // 计算偏移量
    const offset = (parseInt(page as string) - 1) * parseInt(limit as string);
    
    // 查询邮件列表
    const emailsQuery = `
      SELECT 
        e.id, e.message_id, e.sender_email, e.recipient_email,
        e.subject, e.text_content, e.has_attachments, e.received_at,
        u.email_prefix,
        COUNT(a.id) as attachment_count
      FROM emails e
      LEFT JOIN users u ON e.user_id = u.id
      LEFT JOIN attachments a ON e.id = a.email_id
      ${whereClause}
      GROUP BY e.id
      ORDER BY e.received_at DESC
      LIMIT ? OFFSET ?
    `;
    
    const emails = await c.env.DB.prepare(emailsQuery)
      .bind(...bindings, parseInt(limit as string), offset)
      .all();
    
    // 查询总数
    const countQuery = `
      SELECT COUNT(*) as total
      FROM emails e
      LEFT JOIN users u ON e.user_id = u.id
      ${whereClause}
    `;
    
    const countResult = await c.env.DB.prepare(countQuery)
      .bind(...bindings.slice(0, -2)) // 移除limit和offset参数
      .first();
    
    return c.json({
      success: true,
      data: {
        emails: emails.results,
        total: countResult?.total || 0,
        page: parseInt(page as string),
        limit: parseInt(limit as string)
      }
    });
    
  } catch (error) {
    console.error('获取邮件列表失败:', error);
    throw new HTTPException(500, { message: '获取邮件列表失败' });
  }
});

/**
 * 获取邮件详情
 */
app.get('/api/protected/emails/:id', async (c) => {
  try {
    const payload = c.get('jwtPayload') as any;
    const emailId = c.req.param('id');
    
    const userId = payload.user_id;
    const userType = payload.user_type;
    
    let whereClause = 'WHERE e.id = ?';
    let bindings = [emailId];
    
    // 普通用户只能查看自己的邮件
    if (userType !== 'admin') {
      whereClause += ' AND e.user_id = ?';
      bindings.push(userId);
    }
    
    // 查询邮件详情
    const email = await c.env.DB.prepare(`
      SELECT 
        e.*, u.email_prefix
      FROM emails e
      LEFT JOIN users u ON e.user_id = u.id
      ${whereClause}
    `).bind(...bindings).first();
    
    if (!email) {
      throw new HTTPException(404, { message: '邮件不存在或无权限访问' });
    }
    
    // 查询附件列表
    const attachments = await c.env.DB.prepare(`
      SELECT id, filename, content_type, size_bytes, created_at
      FROM attachments
      WHERE email_id = ?
    `).bind(emailId).all();
    
    return c.json({
      success: true,
      data: {
        email: email,
        attachments: attachments.results
      }
    });
    
  } catch (error) {
    console.error('获取邮件详情失败:', error);
    if (error instanceof HTTPException) {
      throw error;
    }
    throw new HTTPException(500, { message: '获取邮件详情失败' });
  }
});

/**
 * 删除邮件
 */
app.delete('/api/protected/emails/:id', async (c) => {
  try {
    const payload = c.get('jwtPayload') as any;
    const emailId = c.req.param('id');
    
    const userId = payload.user_id;
    const userType = payload.user_type;
    
    let whereClause = 'WHERE id = ?';
    let bindings = [emailId];
    
    // 普通用户只能删除自己的邮件
    if (userType !== 'admin') {
      whereClause += ' AND user_id = ?';
      bindings.push(userId);
    }
    
    // 先查询要删除的邮件的附件
    const attachments = await c.env.DB.prepare(`
      SELECT r2_key FROM attachments a
      JOIN emails e ON a.email_id = e.id
      ${whereClause.replace('WHERE id = ?', 'WHERE e.id = ?')}
    `).bind(...bindings).all();
    
    // 删除R2中的附件
    for (const attachment of attachments.results) {
      try {
        await c.env.R2.delete(attachment.r2_key as string);
      } catch (error) {
        console.warn('删除R2附件失败:', attachment.r2_key, error);
      }
    }
    
    // 删除邮件记录（附件记录会因为外键约束自动删除）
    const result = await c.env.DB.prepare(`
      DELETE FROM emails ${whereClause}
    `).bind(...bindings).run();
    
    if (result.changes === 0) {
      throw new HTTPException(404, { message: '邮件不存在或无权限删除' });
    }
    
    return c.json({
      success: true,
      message: '邮件删除成功'
    });
    
  } catch (error) {
    console.error('删除邮件失败:', error);
    if (error instanceof HTTPException) {
      throw error;
    }
    throw new HTTPException(500, { message: '删除邮件失败' });
  }
});

/**
 * 下载附件
 */
app.get('/api/protected/attachments/:id', async (c) => {
  try {
    const payload = c.get('jwtPayload') as any;
    const attachmentId = c.req.param('id');
    
    const userId = payload.user_id;
    const userType = payload.user_type;
    
    let whereClause = 'WHERE a.id = ?';
    let bindings = [attachmentId];
    
    // 普通用户只能下载自己邮件的附件
    if (userType !== 'admin') {
      whereClause += ' AND e.user_id = ?';
      bindings.push(userId);
    }
    
    // 查询附件信息
    const attachment = await c.env.DB.prepare(`
      SELECT a.*, e.user_id
      FROM attachments a
      JOIN emails e ON a.email_id = e.id
      ${whereClause}
    `).bind(...bindings).first();
    
    if (!attachment) {
      throw new HTTPException(404, { message: '附件不存在或无权限访问' });
    }
    
    // 从R2获取附件内容
    const object = await c.env.R2.get(attachment.r2_key as string);
    if (!object) {
      throw new HTTPException(404, { message: '附件文件不存在' });
    }
    
    const content = await object.arrayBuffer();
    
    return new Response(content, {
      headers: {
        'Content-Type': attachment.content_type as string || 'application/octet-stream',
        'Content-Disposition': `attachment; filename="${attachment.filename}"`,
        'Content-Length': content.byteLength.toString()
      }
    });
    
  } catch (error) {
    console.error('下载附件失败:', error);
    if (error instanceof HTTPException) {
      throw error;
    }
    throw new HTTPException(500, { message: '下载附件失败' });
  }
});

/**
 * 用户更新个人设置
 */
app.put('/api/protected/settings', async (c) => {
  try {
    const payload = c.get('jwtPayload') as any;
    const { webhook_url, webhook_secret, email_password } = await c.req.json();
    
    const userId = payload.user_id;
    
    // 构建更新字段
    const updateFields: string[] = [];
    const bindings: any[] = [];
    
    if (webhook_url !== undefined && webhook_url !== null) {
      updateFields.push('webhook_url = ?');
      bindings.push(webhook_url || null);
    }
    
    if (webhook_secret !== undefined && webhook_secret !== null) {
      updateFields.push('webhook_secret = ?');
      bindings.push(webhook_secret || null);
    }
    
    if (email_password && email_password.length >= 6) {
      const hashedPassword = await hashPassword(email_password);
      updateFields.push('email_password = ?');
      bindings.push(hashedPassword);
    }
    
    if (updateFields.length === 0) {
      throw new HTTPException(400, { message: '没有有效的更新字段' });
    }
    
    updateFields.push('updated_at = datetime(\'now\')');
    bindings.push(userId);
    
    // 执行更新
    await c.env.DB.prepare(`
      UPDATE users 
      SET ${updateFields.join(', ')}
      WHERE id = ?
    `).bind(...bindings).run();
    
    return c.json({
      success: true,
      message: '设置更新成功'
    });
    
  } catch (error) {
    console.error('更新用户设置失败:', error);
    if (error instanceof HTTPException) {
      throw error;
    }
    throw new HTTPException(500, { message: '更新设置失败' });
  }
});

/**
 * 获取用户信息
 */
app.get('/api/protected/user', async (c) => {
  try {
    const payload = c.get('jwtPayload') as any;
    const userId = payload.user_id;
    
    const user = await c.env.DB.prepare(`
      SELECT id, email_prefix, user_type, webhook_url, created_at
      FROM users
      WHERE id = ?
    `).bind(userId).first();
    
    if (!user) {
      throw new HTTPException(404, { message: '用户不存在' });
    }
    
    return c.json({
      success: true,
      data: {
        user: {
          ...user,
          email_address: `${user.email_prefix}@${c.env.DOMAIN}`,
          // 不返回密码和webhook_secret
          webhook_secret: user.webhook_secret ? '******' : null
        }
      }
    });
    
  } catch (error) {
    console.error('获取用户信息失败:', error);
    if (error instanceof HTTPException) {
      throw error;
    }
    throw new HTTPException(500, { message: '获取用户信息失败' });
  }
});

// ============= 管理员API =============

/**
 * 管理员中间件
 */
const adminMiddleware = async (c: any, next: () => Promise<void>) => {
  const payload = c.get('jwtPayload') as any;
  if (payload.user_type !== 'admin') {
    throw new HTTPException(403, { message: '需要管理员权限' });
  }
  await next();
};

app.use('/api/admin/*', jwtMiddleware, adminMiddleware);

/**
 * 获取所有用户列表（管理员）
 */
app.get('/api/admin/users', async (c) => {
  try {
    const { page = 1, limit = 20, search } = c.req.query();
    
    let whereClause = 'WHERE 1=1';
    let bindings: any[] = [];
    
    if (search) {
      whereClause += ' AND email_prefix LIKE ?';
      bindings.push(`%${search}%`);
    }
    
    const offset = (parseInt(page as string) - 1) * parseInt(limit as string);
    
    // 查询用户列表
    const users = await c.env.DB.prepare(`
      SELECT 
        id, email_prefix, user_type, webhook_url, created_at,
        (SELECT COUNT(*) FROM emails WHERE user_id = users.id) as email_count
      FROM users
      ${whereClause}
      ORDER BY created_at DESC
      LIMIT ? OFFSET ?
    `).bind(...bindings, parseInt(limit as string), offset).all();
    
    // 查询总数
    const countResult = await c.env.DB.prepare(`
      SELECT COUNT(*) as total FROM users ${whereClause}
    `).bind(...bindings.slice(0, -2)).first();
    
    return c.json({
      success: true,
      data: {
        users: users.results.map((user: any) => ({
          ...user,
          email_address: `${user.email_prefix}@${c.env.DOMAIN}`,
          // 不返回敏感信息
          webhook_secret: user.webhook_secret ? '******' : null
        })),
        total: countResult?.total || 0,
        page: parseInt(page as string),
        limit: parseInt(limit as string)
      }
    });
    
  } catch (error) {
    console.error('获取用户列表失败:', error);
    throw new HTTPException(500, { message: '获取用户列表失败' });
  }
});

/**
 * 创建用户（管理员）
 */
app.post('/api/admin/users', async (c) => {
  try {
    const { email_prefix, email_password, user_type = 'user' } = await c.req.json();
    
    if (!email_prefix || !email_password) {
      throw new HTTPException(400, { message: '邮件前缀和密码不能为空' });
    }
    
    if (email_password.length < 6) {
      throw new HTTPException(400, { message: '密码长度至少6位' });
    }
    
    // 检查前缀是否已存在
    const existingUser = await findUserByPrefix(c.env.DB, email_prefix);
    if (existingUser) {
      throw new HTTPException(409, { message: '邮件前缀已存在' });
    }
    
    // 创建用户
    const hashedPassword = await hashPassword(email_password);
    const result = await c.env.DB.prepare(`
      INSERT INTO users (email_prefix, email_password, user_type)
      VALUES (?, ?, ?)
    `).bind(email_prefix, hashedPassword, user_type).run();
    
    return c.json({
      success: true,
      data: {
        user_id: result.meta.last_row_id,
        email_address: `${email_prefix}@${c.env.DOMAIN}`
      }
    });
    
  } catch (error) {
    console.error('创建用户失败:', error);
    if (error instanceof HTTPException) {
      throw error;
    }
    throw new HTTPException(500, { message: '创建用户失败' });
  }
});

/**
 * 删除用户（管理员）
 */
app.delete('/api/admin/users/:id', async (c) => {
  try {
    const userId = c.req.param('id');
    
    // 先删除用户相关的R2附件
    const attachments = await c.env.DB.prepare(`
      SELECT a.r2_key 
      FROM attachments a
      JOIN emails e ON a.email_id = e.id
      WHERE e.user_id = ?
    `).bind(userId).all();
    
    for (const attachment of attachments.results) {
      try {
        await c.env.R2.delete(attachment.r2_key as string);
      } catch (error) {
        console.warn('删除R2附件失败:', attachment.r2_key, error);
      }
    }
    
    // 删除用户（邮件和附件会因为外键约束自动删除）
    const result = await c.env.DB.prepare(`
      DELETE FROM users WHERE id = ?
    `).bind(userId).run();
    
    if (result.changes === 0) {
      throw new HTTPException(404, { message: '用户不存在' });
    }
    
    return c.json({
      success: true,
      message: '用户删除成功'
    });
    
  } catch (error) {
    console.error('删除用户失败:', error);
    if (error instanceof HTTPException) {
      throw error;
    }
    throw new HTTPException(500, { message: '删除用户失败' });
  }
});

/**
 * 获取转发规则列表（管理员）
 */
app.get('/api/admin/forward-rules', async (c) => {
  try {
    const rules = await c.env.DB.prepare(`
      SELECT * FROM forward_rules ORDER BY created_at DESC
    `).all();
    
    return c.json({
      success: true,
      data: {
        rules: rules.results
      }
    });
    
  } catch (error) {
    console.error('获取转发规则失败:', error);
    throw new HTTPException(500, { message: '获取转发规则失败' });
  }
});

/**
 * 创建转发规则（管理员）
 */
app.post('/api/admin/forward-rules', async (c) => {
  try {
    const {
      rule_name,
      sender_filter,
      keyword_filter,
      recipient_filter,
      webhook_url,
      webhook_secret,
      webhook_type = 'custom',
      enabled = 1
    } = await c.req.json();
    
    if (!rule_name || !webhook_url) {
      throw new HTTPException(400, { message: '规则名称和webhook地址不能为空' });
    }
    
    const result = await c.env.DB.prepare(`
      INSERT INTO forward_rules (
        rule_name, sender_filter, keyword_filter, recipient_filter,
        webhook_url, webhook_secret, webhook_type, enabled
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      rule_name, sender_filter, keyword_filter, recipient_filter,
      webhook_url, webhook_secret, webhook_type, enabled
    ).run();
    
    return c.json({
      success: true,
      data: {
        rule_id: result.meta.last_row_id
      }
    });
    
  } catch (error) {
    console.error('创建转发规则失败:', error);
    if (error instanceof HTTPException) {
      throw error;
    }
    throw new HTTPException(500, { message: '创建转发规则失败' });
  }
});

/**
 * 更新转发规则（管理员）
 */
app.put('/api/admin/forward-rules/:id', async (c) => {
  try {
    const ruleId = c.req.param('id');
    const updateData = await c.req.json();
    
    // 构建更新字段
    const allowedFields = [
      'rule_name', 'sender_filter', 'keyword_filter', 'recipient_filter',
      'webhook_url', 'webhook_secret', 'webhook_type', 'enabled'
    ];
    
    const updateFields: string[] = [];
    const bindings: any[] = [];
    
    for (const field of allowedFields) {
      if (updateData[field] !== undefined) {
        updateFields.push(`${field} = ?`);
        bindings.push(updateData[field]);
      }
    }
    
    if (updateFields.length === 0) {
      throw new HTTPException(400, { message: '没有有效的更新字段' });
    }
    
    updateFields.push('updated_at = datetime(\'now\')');
    bindings.push(ruleId);
    
    const result = await c.env.DB.prepare(`
      UPDATE forward_rules 
      SET ${updateFields.join(', ')}
      WHERE id = ?
    `).bind(...bindings).run();
    
    if (result.changes === 0) {
      throw new HTTPException(404, { message: '转发规则不存在' });
    }
    
    return c.json({
      success: true,
      message: '转发规则更新成功'
    });
    
  } catch (error) {
    console.error('更新转发规则失败:', error);
    if (error instanceof HTTPException) {
      throw error;
    }
    throw new HTTPException(500, { message: '更新转发规则失败' });
  }
});

/**
 * 删除转发规则（管理员）
 */
app.delete('/api/admin/forward-rules/:id', async (c) => {
  try {
    const ruleId = c.req.param('id');
    
    const result = await c.env.DB.prepare(`
      DELETE FROM forward_rules WHERE id = ?
    `).bind(ruleId).run();
    
    if (result.changes === 0) {
      throw new HTTPException(404, { message: '转发规则不存在' });
    }
    
    return c.json({
      success: true,
      message: '转发规则删除成功'
    });
    
  } catch (error) {
    console.error('删除转发规则失败:', error);
    if (error instanceof HTTPException) {
      throw error;
    }
    throw new HTTPException(500, { message: '删除转发规则失败' });
  }
});

/**
 * 获取系统设置（管理员）
 */
app.get('/api/admin/settings', async (c) => {
  try {
    const settings = await c.env.DB.prepare(`
      SELECT * FROM system_settings ORDER BY key
    `).all();
    
    return c.json({
      success: true,
      data: {
        settings: settings.results
      }
    });
    
  } catch (error) {
    console.error('获取系统设置失败:', error);
    throw new HTTPException(500, { message: '获取系统设置失败' });
  }
});

/**
 * 更新系统设置（管理员）
 */
app.put('/api/admin/settings', async (c) => {
  try {
    const { settings } = await c.req.json();
    
    if (!Array.isArray(settings)) {
      throw new HTTPException(400, { message: '设置格式错误' });
    }
    
    // 批量更新设置
    for (const setting of settings) {
      await c.env.DB.prepare(`
        INSERT OR REPLACE INTO system_settings (key, value, updated_at)
        VALUES (?, ?, datetime('now'))
      `).bind(setting.key, setting.value).run();
    }
    
    return c.json({
      success: true,
      message: '系统设置更新成功'
    });
    
  } catch (error) {
    console.error('更新系统设置失败:', error);
    if (error instanceof HTTPException) {
      throw error;
    }
    throw new HTTPException(500, { message: '更新系统设置失败' });
  }
});

/**
 * 向用户发送信息（管理员）
 */
app.post('/api/admin/send-user-info/:userId', async (c) => {
  try {
    const userId = c.req.param('userId');
    
    // 获取用户信息
    const user = await c.env.DB.prepare(`
      SELECT email_prefix, email_password, user_type
      FROM users WHERE id = ?
    `).bind(userId).first();
    
    if (!user) {
      throw new HTTPException(404, { message: '用户不存在' });
    }
    
    // 这里可以实现发送邮件或其他通知方式
    // 暂时返回用户信息供管理员查看
    return c.json({
      success: true,
      data: {
        email_prefix: user.email_prefix,
        email_address: `${user.email_prefix}@${c.env.DOMAIN}`,
        // 注意：实际生产环境中不应该返回明文密码
        message: '用户信息已准备就绪，请通过安全渠道发送给用户'
      }
    });
    
  } catch (error) {
    console.error('发送用户信息失败:', error);
    if (error instanceof HTTPException) {
      throw error;
    }
    throw new HTTPException(500, { message: '发送用户信息失败' });
  }
});

/**
 * 获取统计信息（管理员）
 */
app.get('/api/admin/stats', async (c) => {
  try {
    // 用户统计
    const userStats = await c.env.DB.prepare(`
      SELECT 
        COUNT(*) as total_users,
        COUNT(CASE WHEN user_type = 'admin' THEN 1 END) as admin_users,
        COUNT(CASE WHEN user_type = 'user' THEN 1 END) as regular_users
      FROM users
    `).first();
    
    // 邮件统计
    const emailStats = await c.env.DB.prepare(`
      SELECT 
        COUNT(*) as total_emails,
        COUNT(CASE WHEN has_attachments = 1 THEN 1 END) as emails_with_attachments,
        COUNT(CASE WHEN received_at >= date('now', '-7 days') THEN 1 END) as emails_last_7_days
      FROM emails
    `).first();
    
    // 附件统计
    const attachmentStats = await c.env.DB.prepare(`
      SELECT 
        COUNT(*) as total_attachments,
        SUM(size_bytes) as total_size_bytes
      FROM attachments
    `).first();
    
    return c.json({
      success: true,
      data: {
        users: userStats,
        emails: emailStats,
        attachments: attachmentStats
      }
    });
    
  } catch (error) {
    console.error('获取统计信息失败:', error);
    throw new HTTPException(500, { message: '获取统计信息失败' });
  }
});