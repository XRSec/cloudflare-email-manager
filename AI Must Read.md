我认为这些仓库对我的代码很有帮助：

- 当然你也可以索引一些其他的仓库
- https://github.com/vwh/temp-mail
- https://github.com/XRSec/feishu-bot-webhook-action
- https://github.com/webbertakken/email-worker
- https://github.com/dreamhunter2333/cloudflare_temp_email

我想做的效果是：

1. 通过 Cloudflare 电子邮件路由接收电子邮件。
2. 将电子邮件数据存储在 Cloudflare D1 数据库中。
3. **附件支持**：在 Cloudflare R2 中存储最大 50MB 的电子邮件附件。
4. 为电子邮件和附件提供全面的 API 端点。
5. 自动清理旧的电子邮件和附件。可自定义时间
6. 支持多种文件类型，包括文档、图像和档案。
7. 配置信息使用 cloudflare 的 机密
8. 前后端合并，静态文件都存在 workers

管理员：

1. 有一个静态网页可以配置转发列表
    1. 比如 来自 xxx@xxx.xxx 的邮件包含关键字的邮件 转发到 xxx 的 webhook
    2. webhook 支持验签
2. 有一个页面负责创建，管理用户
3. 管理员有是否开放自由注册的权限
4. 管理员有一个页面可以配置 什么邮箱来的邮件转发到什么地址，同时可以过滤邮件发送者，邮件类型，邮件内容是否包含指定文本 ，可自由想象，UI 页面怎么写，最好再配置下验证邮件是否在 cloudflare 已验证，有一个按钮允许管理员向用户发送 用户信息，用户的 EMAIL PREFIX  EMAIL PASSWORD

普通用户：

1. 用户首次使用 需要填写 EMAIL PREFIX 和 EMAIL PASSWORD 才能看邮件，不支持越权
2. 用户支持修改 webhook，签名，密码，后端根据内容（不为空）进行更新(一个页面完成)，杜绝 sql 注入，修改完成提示内容，刷新，密码不返回前端，密码默认为空

综合：

1. 有一个页面支持查看 ， 过滤，删除邮件，邮件附件，支持过滤，时间，文件大小，从数据库读取，管理员允许查看所有邮件，用户只能查看自己的邮件
2. EMAIL PREFIX 使用随机数据，不可自定义，但是固定
3. webhook 支持 钉钉 和 飞书，支持后期新增其他平台，webhook 发送相关可以参考：https://github.com/webbertakken/email-worker
4. 我认为当前仓库的 UI 过于复杂，同样的 代码逻辑也很复杂，只适用于借鉴，不使用于我的项目，我认为 https://github.com/vwh/temp-mail 的 UI 够精简
5. 我们的邮箱域名不止一个,需要有自动切换的功能,如果能自动匹配那就更好了,比如收到邮件,匹配邮箱域

你需要做的是：

1. 代码需要中文注释
2. 参考当前仓库，魔改代码，实现我要的效果
3. 完善(总结/清理) README.md
4. README 中应该介绍 dev init clean deploy db:init db:init:dev 的作用
5. 更新清理完善 [schema.sql](db/schema.sql) 的内容
6. 