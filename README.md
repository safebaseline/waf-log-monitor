# WAF Log Monitor · 云 WAF 攻击/访问日志本地监控

零依赖的 Node.js 单文件服务：轮询 websaas 云 WAF 的攻击日志与访问日志接口，全量存入本地 SQLite，并提供实时仪表盘——趋势图表、多维筛选、全文搜索、IP 一键拉黑与黑名单管理。

> 适用对象：已拥有 websaas.cn 云 WAF 账号、希望把平台网页上的日志能力搬到本地的用户——更快的检索、更长的留存、可自定义的统计视图。

## 特性

**采集**
- 自动发现账号下全部防护站点：每轮从站点接口取 `domainPort` 依次查询；也可用 `sites.txt` 手动指定
- 攻击日志 + 访问日志双通道；访问日志游标式增量采集（reqId 去重、缺口统计与页面告警）
- 断档自动补采：Token 失效恢复 / 服务停机重启后，自动回补最长 2 小时（可配）的断档数据
- 新站点首次纳入自动回拉近 24 小时历史

**展示（五视图）**
- 攻击总览 / 访问总览：今日统计卡片、24 小时趋势图（连续时间轴，空时段补零）、TOP3 站点分站点趋势、TOP 站点 / 源 IP / 攻击类型 / 状态码榜
- 攻击日志 / 访问日志：站点·等级·动作·状态码·时间范围·关键字多维筛选（选项数量随范围联动），分页支持手输页码跳转
- IP 黑名单：实时同步平台「访问控制」封禁规则，支持搜索与删除
- 浅色 / 深色主题；SSE 实时推送新日志，菜单徽章显示今日攻击数 / 访问量 / 规则数

**处置**
- 从攻击日志一键拉黑攻击源：IPv4 / IPv6 / CIDR 网段、多 IP 批量、1/7/30/365 天有效期与备注
- 黑名单列表支持关键字搜索与按 uuid 删除（官方 `acl/batch` 接口，删除前有确认弹窗）

**可靠性**
- Token 自动换发：每 10 分钟调用账号接口续期，新 Token 先经接口验证再采纳；另有 60 秒保活探测兜底
- 瞬时网络错误（断连 / 超时）自动重试；轮询 / 筛选互不阻塞
- 关键字搜索基于 SQLite FTS5 全文索引，百万行级毫秒~秒级响应

## 快速开始

环境要求：Node.js ≥ 22.5（使用内置 `node:sqlite`，无需 `npm install`）

1. 克隆仓库，在 `config.json` 的 `token` 字段填入你的 Bearer Token（获取方式见下文）
2. 启动：`node server.js`；Windows 下也可双击 `start.bat`（前台）或 `start-background.vbs`（无窗口后台）
3. 打开 <http://127.0.0.1:8686> —— 首次启动自动回拉近 24 小时日志

> 示例配置中的站点域名（`campus1.example.edu` 等）为占位符，请替换为你账号下的真实站点，或清空 `sites.txt` 让服务自动发现。

### 获取 Token

1. 浏览器登录 websaas.cn 控制台
2. F12 → 网络（Network）→ 任选一个请求 → 复制请求头 `Authorization: Bearer` 后面的整串
3. 粘贴到监控页面右上角「更新 Token」，或直接写入 `config.json`

## Token 机制

平台 Token 为固定 30 分钟寿命的 JWT，本项目通过三层机制尽量免手动维护：

| 机制 | 说明 |
|---|---|
| 自动换发（主） | 每 `tokenRefreshMinutes`（默认 10）分钟调用 `/q/api/account/token` 换发新 Token；换出的新 Token 先经站点接口验证可用才采纳保存。服务持续运行即可无限续期 |
| 保活探测（兜底） | 每 60 秒一次轻量请求，Token 意外失效 1 分钟内页面红条告警；响应头若下发新 Token 也会自动采纳 |
| 手动更新（最后手段） | 服务停机超过 30 分钟会导致换发链断裂（旧 Token 过期后无法换新），需手动更新一次，之后恢复自动续期 |

已知陷阱：`/q/saas-threat-report/api/threat/pub/token` 换出的是威胁报表模块专用 Token（sub=`cloud-waf-threat`），不能用于日志接口——验证门会自动忽略它。

## 配置

### config.json

| 字段 | 默认 | 说明 |
|---|---|---|
| token | 空 | Bearer Token（自动换发会持续更新此文件，请勿外传） |
| autoSites | true | 每轮轮询前调用站点接口，取返回包 `domainPort` 依次查询 |
| sites | [] | 站点列表（sites.txt 存在时被手动列表覆盖；同步失败时兜底） |
| intervalMinutes | 10 | 轮询间隔（分钟）；页面顶栏可实时切换 30 秒 / 1 / 5 / 10 分钟 |
| lookbackMinutes | 30 | 常规回看窗口（大于轮询间隔，防止日志延迟漏采） |
| catchupHours | 2 | 断档补采上限（小时） |
| initialHours | 24 | 新站点首次纳入时的深度回拉时长 |
| pageSize / maxPagesPerSite | 100 / 20 | 攻击日志单站分页参数 |
| visitLogs | true | 是否采集访问日志 |
| visitPageSize / visitMaxPagesPerSite | 100 / 30 | 访问日志单站分页参数（游标追平即停；补采轮自动 ×5） |
| visitOverlapSeconds | 90 | 访问日志游标回退重叠量（容忍平台入库延迟） |
| maxLogs / visitMaxLogs | 0 / 0 | 攻击 / 访问日志容量上限；**0 = 全量存储**，正数 = 按条数裁剪最旧 |
| tokenRefreshUrl / tokenRefreshMinutes | 空 / 10 | Token 换发接口与周期；仓库示例已预填账号换发接口 |
| tokenKeepAlive / keepAliveSeconds | true / 60 | 保活探测开关与周期 |
| port | 8686 | 本地控制台端口（仅监听 127.0.0.1） |
| apiUrl / sitesApiUrl / visitApiUrl / acl*Url | 平台地址 | 各平台接口，一般无需修改 |

### sites.txt（站点列表，可选）

- 每行一个站点：`域名` 或 `域名:端口`（如 `www.example.edu:443`），行内空格后可写备注
- `#` 开头为注释；删除 / 注释某行即停止采集，新增一行即纳入
- 保存后点页面「立即刷新」立即生效，或等下一轮轮询
- **清空或删除本文件 → 恢复自动发现模式**（每轮从站点接口取全量站点）

### visit-exclude.txt（访问日志采集例外，可选）

- 不采集某些站点的**访问日志**（攻击日志照常）：每行一个站点，`域名` 整站排除或 `域名:端口` 精确排除
- 修改后下一轮生效；清空 / 删除文件恢复全量采集；已入库数据保留

## 数据存储

日志存于本地 SQLite 数据库 `data/waflogs.db`（Node 内置 `node:sqlite`，WAL 模式，运行中可用 DB Browser 等工具只读查看）：

| 表 | 用途 |
|---|---|
| `logs` / `visit_logs` | 攻击 / 访问日志明细：结构化字段 + 完整原始 JSON（`raw` 列），按需建组合索引 |
| `visit_hourly` | 访问量小时聚合（站点 × 小时），趋势图与总览统计的数据源，不随明细裁剪丢失 |
| `visit_fts` | FTS5 全文索引（URL / UA / Referer / IP / 站点 / 地理），关键字搜索的数据源 |
| `visit_cursors` / `known_sites` / `meta` | 采集游标、已回拉站点、断档锚点等运行状态 |

容量策略：`maxLogs` / `visitMaxLogs` 默认 **0 = 全量存储**。访问日志在大流量站点（千条/分钟级）下约 2.5GB/天，磁盘紧张时设为正数即可按条数裁剪最旧记录。

## 控制台页面

| 菜单 | 内容 |
|---|---|
| 📊 攻击总览 | 今日攻击 / 阻断 / 中高危卡片、24 小时攻击趋势、TOP3 受攻击站点分站点趋势、TOP 站点 / 源 IP / 攻击类型 |
| 📋 攻击日志 | 多维筛选 + 明细表 + 完整详情（含原始事件 rawEvent）+ 一键拉黑 |
| 📊 访问总览 | 今日访问量 / 活跃站点 / 爬虫占比、24 小时访问趋势、TOP3 站点分站点趋势、TOP 站点 / 状态码 / 方法 / 源 IP |
| 🌐 访问日志 | 多维筛选 + 明细表（含 Referer、UA、耗时、流量、爬虫标记）+ 完整详情 |
| 🚫 黑名单 | 平台封禁规则实时列表（类型 / 到期 / 剩余天数 / 操作人）、搜索、删除 |

顶栏提供：实时连接状态、Token 状态与换发进度、保活时间、站点数、**轮询间隔下拉（30 秒 / 1 / 5 / 10 分钟，即改即生效）**、手动刷新、Token 更新、主题切换。

## 本地 API

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | /api/state | 服务 / Token / 站点 / 轮询状态 |
| GET | /api/logs | 攻击日志查询（site / level / action / status / hours / kw / page / size） |
| GET | /api/log?id= | 攻击日志单条详情（含原始事件） |
| GET | /api/stats?hours= | 攻击统计聚合（含 TOP3 站点趋势） |
| GET | /api/facets?hours= | 攻击日志筛选选项聚合 |
| GET | /api/visitlogs | 访问日志查询（site / status / method / hours / kw / page / size） |
| GET | /api/visitlog?id= | 访问日志单条详情 |
| GET | /api/visitstats?hours= | 访问统计聚合（小时聚合表） |
| GET | /api/visitfacets?hours= | 访问日志筛选选项聚合 |
| GET | /api/stream | SSE 事件流（poll / token / keepalive / interval） |
| GET / POST | /api/token | 读取 / 更新 Bearer Token |
| POST | /api/interval | `{"minutes": 0.5\|1\|5\|10}` 设置轮询间隔 |
| POST | /api/poll | 手动触发一轮采集（1 分钟限频） |
| POST | /api/blacklist | `{"ip", "expireDays", "desc"}` 添加封禁（IPv4/IPv6/CIDR，多 IP 支持换行分隔） |
| GET | /api/blacklist/list | 平台封禁规则列表 |
| POST | /api/blacklist/remove | `{"uuids": [...]}` 删除封禁规则 |

## 项目结构

```
├── server.js               # 服务端（单文件，零第三方依赖）
├── config.json             # 配置（Token 由自动换发持续更新）
├── sites.txt               # 站点列表（可选手动模式；删除则自动发现）
├── visit-exclude.txt       # 访问日志采集例外
├── public/index.html       # 仪表盘页面（无构建、无外部依赖）
├── data/waflogs.db         # SQLite 数据库（首次运行自动创建）
├── start.bat               # Windows 前台启动
├── start-background.vbs    # Windows 无窗口后台启动
├── stop-service.bat        # 停止后台服务
└── .backfill.js            # 历史数据回填工具（按需使用）
```

## 安全说明

- 服务仅监听 `127.0.0.1`，不对外网暴露
- 所有出站请求经 SSRF 校验：仅允许 http/https 且目标为公网地址，解析到内网 / 环回地址即拒绝
- 黑名单提交对 IP 格式做严格校验（`net.isIP` + CIDR 前缀长度检查）
- `config.json` 中的 Token 由自动换发持续更新——**切勿把含真实 Token 的版本提交到仓库或分享给他人**

## 常见问题

**30 秒轮询档为什么实际不止 30 秒？**
单轮需要遍历全部站点，实际节奏 = 单轮耗时 + 间隔；内置防重入保护，不会并发叠加请求。

**访问日志页能查多久之前的数据？**
明细筛选范围最大「近 2 天」（保证响应速度）；更长时间维度的统计请看访问总览（走小时聚合表，不受明细裁剪影响）。`visitMaxLogs` 全量存储（0）时明细本身也是完整的。

**想补拉某段历史数据？**
编辑 `.backfill.js` 顶部的 `T0` / `T1` 时间窗后运行 `node .backfill.js`：按天分窗拉取（平台访问日志接口单次查询跨度限 24 小时）、限速 2.5 请求/秒、断点续跑、与主服务共用同一套去重键，可安全重复执行。

**黑名单删除失败？**
确认用的是规则列表里的 uuid（删除走官方 `acl/batch` 接口）；平台控制台的「访问控制」页始终可作为兜底。
