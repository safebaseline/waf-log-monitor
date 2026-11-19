# WAF 攻击日志本地实时监控

爬取 www.websaas.cn 云 WAF 的攻击日志接口，每 10 分钟按站点轮询，在本地网页实时展示。

## 快速开始

1. 双击 `start.bat`（或命令行运行 `node server.js`）
2. 浏览器自动打开 http://127.0.0.1:8686
3. 首次启动自动回拉近 24 小时日志，之后每 10 分钟自动增量更新

## Token 自动换发（已实现无人值守）

平台 Token 为固定 30 分钟寿命的 JWT。本服务每 `tokenRefreshMinutes`（默认 10）分钟调用 `tokenRefreshUrl`（`/q/api/account/token`）换发新 Token，**换得的新 Token 先经站点接口验证可用后才采纳保存**——只要服务持续运行，Token 每 10 分钟顺延一次，永不过期，无需手动更新。

- **断档自动补采**：每轮成功采集的时刻持久化在 `meta` 表；Token 失效恢复、服务停机重启后，轮询窗口自动扩大为「断档时长 + 5 分钟」（下限 30 分钟，上限 `catchupHours` 默认 2 小时），攻击/访问日志一并回补断档期数据，补采轮会放宽访问日志单站页数上限（×5），并在日志中记录补采窗口
- 页面「更新 Token」弹窗顶部显示自动换发状态（次数、最近结果）
- 注意事项：
  - `/q/saas-threat-report/api/threat/pub/token` 换出的是威胁报表模块专用 Token（sub=cloud-waf-threat），**不能**用于日志接口，验证门会自动忽略它
  - 若本服务停机超过 30 分钟，换发链断裂，需手动更新一次 Token（此后又可长期自动续期）
  - 换发接口失效（如旧 Token 已过期）时状态会显示失败原因并弹出页面红条

## Token 保活（辅助）

`tokenKeepAlive: true`（默认开启）时，服务端每 60 秒再发一次轻量请求作为兜底探测：Token 意外失效时 1 分钟内即可发现并在页面告警；若平台通过响应头下发新 Token 也会自动采纳。

## Token 过期后怎么办

Token 有效期约数小时。过期后页面顶部会变红提示，此时：

1. 浏览器登录 www.websaas.cn，打开「攻击日志」页面
2. F12 → 网络(Network) → 任选一个 `cloud-waf` 请求 → 请求头 `Authorization: Bearer xxx`
3. 复制 Bearer 后面的整串，粘贴到本页面右上角「更新 Token」弹窗中保存，立即恢复轮询

也可直接编辑 `config.json` 的 `token` 字段后重启。

## 站点配置文件（sites.txt）

采集哪些站点由本地文件 `sites.txt` 手动配置，随时可改、无需重启：

- 每行一个站点：`域名` 或 `域名:端口`（如 `www.campus1.example.edu:443`、`oa.campus1.example.edu:9090`），行内空格后可写备注
- `#` 开头为注释；删除/注释某行即停止采集，新增一行即纳入（新站点自动回拉近 24 小时历史）
- 保存后点页面右上角「立即刷新」立即生效，或等下一轮自动轮询（10 分钟）
- **清空或删除 sites.txt → 恢复自动同步账号全部站点**（每 60 分钟刷新一次站点列表）
- 页面顶栏「站点」徽章会显示当前数量与来源（手动/自动）

## 访问日志采集例外（visit-exclude.txt）

不采集某些站点的**访问日志**（攻击日志照常），在 `visit-exclude.txt` 每行写一个站点：

- `域名:端口` 精确排除该查询键；`域名` 整站排除（带/不带端口的变体一并排除）
- 修改后下一轮轮询或点「立即刷新」生效；清空/删除文件恢复全量采集
- 已入库的历史数据保留，仍可在页面筛选查看；页面「访问日志」页底部会显示当前排除名单

## 本地数据库

日志存储在本地 SQLite 数据库 `data/waflogs.db`（Node 内置 `node:sqlite`，无需安装任何依赖）：

- `logs` 表：攻击日志明细（结构化字段 + 完整原始 JSON），`at`/`host`/`level` 建有索引，筛选与统计均走 SQL 聚合
- `known_sites` 表：已完成深度回拉的站点记录
- WAL 模式写入，运行中可安全用其他工具（如 `sqlite3`、DB Browser for SQLite）打开查看
- 容量策略：`maxLogs` / `visitMaxLogs` 为 **0 = 全量存储不裁剪**（当前配置）；设为正数则按条数上限裁剪最旧记录
- 由旧版 store.json 首次启动时自动迁移，原文件保留为 `data/store.json.bak`

## 配置说明（config.json）

| 字段 | 默认 | 说明 |
|---|---|---|
| apiUrl | attackLogQueryTotal | WAF 日志查询接口 |
| sitesApiUrl | searchSiteByDomain1 | 账号站点列表接口（自动采集全部站点） |
| visitApiUrl | visitLogQueryTotal | 访问日志查询接口 |
| visitLogs / visitMaxPagesPerSite | true / 3 | 是否采集访问日志 / 每轮每站采样页数上限 |
| token | - | Bearer Token（自动换发会持续更新） |
| tokenRefreshUrl / tokenRefreshMinutes | /q/api/account/token / 10 | 每 10 分钟自动换发 Token（新 Token 先验证后采纳） |
| tokenKeepAlive / keepAliveSeconds | true / 60 | 每分钟保活探测（兜底告警） |
| sites | 10 个 campus1.example.edu 站点 | 站点列表（自动同步后会被全量覆盖，作为同步失败时的兜底） |
| autoSites | true | 每轮轮询前自动调用站点接口，取返回包 domainPort 依次查询攻击日志 |
| intervalMinutes | 10 | 轮询间隔（分钟，页面顶栏可切换） |
| lookbackMinutes / catchupHours | 30 / 2 | 常规回看窗口 / 断档补采上限（Token 失效恢复后最多回拉时长） |
| lookbackMinutes | 30 | 每次轮询回看窗口（大于间隔，防止日志延迟漏采） |
| initialHours | 24 | 新站点首次纳入时的深度回拉小时数 |
| pageSize / maxPagesPerSite | 100 / 20 | 单站点单次轮询的分页抓取上限 |
| maxLogs / visitMaxLogs | 0 | 攻击/访问日志容量上限；**0 = 全量存储**，正数 = 按条数裁剪最旧 |
| port | 8686 | 本地控制台端口 |

## 文件结构

```
server.js           服务端（零依赖，Node ≥ 22.5，建议 24+）
config.json         配置（含 Token，请勿外传）
sites.txt           采集站点列表（手动可编辑；删除则自动同步全账号）
public/index.html   控制台页面
data/waflogs.db     SQLite 日志数据库（WAL 模式）
data/store.json.bak 旧版 JSON 存储备份（已迁移）
start.bat           Windows 一键启动
```

## 功能

- 自动采集账号下全部站点（searchSiteByDomain1），**每轮轮询前重新获取** domainPort 列表并依次查询
- 五个页面：攻击总览（趋势图/TOP 榜）、攻击日志、**访问总览**（访问量趋势图/请求 TOP 站点/状态码分布/爬虫占比）、访问日志（明细）、**IP 黑名单**（实时规则列表与管理）
- 访问日志为**游标式增量采集**：每站点记录采集进度（visit_cursors），每轮从上次位置 + 90 秒重叠继续翻页直到追平（reqId 作去重主键，平台原生唯一 ID）；页数硬上限 `visitMaxPagesPerSite`（默认 30）。页面底部实时显示上一轮缺口，>0 会红色告警并提示处置方法
- 对账工具：`node .audit-gap.js` 可随时抽查平台接口与本地库同窗口条数差异
- 顶栏「⏱ 轮询」下拉可直接切换间隔：30 秒 / 1 分钟 / 5 分钟 / 10 分钟，保存即生效并写入 config.json（多标签页会同步）
- 注意：站点较多时单轮轮询本身需 20~40 秒，30 秒档的实际节奏为「轮询耗时 + 30 秒」，不会并发叠加
- 每轮自动轮询全部站点，SSE 实时推送新日志（新行高亮，菜单徽章显示今日攻击/访问数）
- 总览：今日攻击/阻断/中高危统计、按小时趋势图、TOP 攻击类型/源 IP/等级
- 日志页：站点/等级/动作/时间范围/关键字筛选（选项随数据与范围联动），分页浏览，点击行查看完整详情（含原始事件 rawEvent）
- **IP 一键拉黑**：攻击日志详情底部「⛔ 拉黑源 IP」按钮或日志页筛选栏「⛔ 拉黑 IP」均可提交云 WAF ACL 封禁（对全部监控站点生效）；支持 IPv4 / CIDR 网段、多 IP 批量、1/7/30/365 天有效期与备注
- **🚫 黑名单菜单**：实时列出云 WAF「访问控制」的全部封禁规则（IP/网段、类型、备注、生效域名数、创建/到期时间、剩余天数、操作人），支持关键字搜索与删除（官方 `acl/batch` 按 uuid 删除，操作前有确认弹窗；支持 IPv4/IPv6/CIDR）
- Token 状态监测、页面内一键更新、每分钟保活
- 服务端出网仅允许 http/https 且目标为公网地址（内网/环回地址拒绝）

## 本地 API

- `GET /api/state` 服务与 Token 状态
- `GET /api/logs?site=&level=&action=&hours=&kw=&page=&size=` 日志查询
- `GET /api/log?id=` 单条详情
- `GET /api/stats?hours=` 统计聚合
- `GET /api/stream` SSE 事件流
- `POST /api/token` `{"token":"..."}` 更新 Token
- `POST /api/poll` 手动触发一次轮询（1 分钟限频）
