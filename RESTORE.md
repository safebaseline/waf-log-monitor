# 备份说明（脱敏版）

生成时间：2026-11-19

## 已脱敏内容
- config.json 的 token 字段 → 占位符（原 JWT 含手机号，已移除）

## 未包含（含真实数据/凭据，不入脱敏备份）
- data/（SQLite 数据库：真实攻击/访问日志、源 IP）
- server.log（运行日志）
- .acl.json / .sites.json 等调试残留文件
- .backfill-progress.json / .backfill.log（含真实站点与数据量）

## 恢复步骤
1. 将本目录内容复制到新位置
2. 在 config.json 的 token 字段粘贴你的 Bearer Token
   （从 websaas.cn 页面 F12 → 网络中任一请求的 Authorization 复制）
3. node server.js 启动（或双击 start-background.vbs 后台启动）
4. sites.txt / visit-exclude.txt 中站点域名已替换为 example.edu 占位，实际使用时请改回你的站点
