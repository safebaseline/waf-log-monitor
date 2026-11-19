/**
 * WAF 攻击日志本地监控服务
 * - 每 N 分钟轮询 websaas 云 WAF 攻击日志接口（站点列表可自动同步 / sites.txt 手动配置）
 * - 本地 SQLite 数据库存储（Node 内置 node:sqlite，零第三方依赖）
 * - 提供本地 Web 控制台与 SSE 实时推送
 * Node >= 22.5（建议 24+）
 */
'use strict';

const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const net = require('net');
const dns = require('dns').promises;
const { DatabaseSync } = require('node:sqlite');

const ROOT = __dirname;
const CFG_PATH = path.join(ROOT, 'config.json');
const DATA_DIR = path.join(ROOT, 'data');
const DB_PATH = path.join(DATA_DIR, 'waflogs.db');
const STORE_PATH = path.join(DATA_DIR, 'store.json'); // 旧版 JSON 存储，仅用于迁移
const SITES_FILE = path.join(ROOT, 'sites.txt');
const VISIT_EXCLUDE_FILE = path.join(ROOT, 'visit-exclude.txt');
const INDEX_HTML = path.join(ROOT, 'public', 'index.html');

// ---------- 配置 ----------
const DEFAULT_CFG = {
  apiUrl: 'https://www.websaas.cn/q/cloud-waf/api/asset/attackLogQueryTotal',
  sitesApiUrl: 'https://www.websaas.cn/q/cloud-waf/api/client/searchSiteByDomain1',
  visitApiUrl: 'https://www.websaas.cn/q/cloud-waf/api/asset/visitLogQueryTotal',
  visitLogs: true,          // 是否采集访问日志
  visitPageSize: 100,
  visitMaxPagesPerSite: 30, // 单站单轮页数硬上限（游标追平即停，一般远用不满；补采轮自动×5）
  visitOverlapSeconds: 90,  // 游标回退重叠，容忍平台入库延迟
  visitMaxLogs: 0,           // 访问明细容量上限；0 = 全量存储不裁剪
  token: '',
  sites: [],
  autoSites: true,          // 每轮轮询前自动调用站点接口，取 domainPort 依次查询
  tokenKeepAlive: true,     // 每分钟向平台发一次轻量请求保持会话活跃
  keepAliveSeconds: 60,
  tokenRefreshUrl: '',      // 定期换发 Token 的接口（返回 data 字段为新 JWT）；换得的新 Token 会先验证可用于日志接口再采纳
  tokenRefreshMinutes: 10,
  aclCreateUrl: 'https://www.websaas.cn/q/cloud-waf/api/acl/create', // IP 黑名单添加接口
  aclSearchUrl: 'https://www.websaas.cn/q/cloud-waf/api/acl/search', // 黑名单列表接口
  aclBatchUrl: 'https://www.websaas.cn/q/cloud-waf/api/acl/batch',   // 黑名单删除接口（按 uuids）
  intervalMinutes: 10,   // 轮询间隔
  lookbackMinutes: 30,    // 每次轮询回看的窗口（留出日志延迟余量）
  catchupHours: 2,        // 断档补采上限：Token 失效等故障恢复后最多回拉时长
  initialHours: 24,       // 新站点首次纳入时的深度回拉小时数
  pageSize: 100,
  maxPagesPerSite: 20,
  maxLogs: 0,              // 攻击日志容量上限；0 = 全量存储不裁剪         // 数据库保留的最大日志行数（超出删除最旧）
  port: 8686
};

function loadConfig() {
  let cfg = {};
  try { cfg = JSON.parse(fs.readFileSync(CFG_PATH, 'utf8')); } catch (e) {
    console.error('[config] 读取失败，使用默认值:', e.message);
  }
  return Object.assign({}, DEFAULT_CFG, cfg);
}
let cfg = loadConfig();
function saveConfig() {
  fs.writeFileSync(CFG_PATH, JSON.stringify(cfg, null, 2) + '\n', 'utf8');
}

// ---------- SSRF 防护：仅允许 http/https 且目标必须是公网地址 ----------
function ipv4ToInt(ip) { const p = ip.split('.').map(Number); return ((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3]; }
function inCidr4(ip, base, bits) {
  const n = ipv4ToInt(ip), b = ipv4ToInt(base), mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
  return (n & mask) === (b & mask);
}
const RESERVED_V4 = [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8],
  ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24],
  ['192.168.0.0', 16], ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24],
  ['224.0.0.0', 4], ['240.0.0.0', 4]
];
function isPrivateAddress(addr) {
  if (addr.includes(':')) {
    const a = addr.toLowerCase();
    if (a === '::1' || a === '::') return true;
    if (a.startsWith('::ffff:')) return isPrivateAddress(a.slice(7)); // v4 映射地址
    if (/^f[cd]/.test(a)) return true;   // fc00::/7 私有
    if (/^fe[89ab]/.test(a)) return true; // fe80::/10 链路本地
    return false;
  }
  if (!/^\d+\.\d+\.\d+\.\d+$/.test(addr)) return true; // 无法识别的一律拒绝
  return RESERVED_V4.some(([base, bits]) => inCidr4(addr, base, bits));
}
let safeUrlCache = new Map(); // host -> {ok, at}
async function assertSafeTarget(rawUrl) {
  let u;
  try { u = new URL(rawUrl); } catch (e) { throw new Error('URL 无效'); }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') throw new Error('仅允许 http/https 协议');
  const host = u.hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local') || host.endsWith('.internal')) {
    throw new Error('禁止访问本地/内部主机: ' + host);
  }
  const cached = safeUrlCache.get(host);
  if (cached && Date.now() - cached.at < 10 * 60 * 1000) { if (!cached.ok) throw new Error('目标主机地址非法: ' + host); return; }
  let addrs;
  try { addrs = await dns.lookup(host, { all: true, verbatim: true }); }
  catch (e) { throw new Error('DNS 解析失败: ' + host); }
  for (const a of addrs) {
    if (isPrivateAddress(a.address)) {
      safeUrlCache.set(host, { ok: false, at: Date.now() });
      throw new Error(`目标主机 ${host} 解析到保留/内网地址 ${a.address}，已拒绝请求`);
    }
  }
  safeUrlCache.set(host, { ok: true, at: Date.now() });
}

// ---------- HTTP 客户端 ----------
// 瞬时网络错误（断连/重置/超时等）自动重试 2 次，避免平台偶发抖动造成整轮采集失败
const TRANSIENT_RE = /socket hang up|ECONNRESET|EPIPE|ETIMEDOUT|ECONNABORTED|EAI_AGAIN|请求超时|network/i;
function httpRequest(method, targetUrl, bodyObj, extraHeaders) {
  return new Promise(async (resolve, reject) => {
    try { await assertSafeTarget(targetUrl); } catch (e) { return reject(e); }
    const u = new URL(targetUrl);
    const payload = bodyObj ? JSON.stringify(bodyObj) : null;
    const mod = u.protocol === 'https:' ? https : http;
    const baseHeaders = {
      'Accept': 'application/json, text/plain, */*',
      'Authorization': 'Bearer ' + cfg.token
    };
    if (extraHeaders) Object.assign(baseHeaders, extraHeaders);
    if (payload) {
      baseHeaders['Content-Type'] = 'application/json;charset=utf-8';
      baseHeaders['Content-Length'] = Buffer.byteLength(payload);
    }
    const doReq = (attempt) => {
      const req = mod.request({
        hostname: u.hostname, port: u.port || (u.protocol === 'https:' ? 443 : 80),
        path: u.pathname + u.search, method, headers: baseHeaders, timeout: 30000
      }, res => {
        let buf = [];
        res.on('data', c => buf.push(c));
        res.on('error', er => {
          if (TRANSIENT_RE.test(er.message) && attempt < 2) return setTimeout(() => doReq(attempt + 1), 800 * (attempt + 1));
          reject(er);
        });
        res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, text: Buffer.concat(buf).toString('utf8') }));
      });
      req.on('timeout', () => { req.destroy(new Error('请求超时')); });
      req.on('error', err => {
        if (TRANSIENT_RE.test(err.message) && attempt < 2) {
          console.log(`[http] ${u.hostname} ${err.message}，第 ${attempt + 1} 次重试…`);
          return setTimeout(() => doReq(attempt + 1), 800 * (attempt + 1));
        }
        reject(err);
      });
      if (payload) req.write(payload);
      req.end();
    };
    doReq(0);
  });
}

function authError(msg) { const e = new Error(msg); e.authError = true; return e; }

async function queryPage(site, startTime, endTime, page) {
  const body = {
    destHostName: site, requestUrl: '', srcAddress: null, responseCode: '',
    requestMethod: '', startTime, endTime, country: '', srcPrivince: null,
    srcCity: null, page, size: cfg.pageSize
  };
  const res = await httpRequest('POST', cfg.apiUrl, body);
  if (res.status === 401 || res.status === 403) throw authError('Token 无效或已过期 (HTTP ' + res.status + ')');
  if (res.status !== 200) throw new Error('HTTP ' + res.status + ' ' + res.text.slice(0, 120));
  let json;
  try { json = JSON.parse(res.text); } catch (e) { throw new Error('响应不是 JSON: ' + res.text.slice(0, 120)); }
  if (!json.success && json.errorCode !== 0) {
    const err = new Error('接口返回错误: ' + (json.message || json.errorCode));
    if (/登录|token|授权|认证|未授权/i.test(json.message || '')) err.authError = true;
    throw err;
  }
  const data = json.data || {};
  const pg = data.page || {};
  return { total: (data.total != null ? data.total : pg.totalElements) || 0, content: Array.isArray(pg.content) ? pg.content : [], last: pg.last !== false };
}

async function visitQueryPage(site, startTime, endTime, page) {
  const body = {
    destHostName: site, requestUrl: '', srcAddress: null, responseCode: null,
    requestMethod: '', startTime, endTime, country: '', srcPrivince: null,
    srcCity: null, page, size: cfg.visitPageSize
  };
  const res = await httpRequest('POST', cfg.visitApiUrl, body);
  if (res.status === 401 || res.status === 403) throw authError('Token 无效或已过期 (HTTP ' + res.status + ')');
  if (res.status !== 200) throw new Error('HTTP ' + res.status + ' ' + res.text.slice(0, 120));
  let json;
  try { json = JSON.parse(res.text); } catch (e) { throw new Error('响应不是 JSON: ' + res.text.slice(0, 120)); }
  if (!json.success && json.errorCode !== 0) {
    const err = new Error('接口返回错误: ' + (json.message || json.errorCode));
    if (/登录|token|授权|认证|未授权/i.test(json.message || '')) err.authError = true;
    throw err;
  }
  const data = json.data || {};
  const pg = data.page || {};
  return { total: (data.total != null ? data.total : pg.totalElements) || 0, content: Array.isArray(pg.content) ? pg.content : [], last: pg.last !== false };
}

function normalizeVisitEntry(e, queriedSite) {
  const ts = e.etlProcessTime || parseCst(e.startTime) || parseCst(e.collectorReceiptTime) || 0;
  const at = parseCst(e.startTime) || ts;
  const host = String(e.destHostName || queriedSite || '').replace(/:\d+$/, '');
  // 平台 rawEvent 携带的 reqId 全局唯一，优先作为去重主键；无 reqId 时退回复合键
  const reqId = (String(e.rawEvent || '').match(/reqId=([0-9a-fA-F]+)/) || [])[1];
  const id = reqId ? 'r:' + reqId : sha256([e.startTime, e.srcAddress, e.srcPort, e.requestUrl, e.requestMethod, host].join('|'));
  return {
    id, at, ts, host,
    site: e.destHostName || queriedSite || '',
    method: e.requestMethod || '',
    url: e.requestUrl || '',
    status_code: String(e.responseCode == null ? '' : e.responseCode),
    src_ip: e.srcAddress || '',
    geo_country: e.srcGeoCountry || '', geo_region: e.srcGeoRegion || '', geo_city: e.srcGeoCity || '',
    referer: e.httpReferer || '',
    ua: e.requestClientApplication || e.accessAgent || '',
    os: e.clientOperatingSystem || '',
    browser: e.browser_version || '',
    spider: String(e.isSpider == null ? '' : e.isSpider),
    bytes_in: Number(e.bytesIn) || 0,
    bytes_out: Number(e.bytesOut) || 0,
    rt: Number(e.trTime) || 0,
    start_time: e.startTime || '',
    raw: JSON.stringify(e)
  };
}

// ---------- 站点列表自动同步 ----------
async function fetchSiteList() {
  const found = new Map();   // 查询键(domainPort) -> true
  const infos = [];          // {host, name, attackCount}
  const idByKey = new Map(); // domainPort -> 平台站点 _id（用于 ACL siteIds）
  let page = 0;
  while (page < 20) {
    const u = new URL(cfg.sitesApiUrl);
    u.searchParams.set('page', page);
    u.searchParams.set('size', '100');
    u.searchParams.set('domain1', '');
    u.searchParams.set('ruleEngine', '');
    u.searchParams.set('isParse', '');
    const res = await httpRequest('GET', u.toString(), null);
    if (res.status === 401 || res.status === 403) throw authError('Token 无效或已过期 (HTTP ' + res.status + ')');
    if (res.status !== 200) throw new Error('站点接口 HTTP ' + res.status);
    let json;
    try { json = JSON.parse(res.text); } catch (e) { throw new Error('站点接口响应不是 JSON'); }
    const arr = Array.isArray(json.data) ? json.data : [];
    if (!arr.length) break;
    for (const it of arr) {
      const key = String(it.domainPort || it.domain || '').trim();
      if (!key) continue;
      found.set(key, true);
      if (it._id) idByKey.set(key, String(it._id));
      const host = String(it.domain || key).replace(/:\d+$/, '');
      if (!infos.some(x => x.host === host && x.name === (it.name || host))) {
        infos.push({ host, name: it.name || host, attackCount: it.attack_count || 0 });
      }
    }
    if (arr.length < 100) break;
    page++;
  }
  const sites = [...found.keys()];
  if (!sites.length) throw new Error('站点接口未返回任何站点');
  // 每轮都会调用本函数；列表无变化时不再重写 config.json，避免频繁写盘
  const changed = JSON.stringify(sites) !== JSON.stringify(cfg.sites);
  cfg.sites = sites;
  state.siteInfo = infos;
  state.siteIdByKey = idByKey;
  state.lastSiteSyncAt = Date.now();
  if (changed) {
    saveConfig();
    console.log(`[sites] 已同步 ${sites.length} 个站点（domainPort 列表有变化）`);
  }
  return sites.length;
}

// ---------- 手动站点配置文件（sites.txt）----------
// 文件存在且含有效行 → 手动模式按文件采集；否则回退自动同步
let sitesFileMtime = -1;
function loadManualSites() {
  let st;
  try { st = fs.statSync(SITES_FILE); } catch (e) {
    if (sitesFileMtime !== 0) console.log('[sites] 未找到 sites.txt，使用自动同步模式');
    sitesFileMtime = 0;
    state.manualSites = [];
    return;
  }
  const mtime = st.mtimeMs;
  if (mtime === sitesFileMtime) return; // 未变化
  sitesFileMtime = mtime;
  let lines;
  try { lines = fs.readFileSync(SITES_FILE, 'utf8').split(/\r?\n/); } catch (e) { return; }
  const list = [];
  for (let line of lines) {
    line = line.trim();
    if (!line || line.startsWith('#')) continue;
    // 支持 "域名  备注" 形式：取第一段，其余视为备注
    const key = line.split(/[\s,;]+/)[0];
    if (key && !list.includes(key)) list.push(key);
  }
  const prev = state.manualSites.length;
  state.manualSites = list;
  console.log(`[sites] 已从 sites.txt 加载 ${list.length} 个手动站点（此前 ${prev} 个）`);
}
function effectiveSites() {
  return state.manualSites.length ? state.manualSites : cfg.sites;
}

// ---------- 访问日志采集例外（visit-exclude.txt）----------
// 每轮热加载；条目支持「域名:端口」精确匹配或「域名」整站匹配（带/不带端口变体一并排除）
let visitExcludeMtime = -1;
function loadVisitExclude() {
  let st;
  try { st = fs.statSync(VISIT_EXCLUDE_FILE); } catch (e) {
    if (state.visitExclude.length) console.log('[visits] 未找到 visit-exclude.txt，访问日志全量采集');
    visitExcludeMtime = 0;
    state.visitExclude = [];
    return;
  }
  if (st.mtimeMs === visitExcludeMtime) return;
  visitExcludeMtime = st.mtimeMs;
  let lines;
  try { lines = fs.readFileSync(VISIT_EXCLUDE_FILE, 'utf8').split(/\r?\n/); } catch (e) { return; }
  const list = [];
  for (let line of lines) {
    line = line.trim();
    if (!line || line.startsWith('#')) continue;
    const key = line.split(/[\s,;]+/)[0];
    if (key && !list.includes(key)) list.push(key);
  }
  const prev = state.visitExclude.length;
  state.visitExclude = list;
  console.log(`[visits] 访问日志排除列表已加载: ${list.length} 项（此前 ${prev} 项）${list.length ? ': ' + list.join(', ') : ''}`);
}
function visitExcluded(siteKey) {
  if (!state.visitExclude.length) return false;
  return state.visitExclude.includes(siteKey) || state.visitExclude.includes(String(siteKey).replace(/:\d+$/, ''));
}

// ---------- 日志归一化 ----------
function sha256(s) { return crypto.createHash('sha256').update(s).digest('hex'); }
function parseCst(s) { // "2026-10-19 12:15:44" 视为东八区
  if (!s || typeof s !== 'string') return 0;
  const t = Date.parse(s.replace(' ', 'T') + '+08:00');
  return isNaN(t) ? 0 : t;
}
function normalizeEntry(e, queriedSite) {
  const ts = e.etlProcessTime || parseCst(e.startTime) || parseCst(e.collectorReceiptTime) || 0;
  const at = parseCst(e.startTime) || ts;
  const host = String(e.destHostName || queriedSite || '').replace(/:\d+$/, '');
  // 去重键使用去掉端口的站点名，避免同一站点带/不带端口两次查询造成重复
  const id = sha256([e.startTime, e.srcAddress, e.srcPort, e.requestUrlAddress, e.name, e.ruelId, host].join('|'));
  return {
    id, at, ts, host,
    site: e.destHostName || queriedSite || '',
    attack_type: e.name || '',
    level: e.dbappWAFEventLevel || '',
    level_id: String(e.dbappWAFEventLevelId == null ? '' : e.dbappWAFEventLevelId),
    action: e.dvcAction || '',
    method: e.requestMethod || '',
    url: e.requestUrlAddress || '',
    status_code: String(e.responseCode == null ? '' : e.responseCode),
    rule_id: String(e.ruelId == null ? '' : e.ruelId),
    src_ip: e.srcAddress || '',
    geo_country: e.srcGeoCountry || '',
    geo_region: e.srcGeoRegion || '',
    geo_city: e.srcGeoCity || '',
    start_time: e.startTime || '',
    raw: JSON.stringify(e)
  };
}

// ---------- SQLite 本地数据库 ----------
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
const db = new DatabaseSync(DB_PATH);
// 全部 SQL 均为静态语句 + 参数绑定，不拼接任何外部输入
db.prepare('PRAGMA journal_mode = WAL').get();
// 大库调优：页面缓存 256MB + mmap，让重复扫描/筛选命中内存而非反复读盘
db.prepare('PRAGMA cache_size = -262144').run();
try { db.prepare('PRAGMA mmap_size = 1073741824').get(); } catch (e) {}
db.prepare(`CREATE TABLE IF NOT EXISTS logs (
  id          TEXT PRIMARY KEY,
  at          INTEGER NOT NULL,
  ts          INTEGER,
  host        TEXT,
  site        TEXT,
  attack_type TEXT,
  level       TEXT,
  level_id    TEXT,
  action      TEXT,
  method      TEXT,
  url         TEXT,
  status_code TEXT,
  rule_id     TEXT,
  src_ip      TEXT,
  geo_country TEXT,
  geo_region  TEXT,
  geo_city    TEXT,
  start_time  TEXT,
  raw         TEXT NOT NULL
)`).run();
db.prepare('CREATE INDEX IF NOT EXISTS idx_logs_at ON logs(at)').run();
db.prepare('CREATE INDEX IF NOT EXISTS idx_logs_host ON logs(host)').run();
db.prepare('CREATE INDEX IF NOT EXISTS idx_logs_level ON logs(level)').run();
db.prepare('CREATE TABLE IF NOT EXISTS known_sites (site TEXT PRIMARY KEY, first_seen INTEGER)').run();
db.prepare('CREATE TABLE IF NOT EXISTS visit_cursors (site TEXT PRIMARY KEY, last_at INTEGER)').run();
// 访问日志全文索引（外部内容表，磁盘不重复存储；供关键字搜索毫秒级命中）
db.prepare(`CREATE VIRTUAL TABLE IF NOT EXISTS visit_fts USING fts5(
  url, ua, referer, src_ip, host, geo_city, geo_region,
  content='visit_logs', content_rowid='rowid'
)`).run();
// 小时级访问量聚合（host×小时），用于趋势图/TOP统计；不随明细裁剪丢失
db.prepare('CREATE TABLE IF NOT EXISTS visit_hourly (host TEXT, hb INTEGER, count INTEGER, PRIMARY KEY (host, hb))').run();
db.prepare('CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT)').run();
db.prepare(`CREATE TABLE IF NOT EXISTS visit_logs (
  id          TEXT PRIMARY KEY,
  at          INTEGER NOT NULL,
  ts          INTEGER,
  host        TEXT,
  site        TEXT,
  method      TEXT,
  url         TEXT,
  status_code TEXT,
  src_ip      TEXT,
  geo_country TEXT,
  geo_region  TEXT,
  geo_city    TEXT,
  referer     TEXT,
  ua          TEXT,
  os          TEXT,
  browser     TEXT,
  spider      TEXT,
  bytes_in    INTEGER,
  bytes_out   INTEGER,
  rt          INTEGER,
  start_time  TEXT,
  raw         TEXT NOT NULL
)`).run();
db.prepare('CREATE INDEX IF NOT EXISTS idx_vlogs_at ON visit_logs(at)').run();
// 组合索引（列+时间）：筛选/统计的 GROUP BY 在索引内完成，避免回表
db.prepare('DROP INDEX IF EXISTS idx_vlogs_host').run();
db.prepare('CREATE INDEX IF NOT EXISTS idx_vlogs_host_at ON visit_logs(host, at)').run();
db.prepare('DROP INDEX IF EXISTS idx_vlogs_status').run();
db.prepare('CREATE INDEX IF NOT EXISTS idx_vlogs_status_at ON visit_logs(status_code, at)').run();
db.prepare('DROP INDEX IF EXISTS idx_vlogs_method').run();
db.prepare('CREATE INDEX IF NOT EXISTS idx_vlogs_method_at ON visit_logs(method, at)').run();
db.prepare('DROP INDEX IF EXISTS idx_vlogs_spider').run();
db.prepare('CREATE INDEX IF NOT EXISTS idx_vlogs_spider_at ON visit_logs(spider, at)').run();
db.prepare('CREATE INDEX IF NOT EXISTS idx_vlogs_srcip_at ON visit_logs(src_ip, at)').run();

const txBegin = db.prepare('BEGIN');
const txCommit = db.prepare('COMMIT');
const txRollback = db.prepare('ROLLBACK');
const stmtInsertLog = db.prepare(
  'INSERT OR IGNORE INTO logs (id, at, ts, host, site, attack_type, level, level_id, action, method, url, status_code, rule_id, src_ip, geo_country, geo_region, geo_city, start_time, raw) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)'
);
const stmtGetRaw = db.prepare('SELECT raw FROM logs WHERE id = ?');
const stmtIsKnown = db.prepare('SELECT 1 AS ok FROM known_sites WHERE site = ?');
const stmtMarkKnown = db.prepare('INSERT OR IGNORE INTO known_sites (site, first_seen) VALUES (?, ?)');
const stmtCountLogs = db.prepare('SELECT COUNT(*) AS c FROM logs');
const stmtLatestIds = db.prepare('SELECT id FROM logs ORDER BY at DESC, rowid DESC LIMIT 20');
const stmtTrim = db.prepare('DELETE FROM logs WHERE id IN (SELECT id FROM logs ORDER BY at DESC, rowid DESC LIMIT -1 OFFSET ?)');
const stmtInsertVisit = db.prepare(
  'INSERT OR IGNORE INTO visit_logs (id, at, ts, host, site, method, url, status_code, src_ip, geo_country, geo_region, geo_city, referer, ua, os, browser, spider, bytes_in, bytes_out, rt, start_time, raw) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)'
);
const stmtGetVisitRaw = db.prepare('SELECT raw FROM visit_logs WHERE id = ?');
const stmtCountVisits = db.prepare('SELECT COUNT(*) AS c FROM visit_logs');
const stmtTrimVisits = db.prepare('DELETE FROM visit_logs WHERE id IN (SELECT id FROM visit_logs ORDER BY at DESC, rowid DESC LIMIT -1 OFFSET ?)');
const stmtGetVisitCursor = db.prepare('SELECT last_at FROM visit_cursors WHERE site = ?');
const stmtSetVisitCursor = db.prepare('INSERT OR REPLACE INTO visit_cursors (site, last_at) VALUES (?, ?)');
const stmtUpsertHourly = db.prepare('INSERT INTO visit_hourly (host, hb, count) VALUES (?, ?, ?) ON CONFLICT (host, hb) DO UPDATE SET count = count + excluded.count');
const stmtInsFts = db.prepare('INSERT INTO visit_fts(rowid, url, ua, referer, src_ip, host, geo_city, geo_region) VALUES (?, ?, ?, ?, ?, ?, ?, ?)');
const stmtGetMeta = db.prepare('SELECT v FROM meta WHERE k = ?');
const stmtSetMeta = db.prepare('INSERT OR REPLACE INTO meta (k, v) VALUES (?, ?)');

const INSERT_COLS = ['id', 'at', 'ts', 'host', 'site', 'attack_type', 'level', 'level_id', 'action', 'method', 'url', 'status_code', 'rule_id', 'src_ip', 'geo_country', 'geo_region', 'geo_city', 'start_time', 'raw'];
function insertEntry(e) {
  return stmtInsertLog.run(...INSERT_COLS.map(k => e[k])).changes;
}
const VISIT_COLS = ['id', 'at', 'ts', 'host', 'site', 'method', 'url', 'status_code', 'src_ip', 'geo_country', 'geo_region', 'geo_city', 'referer', 'ua', 'os', 'browser', 'spider', 'bytes_in', 'bytes_out', 'rt', 'start_time', 'raw'];
function insertVisit(e) {
  return stmtInsertVisit.run(...VISIT_COLS.map(k => e[k])).changes;
}
function insertVisitMany(entries) {
  txBegin.run();
  try {
    let n = 0;
    const fresh = [];
    for (const e of entries) {
      const r = stmtInsertVisit.run(...VISIT_COLS.map(k => e[k]));
      if (r.changes) { n++; fresh.push({ e, rowid: r.lastInsertRowid }); }
    }
    // 新增明细同步累进小时聚合与全文索引（已去重，重复行不计）
    for (const f of fresh) {
      stmtUpsertHourly.run(f.e.host, Math.floor((f.e.at + 8 * 3600e3) / 3600e3), 1);
      stmtInsFts.run(f.rowid, f.e.url, f.e.ua, f.e.referer, f.e.src_ip, f.e.host, f.e.geo_city, f.e.geo_region);
    }
    txCommit.run();
    return n;
  } catch (er) { txRollback.run(); throw er; }
}
function insertMany(entries) {
  txBegin.run();
  try {
    let n = 0;
    for (const e of entries) if (insertEntry(e)) n++;
    txCommit.run();
    return n;
  } catch (er) { txRollback.run(); throw er; }
}

// 旧版 store.json → SQLite 一次性迁移
function migrateFromStoreJson() {
  if (stmtCountLogs.get().c > 0) return;
  let s;
  try { s = JSON.parse(fs.readFileSync(STORE_PATH, 'utf8')); } catch (e) { return; }
  if (!Array.isArray(s.logs) || !s.logs.length) return;
  try {
    const mapped = s.logs.map(e => {
      const raw = Object.assign({}, e);
      delete raw._id; delete raw._at; delete raw._ts; delete raw._host;
      return {
        id: e._id, at: e._at || 0, ts: e._ts || 0, host: e._host || '',
        site: raw.destHostName || '', attack_type: raw.name || '',
        level: raw.dbappWAFEventLevel || '', level_id: String(raw.dbappWAFEventLevelId == null ? '' : raw.dbappWAFEventLevelId),
        action: raw.dvcAction || '', method: raw.requestMethod || '', url: raw.requestUrlAddress || '',
        status_code: String(raw.responseCode == null ? '' : raw.responseCode), rule_id: String(raw.ruelId == null ? '' : raw.ruelId),
        src_ip: raw.srcAddress || '', geo_country: raw.srcGeoCountry || '', geo_region: raw.srcGeoRegion || '',
        geo_city: raw.srcGeoCity || '', start_time: raw.startTime || '', raw: JSON.stringify(raw)
      };
    });
    insertMany(mapped);
    txBegin.run();
    try {
      for (const k of (s.knownSites || [])) stmtMarkKnown.run(k, Date.now());
      txCommit.run();
    } catch (er) { txRollback.run(); }
    fs.renameSync(STORE_PATH, STORE_PATH + '.bak');
    console.log(`[db] 已迁移 store.json ${mapped.length} 条 → SQLite（原文件备份为 store.json.bak）`);
  } catch (er) {
    console.error('[db] 迁移失败:', er.message);
  }
}
migrateFromStoreJson();
// 首次启动把已有明细回填进小时聚合表
if (db.prepare('SELECT COUNT(*) AS c FROM visit_hourly').get().c === 0) {
  const n = db.prepare('INSERT OR IGNORE INTO visit_hourly (host, hb, count) SELECT host, CAST((at + 28800000) / 3600000 AS INTEGER) AS hb, COUNT(*) AS count FROM visit_logs GROUP BY host, hb').run();
  console.log(`[db] 小时聚合表回填完成（${n.changes} 组）`);
}
// 一次性构建访问日志全文索引（存量数据）
if (!(stmtGetMeta.get('ftsBuilt') || {}).v) {
  console.log('[db] 构建访问日志全文索引（一次性，可能需要 1~2 分钟）…');
  db.prepare("INSERT INTO visit_fts(visit_fts) VALUES('rebuild')").run();
  stmtSetMeta.run('ftsBuilt', String(Date.now()));
  console.log('[db] 全文索引构建完成');
}

// ---------- 状态 ----------
const state = {
  manualSites: [],        // sites.txt 手动配置的站点（空 = 自动模式）
  siteIdByKey: new Map(), // domainPort -> 平台站点 _id（拉黑用 siteIds）
  siteTotals: {},         // site -> 最近一次轮询窗口内的 total
  siteInfo: [],           // 自动同步的站点信息 [{host, name, attackCount}]
  lastSiteSyncAt: null,
  lastPollAt: null, nextPollAt: null, polling: false, lastGoodAt: null,
  visitTotals: {}, visitGap: 0, visitGapSites: [], visitExclude: [],
  keepAlive: { enabled: false, lastAt: null, ok: null, code: null, note: '' },
  tokenRefresh: { enabled: false, lastAt: null, ok: null, note: '', adopted: 0 },
  lastError: null, tokenStatus: 'unknown', tokenExp: null, tokenSub: null,
  startedAt: Date.now(),
  pollLog: []             // {at, ok, added, msg}
};
function jwtInfo(token) {
  try {
    const part = token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
    const payload = JSON.parse(Buffer.from(part, 'base64').toString('utf8'));
    return { exp: payload.exp * 1000 || null, sub: payload.sub || null };
  } catch (e) { return { exp: null, sub: null }; }
}
function refreshTokenInfo() {
  if (!cfg.token) { state.tokenStatus = 'missing'; state.tokenExp = null; state.tokenSub = null; return; }
  const info = jwtInfo(cfg.token);
  state.tokenExp = info.exp; state.tokenSub = info.sub;
  state.tokenStatus = info.exp ? (Date.now() < info.exp ? 'valid' : 'expired') : 'unknown';
}
refreshTokenInfo();

// ---------- 轮询 ----------
const sleep = ms => new Promise(r => setTimeout(r, ms));
let pollTimer = null;

async function pollOnce(reason) {
  if (state.polling) return;
  state.polling = true;
  state.lastError = null;
  const endTs = Math.floor(Date.now() / 1000);
  let added = 0, visitAdded = 0, errors = [];
  state.visitGap = 0; state.visitGapSites = [];
  refreshTokenInfo();

  // 断档感知补采窗口：距上次成功采集越久窗口越大（30 分钟 ~ catchupHours 上限），
  // Token 失效恢复 / 服务停机重启后自动回补断档期间的数据
  const sinceGoodSec = state.lastGoodAt ? Math.max(0, (Date.now() - state.lastGoodAt) / 1000) : 0;
  const catchupSec = Math.min(cfg.catchupHours * 3600, Math.max(cfg.lookbackMinutes * 60, sinceGoodSec + 300));
  const isCatchup = catchupSec > cfg.lookbackMinutes * 60 + 120;
  if (isCatchup) console.log(`[poll] 检测到断档（距上次成功采集 ${Math.round(sinceGoodSec / 60)} 分钟），本轮补采窗口 ${Math.round(catchupSec / 60)} 分钟`);

  // 每轮检查 sites.txt 是否被手动修改（编辑后下一轮询或手动刷新即生效）
  loadManualSites();
  loadVisitExclude();

  // 每轮先调用站点接口，取返回包中的 domainPort 作为本轮攻击日志查询键，依次轮询；
  // 接口失败时沿用上一轮缓存的列表继续
  if (cfg.autoSites) {
    try { await fetchSiteList(); }
    catch (e) {
      errors.push('站点同步: ' + e.message);
      if (e.authError) state.tokenStatus = 'invalid';
    }
  }

  const sitesToPoll = effectiveSites();
  // 补采轮放宽单站页数上限，尽量覆盖断档期数据
  const visitPageCap = isCatchup ? cfg.visitMaxPagesPerSite * 5 : cfg.visitMaxPagesPerSite;
  for (const site of sitesToPoll) {
    // 新纳入的站点做深度回拉（initialHours），已知站点按补采窗口回看
    const deepFetch = !stmtIsKnown.get(site);
    const windowMs = deepFetch ? cfg.initialHours * 3600e3 : catchupSec * 1000;
    const startTs = Math.floor((Date.now() - windowMs) / 1000);
    let siteOk = true;
    try {
      let page = 0, fetched = 0, total = 0;
      while (page < cfg.maxPagesPerSite) {
        const r = await queryPage(site, startTs, endTs, page);
        total = r.total || total;
        if (r.content.length) {
          const n = insertMany(r.content.map(x => normalizeEntry(x, site)));
          added += n;
          if (n === 0) break; // 整页均为已知：窗口内更早数据已采集，提前结束省请求
        }
        fetched += r.content.length;
        if (r.last || r.content.length === 0 || (total && fetched >= total)) break;
        page++;
        await sleep(150);
      }
      state.siteTotals[site] = total;
    } catch (e) {
      siteOk = false;
      errors.push(`${site}: ${e.message}`);
      if (e.authError) { state.tokenStatus = 'invalid'; }
    }
    // 访问日志：游标式增量采集，排除名单中的站点跳过（攻击日志不受影响）
    if (cfg.visitLogs && !visitExcluded(site)) {
      try {
        const cur = stmtGetVisitCursor.get(site);
        // 游标太旧（断档/停机超过补采上限）时按补采窗口钳制
        const initialStart = endTs - catchupSec;
        const vStart = cur && cur.last_at ? Math.max(Math.floor(cur.last_at / 1000) - cfg.visitOverlapSeconds, initialStart) : initialStart;
        let vp = 0, vfetched = 0, vtotal = 0, reachedLast = false, hitKnownPage = false;
        while (vp < visitPageCap) {
          const vr = await visitQueryPage(site, vStart, endTs, vp);
          vtotal = vr.total || vtotal;
          if (!vr.content.length) { reachedLast = true; break; }
          const n = insertVisitMany(vr.content.map(x => normalizeVisitEntry(x, site)));
          visitAdded += n;
          vfetched += vr.content.length;
          if (n === 0) { hitKnownPage = true; break; } // 翻到与上轮重叠的已知区
          if (vr.last) { reachedLast = true; break; }
          vp++;
          await sleep(80);
        }
        // 因页上限停止且未追平 → 存在缺口，记录条数供页面展示
        if (!hitKnownPage && !reachedLast && vtotal > vfetched) {
          state.visitGap += vtotal - vfetched;
          state.visitGapSites.push(site.replace(/:\d+$/, ''));
        }
        state.visitTotals[site] = vtotal;
        stmtSetVisitCursor.run(site, endTs * 1000);
      } catch (e) {
        errors.push(`访问日志 ${site}: ${e.message}`);
        if (e.authError) state.tokenStatus = 'invalid';
      }
    }
    if (siteOk) stmtMarkKnown.run(site, Date.now());
    await sleep(120);
  }

  // 容量修剪：超出上限删除最旧（maxLogs / visitMaxLogs 为 0 表示全量存储）
  let total = stmtCountLogs.get().c;
  if (cfg.maxLogs > 0 && total > cfg.maxLogs) { stmtTrim.run(cfg.maxLogs); total = cfg.maxLogs; }
  if (cfg.visitLogs && cfg.visitMaxLogs > 0) {
    const vc = stmtCountVisits.get().c;
    if (vc > cfg.visitMaxLogs) stmtTrimVisits.run(cfg.visitMaxLogs);
  }

  // 本轮无 Token 失效类错误 → 记录成功时刻（断档感知的锚点，跨重启持久化）
  const authFailed = errors.some(m => /Token/i.test(m));
  if (!authFailed) {
    state.lastGoodAt = Date.now();
    try { stmtSetMeta.run('lastGoodAt', String(state.lastGoodAt)); } catch (e) {}
  }
  facetCache.clear(); // 新数据已入库，聚合缓存随之失效，页面下拉数量随轮询刷新

  state.lastPollAt = Date.now();
  // 错误去重并截断，避免 Token 失效等共性错误刷屏
  const uniqErrors = [...new Set(errors)];
  state.lastError = uniqErrors.length ? uniqErrors.slice(0, 5).join(' ; ') + (uniqErrors.length > 5 ? ` ……等 ${uniqErrors.length} 项` : '') : null;
  state.pollLog.unshift({ at: state.lastPollAt, ok: errors.length === 0, added, msg: state.lastError || `${sitesToPoll.length} 个站点查询完成` });
  state.pollLog = state.pollLog.slice(0, 30);
  state.polling = false;

  console.log(`[poll:${reason}] +${added} 攻击 / +${visitAdded} 访问, 库内 ${total}${errors.length ? ', 错误: ' + errors[0] : ''}`);
  broadcast('poll', {
    at: state.lastPollAt, added, visitAdded, total,
    latest: stmtLatestIds.all().map(r => ({ _id: r.id })),
    error: state.lastError, tokenStatus: state.tokenStatus
  });
}
function scheduleNext() {
  clearTimeout(pollTimer);
  state.nextPollAt = Date.now() + cfg.intervalMinutes * 60 * 1000;
  pollTimer = setTimeout(async () => {
    await pollOnce('timer');
    scheduleNext();
  }, cfg.intervalMinutes * 60 * 1000);
}

// ---------- Token 保活 ----------
// 每 keepAliveSeconds 向平台发一次轻量已认证请求，维持服务端会话活跃；
// 若平台通过响应头下发新 Token（authorization/token 等），自动采纳并广播
let lastKaBroadcast = '';
async function keepAliveOnce() {
  const u = new URL(cfg.sitesApiUrl);
  u.searchParams.set('page', '0');
  u.searchParams.set('size', '1');
  u.searchParams.set('domain1', '');
  u.searchParams.set('ruleEngine', '');
  u.searchParams.set('isParse', '');
  try {
    const res = await httpRequest('GET', u.toString(), null);
    state.keepAlive.lastAt = Date.now();
    state.keepAlive.code = res.status;
    state.keepAlive.note = '';
    if (res.status === 401 || res.status === 403) {
      state.keepAlive.ok = false;
      if (state.tokenStatus !== 'invalid') {
        state.tokenStatus = 'invalid';
        broadcast('token', { status: state.tokenStatus });
      }
    } else if (res.status === 200) {
      state.keepAlive.ok = true;
      refreshTokenInfo();
      const h = res.headers || {};
      const fresh = h['authorization'] || h['token'] || h['new-token'] || h['refresh-token'];
      if (fresh) {
        const t = String(fresh).replace(/^Bearer\s+/i, '').trim();
        if (t && t !== cfg.token && t.split('.').length === 3) {
          cfg.token = t; saveConfig(); refreshTokenInfo();
          console.log('[keepalive] 平台响应头下发新 Token，已自动更新');
          broadcast('token', { status: state.tokenStatus, exp: state.tokenExp });
        }
      }
    } else {
      state.keepAlive.ok = false;
      state.keepAlive.note = 'HTTP ' + res.status;
    }
  } catch (e) {
    state.keepAlive.lastAt = Date.now();
    state.keepAlive.ok = false;
    state.keepAlive.code = 0;
    state.keepAlive.note = e.message;
  }
  const sig = String(state.keepAlive.ok);
  if (sig !== lastKaBroadcast) { lastKaBroadcast = sig; broadcast('keepalive', { ok: state.keepAlive.ok, at: state.keepAlive.lastAt }); }
}

// ---------- Token 定期换发 ----------
// 每 tokenRefreshMinutes 请求 tokenRefreshUrl；换得的新 JWT 必须先通过
// 站点接口验证（防止采纳作用域受限的 Token 弄断采集）才会替换保存
async function refreshTokenOnce() {
  if (!cfg.tokenRefreshUrl) return;
  const tr = state.tokenRefresh;
  tr.lastAt = Date.now();
  try {
    const res = await httpRequest('GET', cfg.tokenRefreshUrl, null);
    if (res.status === 401 || res.status === 403) {
      tr.ok = false; tr.note = '当前 Token 已失效，无法换发（HTTP ' + res.status + '），请手动更新';
      broadcast('token', { status: state.tokenStatus });
      return;
    }
    if (res.status !== 200) { tr.ok = false; tr.note = '换发接口 HTTP ' + res.status; return; }
    let json; try { json = JSON.parse(res.text); } catch (e) { tr.ok = false; tr.note = '换发接口返回非 JSON'; return; }
    const candidate = typeof json.data === 'string' ? json.data : (json.data && json.data.token) || json.token;
    if (!candidate || candidate.split('.').length !== 3) { tr.ok = false; tr.note = '换发响应中未找到新 Token'; return; }
    if (candidate === cfg.token) { tr.ok = true; tr.note = '换发返回与当前 Token 相同，无需更新'; return; }
    // 验证候选 Token 能否真正用于日志/站点接口
    const u = new URL(cfg.sitesApiUrl);
    u.searchParams.set('page', '0'); u.searchParams.set('size', '1');
    u.searchParams.set('domain1', ''); u.searchParams.set('ruleEngine', ''); u.searchParams.set('isParse', '');
    const verify = await httpRequest('GET', u.toString(), null, { Authorization: 'Bearer ' + candidate });
    if (verify.status !== 200) {
      tr.ok = false;
      tr.note = '换发的 Token 无法访问日志接口（作用域不符，HTTP ' + verify.status + '），已忽略、保留原 Token';
      console.log('[token-refresh] ' + tr.note);
      return;
    }
    cfg.token = candidate; saveConfig(); refreshTokenInfo();
    tr.ok = true; tr.adopted++; tr.note = '已采纳换发的新 Token（累计 ' + tr.adopted + ' 次）';
    console.log('[token-refresh] 已自动换发并采纳新 Token, 到期: ' + new Date(state.tokenExp).toLocaleString());
    broadcast('token', { status: state.tokenStatus, exp: state.tokenExp });
  } catch (e) {
    tr.ok = false; tr.note = '换发失败: ' + e.message;
  }
}

// ---------- SSE ----------
const sseClients = new Set();
function broadcast(event, data) {
  const msg = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const res of sseClients) {
    try { res.write(msg); } catch (e) { sseClients.delete(res); }
  }
}
setInterval(() => { for (const res of sseClients) { try { res.write(':ping\n\n'); } catch (e) { sseClients.delete(res); } } }, 25000);

// ---------- 统计（SQL 聚合，全部参数绑定） ----------
function cstDayStart(ms) {
  const dayStr = new Date(ms + 8 * 3600e3).toISOString().slice(0, 10);
  return Date.parse(dayStr + 'T00:00:00Z') - 8 * 3600e3;
}
const GROUP_COLS = { host: 'host', attack_type: 'attack_type', level: 'level', action: 'action', src_ip: 'src_ip', method: 'method', status_code: 'status_code', spider: 'spider' };
const GROUP_TABLES = { logs: 'logs', visit_logs: 'visit_logs' };
function topGroup(col, since) {
  const c = GROUP_COLS[col]; // 列名仅限白名单取值
  const sql = `SELECT ${c} AS name, COUNT(*) AS count FROM logs WHERE at >= ? AND ${c} != '' GROUP BY ${c} ORDER BY count DESC LIMIT 8`;
  return db.prepare(sql).all(since);
}
// 筛选器选项聚合（表名/列名仅限白名单，时间条件参数绑定）
function facetGroup(table, col, since) {
  const t = GROUP_TABLES[table], c = GROUP_COLS[col];
  if (since == null) {
    return db.prepare(`SELECT ${c} AS name, COUNT(*) AS count FROM ${t} WHERE ${c} != '' GROUP BY ${c} ORDER BY count DESC`).all();
  }
  return db.prepare(`SELECT ${c} AS name, COUNT(*) AS count FROM ${t} WHERE ${c} != '' AND at >= ? GROUP BY ${c} ORDER BY count DESC`).all(since);
}
function monitoredHosts() {
  const m = new Set();
  for (const q of effectiveSites()) m.add(String(q).replace(/:\d+$/, ''));
  for (const s of state.siteInfo) m.add(s.host);
  return [...m];
}
const facetCache = new Map(); // 聚合结果短缓存（60秒），键为 接口:窗口
function buildStats(hours) {
  const now = Date.now();
  const since = now - hours * 3600e3;
  const bucketStart = now - Math.min(hours, 24) * 3600e3;
  const dayStart = cstDayStart(now);
  const today = db.prepare(
    `SELECT COUNT(*) AS count,
       SUM(CASE WHEN (action LIKE ? OR action LIKE ? OR action LIKE ?) THEN 1 ELSE 0 END) AS blocked,
       SUM(CASE WHEN (level LIKE ? OR level LIKE ?) AND level NOT LIKE ? THEN 1 ELSE 0 END) AS high
     FROM logs WHERE at >= ?`
  ).get('%阻断%', '%拦截%', '%拒绝%', '%严重%', '%高%', '%低%', dayStart);
  // 趋势桶补全为连续小时序列：无数据的小时计 0，时间轴不塌缩
  const fillHours = rows => {
    const map = new Map(rows.map(r => [Number(r.hb), r.count]));
    const startHb = Math.floor((bucketStart + 8 * 3600e3) / 3600e3);
    const endHb = Math.floor((now + 8 * 3600e3) / 3600e3);
    const out = [];
    for (let hb = startHb; hb <= endHb; hb++) out.push({ hb, count: map.get(hb) || 0 });
    return out;
  };
  const hbLabel = r => {
    const d = new Date(Number(r.hb) * 3600e3);
    return { hour: d.toISOString().slice(5, 10).replace('-', '/') + ' ' + d.toISOString().slice(11, 13) + '时', count: r.count };
  };
  const buckets = fillHours(db.prepare(
    'SELECT CAST((at + ?) / 3600000 AS INTEGER) AS hb, COUNT(*) AS count FROM logs WHERE at >= ? GROUP BY hb ORDER BY hb'
  ).all(8 * 3600e3, bucketStart)).map(hbLabel);
  // TOP3 受攻击站点各自的按小时趋势（host 参数绑定）
  const topTrends = topGroup('host', since).slice(0, 3).map(s => ({
    host: s.name, count: s.count,
    buckets: fillHours(db.prepare(
      'SELECT CAST((at + ?) / 3600000 AS INTEGER) AS hb, COUNT(*) AS count FROM logs WHERE at >= ? AND host = ? GROUP BY hb ORDER BY hb'
    ).all(8 * 3600e3, bucketStart, s.name)).map(hbLabel)
  }));
  return {
    window: hours,
    today: { count: today.count || 0, blocked: today.blocked || 0, high: today.high || 0 },
    total: stmtCountLogs.get().c,
    sites: topGroup('host', since),
    types: topGroup('attack_type', since),
    levels: topGroup('level', since),
    srcIps: topGroup('src_ip', since),
    buckets, topTrends
  };
}

// ---------- API ----------
function sendJson(res, code, obj) {
  const buf = Buffer.from(JSON.stringify(obj));
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': buf.length, 'Cache-Control': 'no-store' });
  res.end(buf);
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let buf = [], size = 0;
    req.on('data', c => { size += c.length; if (size > 1e6) { reject(new Error('body 过大')); req.destroy(); } else buf.push(c); });
    req.on('end', () => resolve(Buffer.concat(buf).toString('utf8')));
    req.on('error', reject);
  });
}

const LOG_LIST_SELECT = `SELECT id AS _id, at AS _at, ts AS _ts, host AS _host,
  start_time AS "startTime", site AS "destHostName", attack_type AS "name",
  level AS "dbappWAFEventLevel", level_id AS "dbappWAFEventLevelId", action AS "dvcAction",
  method AS "requestMethod", url AS "requestUrlAddress", status_code AS "responseCode",
  src_ip AS "srcAddress", geo_country AS "srcGeoCountry", geo_region AS "srcGeoRegion",
  geo_city AS "srcGeoCity", rule_id AS "ruelId"`;

// ---------- HTTP 服务 ----------
const server = http.createServer(async (req, res) => {
  const u = new URL(req.url, 'http://127.0.0.1');
  const pathname = u.pathname;
  try {
    if (req.method === 'GET' && (pathname === '/' || pathname === '/index.html')) {
      const html = fs.readFileSync(INDEX_HTML);
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
      return res.end(html);
    }
    if (pathname === '/favicon.ico') { res.writeHead(204); return res.end(); }

    if (pathname === '/api/state' && req.method === 'GET') {
      refreshTokenInfo();
      return sendJson(res, 200, {
        serverTime: Date.now(), startedAt: state.startedAt,
        nextPollAt: state.nextPollAt, lastPollAt: state.lastPollAt, polling: state.polling,
        lastGoodAt: state.lastGoodAt,
        lastError: state.lastError, logCount: stmtCountLogs.get().c,
        visitLogCount: cfg.visitLogs ? stmtCountVisits.get().c : 0,
        visitMaxLogs: cfg.visitMaxLogs,
        visitGap: state.visitGap, visitGapSites: state.visitGapSites.slice(0, 8),
        visitExclude: state.visitExclude,
        intervalMinutes: cfg.intervalMinutes,
        token: { status: state.tokenStatus, exp: state.tokenExp, sub: state.tokenSub },
        tokenRefresh: Object.assign({ enabled: !!cfg.tokenRefreshUrl, interval: cfg.tokenRefreshMinutes }, state.tokenRefresh),
        keepAlive: Object.assign({ enabled: !!cfg.tokenKeepAlive, interval: cfg.keepAliveSeconds }, state.keepAlive),
        sites: effectiveSites(), siteCount: effectiveSites().length,
        siteSource: state.manualSites.length ? 'manual' : 'auto',
        manualSitesCount: state.manualSites.length, autoSites: !!cfg.autoSites,
        siteInfo: state.siteInfo, lastSiteSyncAt: state.lastSiteSyncAt,
        siteTotals: state.siteTotals, pollLog: state.pollLog.slice(0, 10)
      });
    }

    if (pathname === '/api/logs' && req.method === 'GET') {
      const q = u.searchParams;
      const site = (q.get('site') || '').trim();
      const kw = (q.get('kw') || '').trim().toLowerCase();
      const level = q.get('level') || '';
      const action = q.get('action') || '';
      const status = (q.get('status') || '').trim();
      const hours = parseFloat(q.get('hours'));
      const page = Math.max(0, parseInt(q.get('page') || '0', 10) || 0);
      const size = Math.min(200, Math.max(10, parseInt(q.get('size') || '50', 10) || 50));
      const where = [], params = [];
      if (site && site !== 'all') { where.push('host = ?'); params.push(site); }
      if (level && level !== 'all') { where.push('level = ?'); params.push(level); }
      if (action && action !== 'all') { where.push('action = ?'); params.push(action); }
      if (status && status !== 'all') { where.push('status_code = ?'); params.push(status); }
      if (!isNaN(hours) && hours > 0) { where.push('at >= ?'); params.push(Date.now() - hours * 3600e3); }
      if (kw) {
        // 攻击日志量小（万级），LIKE 直查即可
        const like = `%${kw}%`;
        where.push('(src_ip LIKE ? OR url LIKE ? OR attack_type LIKE ? OR host LIKE ? OR geo_city LIKE ? OR geo_region LIKE ? OR raw LIKE ?)');
        params.push(like, like, like, like, like, like, like);
      }
      const whereSql = where.length ? 'WHERE ' + where.join(' AND ') : '';
      const total = db.prepare(`SELECT COUNT(*) AS c FROM logs ${whereSql}`).get(...params).c;
      const items = db.prepare(`${LOG_LIST_SELECT} FROM logs ${whereSql} ORDER BY at DESC, ts DESC LIMIT ? OFFSET ?`)
        .all(...params, size, page * size);
      return sendJson(res, 200, { total, totalCapped: total >= 10001, page, size, items });
    }

    if (pathname === '/api/log' && req.method === 'GET') {
      const id = u.searchParams.get('id') || '';
      const row = stmtGetRaw.get(id);
      if (!row) return sendJson(res, 404, { error: 'not found' });
      return sendJson(res, 200, JSON.parse(row.raw));
    }

    if (pathname === '/api/stats' && req.method === 'GET') {
      const hours = Math.min(168, Math.max(1, parseFloat(u.searchParams.get('hours') || '24') || 24));
      return sendJson(res, 200, buildStats(hours));
    }

    if (pathname === '/api/facets' && req.method === 'GET') {
      const h = parseFloat(u.searchParams.get('hours'));
      const since = (!isNaN(h) && h > 0) ? Date.now() - h * 3600e3 : null;
      const siteCounts = facetGroup('logs', 'host', since);
      const counts = new Map(siteCounts.map(x => [x.name, x.count]));
      // 全部监控站点（含窗口内零攻击的），端口变体归并为同一主机
      const sites = monitoredHosts().map(host => ({ host, count: counts.get(host) || 0 }))
        .sort((a, b) => b.count - a.count || a.host.localeCompare(b.host));
      return sendJson(res, 200, { sites, levels: facetGroup('logs', 'level', since), actions: facetGroup('logs', 'action', since), statusCodes: facetGroup('logs', 'status_code', since).slice(0, 20) });
    }

    if (pathname === '/api/visitlogs' && req.method === 'GET') {
      const q = u.searchParams;
      const site = (q.get('site') || '').trim();
      const kw = (q.get('kw') || '').trim().toLowerCase();
      const status = (q.get('status') || '').trim();
      const method = (q.get('method') || '').trim();
      const hours = parseFloat(q.get('hours'));
      const page = Math.max(0, parseInt(q.get('page') || '0', 10) || 0);
      const size = Math.min(200, Math.max(10, parseInt(q.get('size') || '50', 10) || 50));
      const where = [], params = [];
      if (site && site !== 'all') { where.push('host = ?'); params.push(site); }
      if (status && status !== 'all') { where.push('status_code = ?'); params.push(status); }
      if (method && method !== 'all') { where.push('method = ?'); params.push(method); }
      if (!isNaN(hours) && hours > 0) { where.push('at >= ?'); params.push(Date.now() - hours * 3600e3); }
      const sinceMs = (!isNaN(hours) && hours > 0) ? Date.now() - hours * 3600e3 : null;
      const ftsQuery = kw ? '"' + kw.replace(/"/g, ' ').trim() + '"*' : '';
      let ftsOk = false;
      if (kw) {
        try { db.prepare('SELECT rowid FROM visit_fts WHERE visit_fts MATCH ? LIMIT 1').get(ftsQuery); ftsOk = true; } catch (e) { console.log('[kw] FTS 探测失败: ' + e.message); }
      }
      const hasOtherFilters = (site && site !== 'all') || (status && status !== 'all') || (method && method !== 'all');
      const VISIT_SELECT = `SELECT id AS _id, at AS _at, host AS _host, start_time AS "startTime",
          site AS "destHostName", method AS "requestMethod", url AS "requestUrl", status_code AS "responseCode",
          src_ip AS "srcAddress", geo_country AS "srcGeoCountry", geo_region AS "srcGeoRegion", geo_city AS "srcGeoCity",
          referer AS "httpReferer", ua AS "requestClientApplication", os AS "clientOperatingSystem",
          bytes_in AS "bytesIn", bytes_out AS "bytesOut", rt AS "trTime", spider AS "isSpider"`;
      if (ftsOk && !hasOtherFilters) {
        // 纯关键字搜索快路径：强制 at 索引倒序扫描 + FTS 命中集探测，全程在 SQLite 内完成
        const ftsIn = 'rowid IN (SELECT rowid FROM visit_fts WHERE visit_fts MATCH ?)';
        const cntParams = sinceMs != null ? [sinceMs, ftsQuery] : [ftsQuery];
        const cntSql = sinceMs != null
          ? `SELECT COUNT(*) AS c FROM visit_logs INDEXED BY idx_vlogs_at WHERE at >= ? AND ${ftsIn}`
          : `SELECT COUNT(*) AS c FROM visit_logs INDEXED BY idx_vlogs_at WHERE ${ftsIn}`;
        const total = db.prepare(cntSql).get(...cntParams).c;
        const itemSql = sinceMs != null
          ? `${VISIT_SELECT} FROM visit_logs INDEXED BY idx_vlogs_at WHERE at >= ? AND ${ftsIn} ORDER BY at DESC LIMIT ? OFFSET ?`
          : `${VISIT_SELECT} FROM visit_logs INDEXED BY idx_vlogs_at WHERE ${ftsIn} ORDER BY at DESC LIMIT ? OFFSET ?`;
        const items = db.prepare(itemSql).all(...cntParams, size, page * size);
        return sendJson(res, 200, { total, totalCapped: total >= 10001, page, size, items });
      }
      let fromSql = 'visit_logs', joinParams = [];
      if (ftsOk) {
        // 关键字 + 其他筛选组合：FTS 驱动回表（其他索引筛选先行剪枝，量级可控）
        fromSql = '(SELECT rowid FROM visit_fts WHERE visit_fts MATCH ?) AS f CROSS JOIN visit_logs ON visit_logs.rowid = f.rowid';
        joinParams = [ftsQuery];
      } else if (kw) {
        const like = `%${kw}%`;
        where.push('(src_ip LIKE ? OR url LIKE ? OR host LIKE ? OR geo_city LIKE ? OR geo_region LIKE ? OR referer LIKE ? OR ua LIKE ?)');
        params.push(like, like, like, like, like, like, like);
      }
      const whereSql = where.length ? 'WHERE ' + where.join(' AND ') : '';
      const total = db.prepare(`SELECT COUNT(*) AS c FROM ${fromSql} ${whereSql}`).get(...joinParams, ...params).c;
      const items = db.prepare(`${VISIT_SELECT} FROM ${fromSql} ${whereSql} ORDER BY at DESC, ts DESC LIMIT ? OFFSET ?`)
        .all(...joinParams, ...params, size, page * size);
      return sendJson(res, 200, { total, totalCapped: total >= 10001, page, size, items });
    }

    if (pathname === '/api/visitlog' && req.method === 'GET') {
      const id = u.searchParams.get('id') || '';
      const row = stmtGetVisitRaw.get(id);
      if (!row) return sendJson(res, 404, { error: 'not found' });
      return sendJson(res, 200, JSON.parse(row.raw));
    }

    if (pathname === '/api/visitstats' && req.method === 'GET') {
      const hours = Math.min(168, Math.max(1, parseFloat(u.searchParams.get('hours') || '24') || 24));
      const now = Date.now();
      const since = now - hours * 3600e3;
      const bucketStart = now - Math.min(hours, 24) * 3600e3;
      const dayStart = cstDayStart(now);
      const hbSince = Math.floor((since + 8 * 3600e3) / 3600e3);
      const hbBucket = Math.floor((bucketStart + 8 * 3600e3) / 3600e3);
      const hbToday = Math.floor((dayStart + 8 * 3600e3) / 3600e3);
      const hbLabel = r => {
        const d = new Date(Number(r.hb) * 3600e3);
        return { hour: d.toISOString().slice(5, 10).replace('-', '/') + ' ' + d.toISOString().slice(11, 13) + '时', count: r.count };
      };
      // 补全为连续小时序列（无数据小时计 0）
      const fillHours = rows => {
        const map = new Map(rows.map(r => [Number(r.hb), r.count]));
        const endHb = Math.floor((now + 8 * 3600e3) / 3600e3);
        const out = [];
        for (let hb = hbBucket; hb <= endHb; hb++) out.push({ hb, count: map.get(hb) || 0 });
        return out;
      };
      // 趋势/站点/今日数使用小时聚合表（不受明细容量裁剪影响）
      const today = db.prepare('SELECT COALESCE(SUM(count),0) AS c FROM visit_hourly WHERE hb >= ?').get(hbToday).c;
      const sites = db.prepare('SELECT host AS name, SUM(count) AS count FROM visit_hourly WHERE hb >= ? GROUP BY host ORDER BY 2 DESC LIMIT 8').all(hbSince);
      const buckets = fillHours(db.prepare('SELECT hb, SUM(count) AS count FROM visit_hourly WHERE hb >= ? GROUP BY hb ORDER BY hb').all(hbBucket)).map(hbLabel);
      const topTrends = sites.slice(0, 3).map(s => ({
        host: s.name, count: s.count,
        buckets: fillHours(db.prepare('SELECT hb, count FROM visit_hourly WHERE host = ? AND hb >= ? ORDER BY hb').all(s.name, hbBucket)).map(hbLabel)
      }));
      const statusCodes = facetGroup('visit_logs', 'status_code', since).slice(0, 8);
      return sendJson(res, 200, {
        window: hours, today: { count: today },
        total: stmtCountVisits.get().c,
        sites, statusCodes, methods: facetGroup('visit_logs', 'method', since).slice(0, 8),
        srcIps: facetGroup('visit_logs', 'src_ip', since).slice(0, 8),
        spiders: facetGroup('visit_logs', 'spider', since).slice(0, 4),
        buckets, topTrends
      });
    }

    if (pathname === '/api/visitfacets' && req.method === 'GET') {
      const h = parseFloat(u.searchParams.get('hours'));
      const since = (!isNaN(h) && h > 0) ? Date.now() - h * 3600e3 : null;
      // 60 秒结果缓存：筛选选项变化缓慢，避免每次切页都全量聚合
      const cacheKey = 'visitfacets:' + (since == null ? 'all' : String(h));
      const cached = facetCache.get(cacheKey);
      if (cached && Date.now() - cached.at < 120000) return sendJson(res, 200, cached.data);
      // 筛选页下拉统一为「可查明细」口径（与列表一致）；真实流量口径在访问总览（聚合表）
      const siteCounts = facetGroup('visit_logs', 'host', since);
      const counts = new Map(siteCounts.map(x => [x.name, x.count]));
      const sites = monitoredHosts().map(host => ({ host, count: counts.get(host) || 0 }))
        .sort((a, b) => b.count - a.count || a.host.localeCompare(b.host));
      const result = {
        sites,
        statusCodes: facetGroup('visit_logs', 'status_code', since).slice(0, 20),
        methods: facetGroup('visit_logs', 'method', since)
      };
      facetCache.set(cacheKey, { at: Date.now(), data: result });
      return sendJson(res, 200, result);
    }

    if (pathname === '/api/stream' && req.method === 'GET') {
      res.writeHead(200, {
        'Content-Type': 'text/event-stream', 'Cache-Control': 'no-store',
        'Connection': 'keep-alive', 'X-Accel-Buffering': 'no'
      });
      res.write('retry: 5000\n\n');
      res.write(`event: hello\ndata: ${JSON.stringify({ logCount: stmtCountLogs.get().c })}\n\n`);
      sseClients.add(res);
      req.on('close', () => sseClients.delete(res));
      return;
    }

    if (pathname === '/api/token' && req.method === 'GET') {
      // 本地单机工具：返回当前 Token 供页面展示/复制
      return sendJson(res, 200, { token: cfg.token || '', status: state.tokenStatus, exp: state.tokenExp });
    }

    if (pathname === '/api/token' && req.method === 'POST') {
      const body = JSON.parse(await readBody(req) || '{}');
      const token = String(body.token || '').trim();
      if (!token || token.split('.').length !== 3) return sendJson(res, 400, { error: 'token 格式不正确' });
      cfg.token = token; saveConfig(); refreshTokenInfo();
      state.lastSiteSyncAt = 0; // Token 更新后强制重新同步站点列表
      console.log('[token] 已更新, 状态:', state.tokenStatus);
      broadcast('token', { status: state.tokenStatus, exp: state.tokenExp });
      pollOnce('token-updated').catch(() => {});
      return sendJson(res, 200, { ok: true, status: state.tokenStatus, exp: state.tokenExp });
    }

    if (pathname === '/api/interval' && req.method === 'POST') {
      const body = JSON.parse(await readBody(req) || '{}');
      const minutes = parseFloat(body.minutes);
      const ALLOWED = [0.5, 1, 5, 10]; // 30秒 / 1分钟 / 5分钟 / 10分钟
      if (!ALLOWED.includes(minutes)) return sendJson(res, 400, { error: '仅支持 30秒 / 1分钟 / 5分钟 / 10分钟' });
      cfg.intervalMinutes = minutes;
      saveConfig();
      scheduleNext(); // 按新间隔重新排期
      console.log(`[interval] 轮询间隔已设为 ${minutes < 1 ? minutes * 60 + ' 秒' : minutes + ' 分钟'}`);
      broadcast('interval', { intervalMinutes: minutes, nextPollAt: state.nextPollAt });
      return sendJson(res, 200, { ok: true, intervalMinutes: minutes, nextPollAt: state.nextPollAt });
    }

    if (pathname === '/api/blacklist' && req.method === 'POST') {
      const body = JSON.parse(await readBody(req) || '{}');
      const ips = String(body.ip || '').split(/[\s,;，；]+/).map(s => s.trim()).filter(Boolean);
      const expireDays = Math.min(365, Math.max(1, parseInt(body.expireDays || '30', 10) || 30));
      if (!ips.length) return sendJson(res, 400, { error: '请填写 IP' });
      // 仅允许 IPv4 / IPv6 / 对应 CIDR 网段，防注入到 ACL 规则
      const validIpOrCidr = s => {
        const i = s.indexOf('/');
        if (i === -1) return net.isIP(s) !== 0;
        const base = s.slice(0, i), plen = s.slice(i + 1);
        if (!/^\d{1,3}$/.test(plen)) return false;
        const v = net.isIP(base);
        return v === 4 ? +plen <= 32 : (v === 6 ? +plen <= 128 : false);
      };
      for (const ip of ips) {
        if (!validIpOrCidr(ip)) return sendJson(res, 400, { error: 'IP 格式不正确: ' + ip });
      }
      if (!state.siteIdByKey || !state.siteIdByKey.size) {
        return sendJson(res, 503, { error: '站点 ID 尚未同步完成，请稍后重试（约 1 分钟）' });
      }
      const domains = effectiveSites();
      const siteIds = domains.map(k => state.siteIdByKey.get(k)).filter(Boolean);
      const results = [];
      for (const ip of ips) {
        const payload = {
          action: 'block', desc: String(body.desc || ip).slice(0, 200),
          expire: expireDays * 86400,
          domains, siteIds, level: 'site',
          match: { domain: [], path: [], sip: [ip], ipStr: ip },
          priority: 'fast', label: []
        };
        try {
          const r = await httpRequest('POST', cfg.aclCreateUrl, payload);
          let j = null; try { j = JSON.parse(r.text); } catch (e) {}
          const ok = r.status === 200 && j && (j.success === true || j.errorCode === 0);
          results.push({ ip, ok, detail: ok ? '已封禁' : (j && j.message) || ('HTTP ' + r.status) });
          console.log(`[blacklist] ${ip} ${ok ? '已加入黑名单' : '失败: ' + ((j && j.message) || r.status)}`);
        } catch (e) {
          results.push({ ip, ok: false, detail: e.message });
        }
      }
      const okCount = results.filter(r => r.ok).length;
      return sendJson(res, 200, { ok: okCount === results.length, okCount, total: results.length, results });
    }

    if (pathname === '/api/blacklist/list' && req.method === 'GET') {
      const u2 = new URL(cfg.aclSearchUrl);
      u2.searchParams.set('page', '0');
      u2.searchParams.set('size', '500');
      const r = await httpRequest('GET', u2.toString(), null);
      if (r.status !== 200) return sendJson(res, 502, { error: '平台接口 HTTP ' + r.status });
      let j; try { j = JSON.parse(r.text); } catch (e) { return sendJson(res, 502, { error: '平台响应异常' }); }
      const arr = Array.isArray(j.data) ? j.data : [];
      const items = arr.map(x => ({
        uuid: x.uuid,
        ips: ((x.match && x.match.sip) || []).join(', '),
        action: x.action,
        desc: x.desc || x.systemDesc || '',
        type: String(x.type == null ? '' : x.type),
        endTime: x.endTime ? x.endTime * 1000 : null,
        createTime: x.createTime ? (typeof x.createTime === 'number' ? (x.createTime > 1e12 ? x.createTime : x.createTime * 1000) : parseCst(x.createTime)) : null,
        expireDays: x.expire ? Math.round(x.expire / 86400) : null,
        domains: ((x.domains && x.domains.length ? x.domains : (x.match && x.match.domain)) || []).length,
        user: x.lastModifiedUser || '',
        priority: x.priority || ''
      }));
      return sendJson(res, 200, { total: items.length, items, fetchedAt: Date.now() });
    }

    if (pathname === '/api/blacklist/remove' && req.method === 'POST') {
      const body = JSON.parse(await readBody(req) || '{}');
      const uuids = (Array.isArray(body.uuids) && body.uuids.length) ? body.uuids.map(String)
        : (body.uuid ? [String(body.uuid)] : []);
      if (!uuids.length) return sendJson(res, 400, { error: '缺少规则 uuid' });
      // 平台官方删除接口：POST acl/batch {"uuids":[...]}
      const r = await httpRequest('POST', cfg.aclBatchUrl, { uuids });
      let j = null; try { j = JSON.parse(r.text); } catch (e) {}
      const ok = r.status === 200 && (!j || j.success === true || j.errorCode === 0);
      console.log(`[blacklist] 删除规则 ${uuids.join(',')} ${ok ? '成功' : '失败: ' + ((j && j.message) || r.status)}`);
      return sendJson(res, ok ? 200 : 502, { ok, detail: ok ? '已删除' : ((j && j.message) || 'HTTP ' + r.status) });
    }

    if (pathname === '/api/poll' && req.method === 'POST') {
      if (state.polling) return sendJson(res, 409, { error: '轮询正在进行中' });
      const last = state.pollLog[0];
      if (last && Date.now() - last.at < 60 * 1000) return sendJson(res, 429, { error: '请稍候（1 分钟内已查询过）' });
      pollOnce('manual').catch(() => {});
      scheduleNext();
      return sendJson(res, 200, { ok: true });
    }

    sendJson(res, 404, { error: 'not found' });
  } catch (e) {
    sendJson(res, 500, { error: e.message });
  }
});

// ---------- 启动 ----------
loadManualSites();
// 恢复上次成功采集时刻（用于停机/断档后的补采窗口计算）
try { state.lastGoodAt = Number((stmtGetMeta.get('lastGoodAt') || {}).v) || null; } catch (e) {}
if (state.lastGoodAt && Date.now() - state.lastGoodAt > cfg.lookbackMinutes * 60e3) {
  console.log(`[poll] 距上次成功采集已 ${Math.round((Date.now() - state.lastGoodAt) / 60000)} 分钟，启动后将按补采窗口回拉（上限 ${cfg.catchupHours} 小时）`);
}
if (cfg.tokenKeepAlive) {
  state.keepAlive.enabled = true;
  setTimeout(keepAliveOnce, 3000); // 启动后先探一次
  setInterval(keepAliveOnce, cfg.keepAliveSeconds * 1000);
}
if (cfg.tokenRefreshUrl) {
  state.tokenRefresh.enabled = true;
  setTimeout(refreshTokenOnce, 8000); // 启动后先换发一次
  setInterval(refreshTokenOnce, cfg.tokenRefreshMinutes * 60 * 1000);
}
server.listen(cfg.port, '127.0.0.1', () => {
  const mode = state.manualSites.length ? `手动 sites.txt（${state.manualSites.length} 个）` : '自动同步账号全部站点';
  console.log(`======================================================`);
  console.log(` WAF 攻击日志监控已启动`);
  console.log(` 控制台:   http://127.0.0.1:${cfg.port}`);
  console.log(` 数据库:   ${DB_PATH}（${stmtCountLogs.get().c} 条日志）`);
  console.log(` 轮询间隔: 每 ${cfg.intervalMinutes} 分钟, 站点模式: ${mode}`);
  console.log(` Token 状态: ${state.tokenStatus}${state.tokenExp ? ', 到期: ' + new Date(state.tokenExp).toLocaleString() : ''}`);
  console.log(`======================================================`);
  pollOnce('initial').then(scheduleNext).catch(e => { console.error('[poll] 启动轮询失败:', e.message); scheduleNext(); });
});
