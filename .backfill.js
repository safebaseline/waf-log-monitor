'use strict';
/**
 * 一次性历史回填（独立脚本，不改动 server.js）
 * 拉取 2026-10-15 00:00 ~ 2026-10-19 00:00（东八区）的攻击/访问日志写入 data/waflogs.db
 * - 去重逻辑与 server.js 完全一致（INSERT OR IGNORE），可安全重复执行/断点续跑
 * - 访问日志同步累加 visit_hourly 小时聚合（仅新增行）
 * - 限速：串行请求，每请求间隔 REQ_MS 毫秒
 * - Token 失效(401/403)时重读 config.json（服务端每10分钟自动换发并写回）
 * - 进度记录于 .backfill-progress.json，重跑自动跳过已完成站点
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { DatabaseSync } = require('node:sqlite');

const ROOT = __dirname;
const T0 = Date.parse('2026-10-15T00:00:00+08:00') / 1000;
const T1 = Date.parse('2026-10-19T00:00:00+08:00') / 1000;
const REQ_MS = 400;            // 请求间隔（毫秒）≈ 2.5 请求/秒
const ATTACK_PAGE_CAP = 500;   // 单站攻击页数安全上限
const VISIT_PAGE_CAP = 5000;   // 单站访问页数安全上限
const PROGRESS_FILE = path.join(ROOT, '.backfill-progress.json');

const sleep = ms => new Promise(r => setTimeout(r, ms));
const sha256 = s => crypto.createHash('sha256').update(s).digest('hex');
const parseCst = s => { const t = Date.parse(String(s).replace(' ', 'T') + '+08:00'); return isNaN(t) ? 0 : t; };
const readToken = () => JSON.parse(fs.readFileSync(path.join(ROOT, 'config.json'), 'utf8')).token;
const cfg = JSON.parse(fs.readFileSync(path.join(ROOT, 'config.json'), 'utf8'));

let progress = { attack: [], visit: [] };
try { progress = JSON.parse(fs.readFileSync(PROGRESS_FILE, 'utf8')); } catch (e) {}

const db = new DatabaseSync(path.join(ROOT, 'data', 'waflogs.db'));
db.prepare('PRAGMA busy_timeout = 15000').run();

// 与 server.js 一致的写入语句（全部参数绑定）
const txBegin = db.prepare('BEGIN'); const txCommit = db.prepare('COMMIT'); const txRollback = db.prepare('ROLLBACK');
const insLog = db.prepare('INSERT OR IGNORE INTO logs (id, at, ts, host, site, attack_type, level, level_id, action, method, url, status_code, rule_id, src_ip, geo_country, geo_region, geo_city, start_time, raw) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)');
const insVis = db.prepare('INSERT OR IGNORE INTO visit_logs (id, at, ts, host, site, method, url, status_code, src_ip, geo_country, geo_region, geo_city, referer, ua, os, browser, spider, bytes_in, bytes_out, rt, start_time, raw) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)');
const upHourly = db.prepare('INSERT INTO visit_hourly (host, hb, count) VALUES (?, ?, ?) ON CONFLICT (host, hb) DO UPDATE SET count = count + excluded.count');
const cntLogs = db.prepare('SELECT COUNT(*) AS c FROM logs');
const cntVis = db.prepare('SELECT COUNT(*) AS c FROM visit_logs');

function normAttack(e, site) {
  const ts = e.etlProcessTime || parseCst(e.startTime) || parseCst(e.collectorReceiptTime) || 0;
  const at = parseCst(e.startTime) || ts;
  const host = String(e.destHostName || site || '').replace(/:\d+$/, '');
  return {
    id: sha256([e.startTime, e.srcAddress, e.srcPort, e.requestUrlAddress, e.name, e.ruelId, host].join('|')),
    at, ts, host, site: e.destHostName || site || '',
    attack_type: e.name || '', level: e.dbappWAFEventLevel || '', level_id: String(e.dbappWAFEventLevelId == null ? '' : e.dbappWAFEventLevelId),
    action: e.dvcAction || '', method: e.requestMethod || '', url: e.requestUrlAddress || '',
    status_code: String(e.responseCode == null ? '' : e.responseCode), rule_id: String(e.ruelId == null ? '' : e.ruelId),
    src_ip: e.srcAddress || '', geo_country: e.srcGeoCountry || '', geo_region: e.srcGeoRegion || '',
    geo_city: e.srcGeoCity || '', start_time: e.startTime || '', raw: JSON.stringify(e)
  };
}
function normVisit(e, site) {
  const ts = e.etlProcessTime || parseCst(e.startTime) || parseCst(e.collectorReceiptTime) || 0;
  const at = parseCst(e.startTime) || ts;
  const host = String(e.destHostName || site || '').replace(/:\d+$/, '');
  const reqId = (String(e.rawEvent || '').match(/reqId=([0-9a-fA-F]+)/) || [])[1];
  return {
    id: reqId ? 'r:' + reqId : sha256([e.startTime, e.srcAddress, e.srcPort, e.requestUrl, e.requestMethod, host].join('|')),
    at, ts, host, site: e.destHostName || site || '',
    method: e.requestMethod || '', url: e.requestUrl || '', status_code: String(e.responseCode == null ? '' : e.responseCode),
    src_ip: e.srcAddress || '', geo_country: e.srcGeoCountry || '', geo_region: e.srcGeoRegion || '', geo_city: e.srcGeoCity || '',
    referer: e.httpReferer || '', ua: e.requestClientApplication || e.accessAgent || '', os: e.clientOperatingSystem || '',
    browser: e.browser_version || '', spider: String(e.isSpider == null ? '' : e.isSpider),
    bytes_in: Number(e.bytesIn) || 0, bytes_out: Number(e.bytesOut) || 0, rt: Number(e.trTime) || 0,
    start_time: e.startTime || '', raw: JSON.stringify(e)
  };
}

async function api(url, body) {
  for (let attempt = 0; attempt < 20; attempt++) {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json;charset=utf-8', 'Accept': 'application/json, text/plain, */*', 'Authorization': 'Bearer ' + readToken() },
      body: JSON.stringify(body)
    });
    if (res.status === 401 || res.status === 403) { console.log('  [token] 失效，等待服务端自动换发后重试…'); await sleep(30000); continue; }
    if (res.status !== 200) throw new Error('HTTP ' + res.status);
    const j = await res.json();
    if (!j.success && j.errorCode !== 0) {
      if (j.errorCode === 50002) return { empty: true }; // 查询结果为空
      throw new Error('接口错误: ' + (j.message || j.errorCode));
    }
    return j;
  }
  throw new Error('Token 持续失效，中止');
}

async function backfill(kind) {
  const url = kind === 'attack' ? cfg.apiUrl : cfg.visitApiUrl;
  const done = progress[kind] || [];
  const sites = cfg.sites.filter(s => !done.includes(s));
  const before = kind === 'attack' ? cntLogs.get().c : cntVis.get().c;
  console.log(`[${kind}] 共 ${cfg.sites.length} 站，已完成 ${done.length}，本轮 ${sites.length}，库内起始 ${before} 条`);
  for (const site of sites) {
    let siteAdded = 0;
    // 访问日志接口单次查询跨度限 24 小时：按天分窗回填
    const windows = [];
    if (kind === 'visit') {
      for (let t = T0; t < T1; t += 86400) windows.push([t, Math.min(t + 86400, T1)]);
    } else windows.push([T0, T1]);
    for (const [w0, w1] of windows) {
      let page = 0, fetched = 0, added = 0, empty = false;
      const cap = kind === 'attack' ? ATTACK_PAGE_CAP : VISIT_PAGE_CAP;
      while (page < cap) {
        const body = {
          destHostName: site, requestUrl: '', srcAddress: null,
          responseCode: kind === 'visit' ? null : '', requestMethod: '',
          startTime: w0, endTime: w1, country: '', srcPrivince: null, srcCity: null,
          page, size: 100
        };
      const j = await api(url, body);
      await sleep(REQ_MS);
      const d = j.empty ? { page: { content: [] }, total: 0 } : (j.data || {});
      const pg = d.page || {};
      const content = Array.isArray(pg.content) ? pg.content : [];
      const total = d.total || 0;
      if (content.length) {
        txBegin.run();
        try {
          for (const raw of content) {
            if (kind === 'attack') {
              const e = normAttack(raw, site);
              if (insLog.run(e.id, e.at, e.ts, e.host, e.site, e.attack_type, e.level, e.level_id, e.action, e.method, e.url, e.status_code, e.rule_id, e.src_ip, e.geo_country, e.geo_region, e.geo_city, e.start_time, e.raw).changes) added++;
            } else {
              const e = normVisit(raw, site);
              if (insVis.run(e.id, e.at, e.ts, e.host, e.site, e.method, e.url, e.status_code, e.src_ip, e.geo_country, e.geo_region, e.geo_city, e.referer, e.ua, e.os, e.browser, e.spider, e.bytes_in, e.bytes_out, e.rt, e.start_time, e.raw).changes) {
                added++;
                upHourly.run(e.host, Math.floor((e.at + 8 * 3600e3) / 3600e3), 1);
              }
            }
          }
          txCommit.run();
        } catch (er) { txRollback.run(); throw er; }
      }
      fetched += content.length;
      if (page % 20 === 0) console.log(`  [${kind}] ${site} 窗口${new Date(w0 * 1000).toLocaleDateString()} 第${page}页 累计新增${added}/${total}`);
      if (!content.length || pg.last !== false || (total && fetched >= total)) { empty = true; break; }
      page++;
      }
      siteAdded += added;
    }
    done.push(site);
    progress[kind] = done;
    try { fs.writeFileSync(PROGRESS_FILE, JSON.stringify(progress)); } catch (e) {}
    console.log(`[${kind}] ${site} 完成：+${siteAdded} 条`);
  }
  const after = kind === 'attack' ? cntLogs.get().c : cntVis.get().c;
  console.log(`[${kind}] 全部完成：库内 ${before} → ${after} 条（净增 ${after - before}）`);
}

(async () => {
  console.log(`历史回填窗口: ${new Date(T0 * 1000).toLocaleString()} ~ ${new Date(T1 * 1000).toLocaleString()}`);
  await backfill('attack');
  await backfill('visit');
  db.close();
  console.log('回填结束。');
})().catch(e => { console.error('回填失败:', e.message); process.exit(1); });
