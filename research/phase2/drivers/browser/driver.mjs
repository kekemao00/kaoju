#!/usr/bin/env node
// Playwright 驱动的浏览器（列 chromium-pw、firefox-pw）。
//
// 用法：
//     driver.mjs --browser chromium|firefox <用例.json> <结果.json>
//     driver.mjs --browser chromium|firefox --versions
//
// 约定见 research/phase2/PROTOCOL.md 的“驱动”一节，惯用写法和出处见同目录的 NOTES.md。
// 平时由 run.sh 启动（它负责让 require('playwright') 找得到模块、让 Playwright 找得到浏览器）。
//
// 做法（实际用的写法原样写进结果的 config 和 notes）：
//
// - 一个用例一个浏览器进程。只有一个用户（或没有用户）时：launch({proxy}) 一次，newContext() 一次，
//   newPage() 一次，整个用例都用这一个页面。两个用户时：launch({proxy: {server}})，
//   每个用户一个 newContext({proxy: {server, username, password}})，各一个页面。
// - GET 是顶层导航 page.goto(url)，不改 waitUntil 的默认值。POST、parallel、ws 从同源的 /page 页面里
//   用 fetch、WebSocket 发起；页面不在那个 /page 上时先导航过去（这次导航的 k 是 用例.pre）。
// - 代理凭据只用 proxy 选项的 username、password 两个字段。SOCKS5 一律写成 socks5://。
// - 信任测试 CA：Chromium 靠 HOME 下的 NSS 数据库（run.py 已建好）；Firefox 靠现建的 profile 目录里的 cert9.db。
//   任何地方都不关闭证书校验。
// - default_text：成功时是状态行、响应头、正文前 4 KiB；失败时是异常的 name 和 message，原样。
//   驱动自己不往 default_text 里加说明文字（矩阵要在里面找关键词）。
// - extra_text：page.on('requestfailed') 给的 errorText；Chromium 另有 NetLog（启动参数 --log-net-log）里
//   CONNECT 的请求行、响应头和 SOCKS 的事件。两者都按时间窗归给各步。
//
// 任何异常都落进结果文件，进程以 0 退出。

import { createRequire } from 'node:module';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

const require = createRequire(import.meta.url);

const BODY_HEAD = 4096;
const VARIANTS = { chromium: 'chromium-pw', firefox: 'firefox-pw' };

const EXTRA_HOW_CHROMIUM =
  "两样，都要主动打开：(1) Playwright 的 page.on('requestfailed') 事件里的 request.failure().errorText；" +
  '(2) Chromium 的 NetLog：启动参数 --log-net-log=<文件>（经 Playwright 的 launch({args}) 传入，出处是 Chromium 的 net/docs/net-log.md，' +
  '不在 Playwright 的文档里），浏览器关闭后读文件，取 CONNECT 的请求行、CONNECT 响应的状态行和响应头、SOCKS 的事件。' +
  '两样都按发生时刻落在哪一步的时间窗里归属（并发的子步骤共用同一个时间窗）。';
const EXTRA_HOW_FIREFOX =
  "Playwright 的 page.on('requestfailed') 事件里的 request.failure().errorText，按发生时刻落在哪一步的时间窗里归属" +
  '（并发的子步骤共用同一个时间窗）。Firefox 的 MOZ_LOG 不在 Playwright 的文档里，没有采用。';

function sha256(buf) {
  return createHash('sha256').update(buf).digest('hex');
}

function errText(e) {
  if (e && typeof e === 'object' && 'message' in e) return `${e.name || 'Error'}: ${e.message}`;
  return String(e);
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

// 给一个不会自己超时的操作加上限；超时抛出的错误带 kaojuTimeout 标记。
function withTimeout(promise, ms, what) {
  let timer;
  const t = new Promise((_, rej) => {
    timer = setTimeout(() => {
      const e = new Error(`驱动等了 ${ms} 毫秒，${what}没有结束`);
      e.name = 'KaojuDriverTimeout';
      e.kaojuTimeout = true;
      rej(e);
    }, ms);
  });
  return Promise.race([promise, t]).finally(() => clearTimeout(timer));
}

function loadPlaywright() {
  const pw = require('playwright');
  let version = null;
  try {
    version = require('playwright/package.json').version;
  } catch {
    try {
      version = require('playwright-core/package.json').version;
    } catch {
      /* 读不到就留空 */
    }
  }
  return { pw, version };
}

// 浏览器进程实际的可执行文件：在 /proc 里找本进程的子进程。只留最后三段路径，不带本机的安装前缀。
function childExecutables() {
  const out = [];
  try {
    for (const d of fs.readdirSync('/proc')) {
      if (!/^\d+$/.test(d)) continue;
      try {
        const stat = fs.readFileSync(`/proc/${d}/stat`, 'utf8');
        const rest = stat.slice(stat.lastIndexOf(')') + 2).split(' ');
        if (Number(rest[1]) !== process.pid) continue;
        const exe = fs.readlinkSync(`/proc/${d}/exe`);
        out.push(exe.split('/').slice(-3).join('/'));
      } catch {
        /* 进程已经退出，或读不了 */
      }
    }
  } catch {
    /* 没有 /proc */
  }
  return [...new Set(out)].sort();
}

function proxyServer(px) {
  if (px.scheme === 'http') return { server: `http://${px.host}:${px.port}`, note: null };
  if (px.scheme === 'socks5' || px.scheme === 'socks5h') {
    return {
      server: `socks5://${px.host}:${px.port}`,
      note:
        `用例写的是 ${px.scheme}://；Playwright 的 proxy.server 只有 socks5:// 这一种写法` +
        '（域名交不交给代理由浏览器自己决定，没有开关），所以写成 socks5://',
    };
  }
  throw new Error(`不认识的代理写法：${px.scheme}`);
}

function flatSteps(steps, out = []) {
  for (const st of steps || []) {
    out.push(st);
    if (st.op === 'parallel') flatSteps(st.steps, out);
  }
  return out;
}

function userKey(u) {
  return u === null || u === undefined ? 'none' : String(u);
}

// ---------- 页面里执行的函数（序列化后送进浏览器） ----------

async function inPageFetch(reqs) {
  const toB64 = (buf) => {
    const u8 = new Uint8Array(buf);
    let s = '';
    for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000));
    return btoa(s);
  };
  return Promise.all(
    reqs.map(async (q) => {
      const t0 = Date.now();
      const init = { method: q.method };
      if (q.b64 !== null) {
        init.body = Uint8Array.from(atob(q.b64), (c) => c.charCodeAt(0));
        init.headers = { 'Content-Type': 'application/octet-stream' };
      }
      if (q.method === 'GET') delete init.method;
      try {
        const r = await fetch(q.url, init);
        const buf = await r.arrayBuffer();
        return {
          ok: true,
          status: r.status,
          statusText: r.statusText,
          headers: [...r.headers],
          bodyB64: toB64(buf),
          url: r.url,
          redirected: r.redirected,
          ms: Date.now() - t0,
        };
      } catch (e) {
        return { ok: false, error: `${e && e.name}: ${e && e.message}`, ms: Date.now() - t0 };
      }
    }),
  );
}

function inPageWebSocket({ url, waitMs }) {
  return new Promise((resolve) => {
    const t0 = Date.now();
    const events = [];
    let opened = false;
    let s;
    const done = () => resolve({ opened, events, ms: Date.now() - t0 });
    try {
      s = new WebSocket(url);
    } catch (e) {
      events.push(`${e && e.name}: ${e && e.message}`);
      done();
      return;
    }
    const timer = setTimeout(() => {
      events.push(`（${waitMs} 毫秒内没有等到 close 事件）`);
      done();
    }, waitMs);
    s.onopen = () => {
      opened = true;
      events.push('open');
    };
    s.onerror = () => events.push('error');
    s.onmessage = (m) => events.push(`message ${typeof m.data === 'string' ? m.data.length : '(binary)'}`);
    s.onclose = (e) => {
      events.push(`close code=${e.code} reason=${JSON.stringify(e.reason)} wasClean=${e.wasClean}`);
      clearTimeout(timer);
      done();
    };
  });
}

// ---------- 文字的拼法 ----------

function responseText(status, statusText, headerPairs, body) {
  const lines = [`HTTP ${status} ${statusText}`.trimEnd()];
  for (const [k, v] of headerPairs) lines.push(`${k}: ${v}`);
  lines.push('');
  lines.push(body === null ? '' : body.subarray(0, BODY_HEAD).toString('utf8'));
  return lines.join('\n');
}

// ---------- NetLog ----------

function parseNetLog(file) {
  let text;
  try {
    text = fs.readFileSync(file, 'utf8');
  } catch (e) {
    return { error: `读不到 NetLog 文件：${e.code || e.message}`, events: [] };
  }
  let doc = null;
  const tries = [text, text.replace(/,\s*$/, '') + ']}', text.replace(/,\s*$/, '') + '}'];
  for (const t of tries) {
    try {
      doc = JSON.parse(t);
      break;
    } catch {
      /* 试下一种补法 */
    }
  }
  if (!doc || !doc.constants || !Array.isArray(doc.events)) {
    return { error: `NetLog 文件解析不了（${text.length} 字节）`, events: [] };
  }
  const typeName = {};
  for (const [name, num] of Object.entries(doc.constants.logEventTypes || {})) typeName[num] = name;
  const phaseName = {};
  for (const [name, num] of Object.entries(doc.constants.logEventPhase || {})) phaseName[num] = name;
  const offset = Number(doc.constants.timeTickOffset);
  const out = [];
  for (const ev of doc.events) {
    const name = typeName[ev.type];
    if (!name) continue;
    const tunnel =
      name === 'HTTP_TRANSACTION_SEND_TUNNEL_HEADERS' || name === 'HTTP_TRANSACTION_READ_TUNNEL_RESPONSE_HEADERS';
    const socks = name.startsWith('SOCKS');
    if (!tunnel && !socks) continue;
    if (socks && !ev.params && phaseName[ev.phase] !== 'PHASE_NONE') continue; // 没有内容的阶段起止不留
    out.push({
      t: Number(ev.time) + offset,
      source: ev.source ? ev.source.id : null,
      name,
      phase: phaseName[ev.phase] || String(ev.phase),
      params: ev.params || null,
    });
  }
  out.sort((a, b) => a.t - b.t);
  return { error: null, events: out };
}

function netLogLines(ev, t0) {
  const head = `[+${Math.round(ev.t - t0)}ms 源 ${ev.source}] ${ev.name}`;
  const p = ev.params;
  if (!p) return [head];
  const lines = [head];
  if (typeof p.line === 'string') lines.push('  ' + p.line.trimEnd());
  if (Array.isArray(p.headers)) for (const h of p.headers) lines.push('  ' + String(h).trimEnd());
  const rest = {};
  for (const [k, v] of Object.entries(p)) if (k !== 'line' && k !== 'headers') rest[k] = v;
  if (Object.keys(rest).length) lines.push('  ' + JSON.stringify(rest));
  return lines;
}

// ---------- 一个用例 ----------

class Runner {
  constructor(browserName, kase, result) {
    this.browserName = browserName;
    this.kase = kase;
    this.result = result;
    this.timeoutMs = (kase.timeout_s || 15) * 1000;
    this.browser = null;
    this.persistent = null; // Firefox：launchPersistentContext 返回的上下文
    this.slots = new Map(); // 用户 → {context, page}
    this.failures = []; // requestfailed 事件
    this.windows = []; // {id, t0, shared}：每一步的开始时刻
    this.netlogPath = null;
    this.closedAt = null;
  }

  note(s) {
    this.result.notes.push(s);
  }

  userOf(idx) {
    if (idx === null || idx === undefined) return null;
    const u = (this.kase.users || [])[idx];
    if (!u) throw new Error(`步骤引用了不存在的用户下标 ${idx}`);
    return u;
  }

  proxyOpt(server, idx) {
    const u = this.userOf(idx);
    if (!u) return { server };
    return { server, username: u.user, password: u.pass };
  }

  async open() {
    const { pw } = loadPlaywright();
    const type = pw[this.browserName];
    const kase = this.kase;
    const { server, note } = proxyServer(kase.proxy);
    if (note) this.note(note);
    const keys = [];
    for (const st of flatSteps(kase.steps)) {
      if (st.op !== 'request' && st.op !== 'ws') continue;
      const k = userKey(st.user);
      if (!keys.includes(k)) keys.push(k);
    }
    if (!keys.length) keys.push('none');
    const idxOf = (k) => (k === 'none' ? null : Number(k));
    const multi = keys.length > 1;
    const cfg = [];
    const show = (o) => JSON.stringify(o);

    if (this.browserName === 'chromium') {
      this.netlogPath = path.join(kase.work_dir, 'netlog.json');
      const launchOpt = {
        proxy: multi ? { server } : this.proxyOpt(server, idxOf(keys[0])),
        args: [`--log-net-log=${this.netlogPath}`],
      };
      cfg.push(`const browser = await chromium.launch(${show(launchOpt)});`);
      this.browser = await type.launch(launchOpt);
    } else {
      const profile = path.join(kase.work_dir, 'firefox-profile');
      fs.mkdirSync(profile, { recursive: true });
      const db = 'sql:' + profile;
      execFileSync('certutil', ['-d', db, '-N', '--empty-password'], { stdio: 'pipe' });
      execFileSync('certutil', ['-d', db, '-A', '-n', 'kaoju-phase2-test-ca', '-t', 'C,,', '-i', kase.ca_file], {
        stdio: 'pipe',
      });
      cfg.push(
        '// 事先：certutil -d sql:<profile> -N --empty-password；certutil -d sql:<profile> -A -n kaoju-phase2-test-ca -t "C,," -i <ca_file>',
      );
      const opt = { proxy: multi ? { server } : this.proxyOpt(server, idxOf(keys[0])) };
      cfg.push(`const context = await firefox.launchPersistentContext('<profile>', ${show(opt)});`);
      this.persistent = await type.launchPersistentContext(profile, opt);
      this.browser = this.persistent.browser();
      this.note(
        'Firefox 用 launchPersistentContext 而不是 launch：为了让它读到装了测试 CA 的 cert9.db（launch 不接受自带的 profile）。' +
          '代理配在这个持久上下文上。',
      );
    }

    for (const k of keys) {
      let context;
      if (multi) {
        if (!this.browser) {
          throw new Error(
            'launchPersistentContext 返回的上下文没有 browser()，建不了第二个上下文；这是驱动为了信任测试 CA 选的启动方式带来的限制，不是浏览器的限制',
          );
        }
        const opt = { proxy: this.proxyOpt(server, idxOf(k)) };
        cfg.push(`const context${k} = await browser.newContext(${show(opt)});  // 用户 ${k}`);
        context = await this.browser.newContext(opt);
      } else if (this.persistent) {
        context = this.persistent;
      } else {
        cfg.push('const context = await browser.newContext();');
        context = await this.browser.newContext();
      }
      const page = await context.newPage();
      page.on('requestfailed', (r) => {
        let text = null;
        try {
          const f = r.failure();
          text = f ? f.errorText : null;
        } catch {
          /* 留空 */
        }
        this.failures.push({ t: Date.now(), verb: r.method(), url: r.url(), text });
      });
      this.slots.set(k, { context, page });
    }
    cfg.push(multi ? 'const page<N> = await context<N>.newPage();  // 每个用户一个页面' : 'const page = await context.newPage();');
    cfg.push('// GET：const resp = await page.goto(url, {timeout}); resp.status(); resp.statusText(); await resp.allHeaders(); await resp.body()');
    cfg.push(
      "// POST、parallel：先 page.goto(同源的 /page?k=用例.pre)，再 page.evaluate 里 Promise.all(fetch(url, {method, body: Uint8Array, headers: {'Content-Type': 'application/octet-stream'}}))；GET 的 fetch 不带 init",
    );
    cfg.push('// ws：先 page.goto(步骤的 page)，再 page.evaluate 里 new WebSocket(url)，等 open、close 事件');
    this.result.config = cfg.join('\n');
    this.result.versions.executables = childExecutables();
    try {
      const b = this.browser || (this.persistent && this.persistent.browser());
      this.result.versions.browser_version = b ? b.version() : null;
    } catch {
      /* 留空 */
    }
  }

  async close() {
    const closing = (async () => {
      if (this.persistent) await this.persistent.close();
      else if (this.browser) await this.browser.close();
    })();
    try {
      await withTimeout(closing, 15000, '关闭浏览器');
    } catch (e) {
      this.note('关闭浏览器时出错：' + errText(e));
    }
    this.closedAt = Date.now();
  }

  slot(st) {
    const s = this.slots.get(userKey(st.user));
    if (!s) throw new Error(`没有给用户 ${userKey(st.user)} 准备上下文`);
    return s;
  }

  async gotoStep(page, url) {
    // 返回 {ok, status, text, body, ms, finalUrl}
    const t0 = Date.now();
    try {
      const resp = await page.goto(url, { timeout: this.timeoutMs });
      if (!resp) {
        return { ok: false, status: null, text: 'page.goto 返回了 null（没有响应对象）', body: null, ms: Date.now() - t0 };
      }
      const status = resp.status();
      const statusText = resp.statusText();
      let headers = [];
      let tail = '';
      try {
        headers = Object.entries(await resp.allHeaders());
      } catch (e) {
        tail += '\n' + errText(e);
      }
      let body = null;
      try {
        body = await withTimeout(resp.body(), this.timeoutMs, 'response.body() ');
      } catch (e) {
        tail += '\n' + errText(e);
      }
      return {
        ok: true,
        status,
        text: responseText(status, statusText, headers, body) + tail,
        body,
        ms: Date.now() - t0,
        finalUrl: resp.url(),
      };
    } catch (e) {
      return { ok: false, status: null, text: errText(e), body: null, ms: Date.now() - t0 };
    }
  }

  // 让页面停在 preUrl 上。已经在就不再导航。返回 null 表示就绪，否则是失败的文字。
  async ensurePage(page, preUrl, rec) {
    if (page.url() === preUrl) return null;
    const r = await this.gotoStep(page, preUrl);
    rec.pre = { url: preUrl, ok: r.ok, status: r.status, ms: r.ms, text: r.ok ? null : r.text };
    if (!r.ok) return r.text;
    return null;
  }

  preUrlFor(url) {
    const u = new URL(url);
    return `${u.origin}/page?k=${this.kase.id}.pre`;
  }

  blank(st, extra = {}) {
    return {
      id: st.id,
      op: st.op,
      ok: null,
      status: null,
      body_sha256: null,
      ms: null,
      default_text: null,
      extra_text: null,
      extra_how: null,
      ...extra,
    };
  }

  fetchResult(st, r, rec) {
    if (!r) return rec;
    rec.ms = r.ms;
    if (r.ok) {
      const body = Buffer.from(r.bodyB64, 'base64');
      rec.ok = true;
      rec.status = r.status;
      rec.body_sha256 = sha256(body);
      rec.default_text = responseText(r.status, r.statusText, r.headers, body);
      rec.final_url = r.url;
    } else {
      rec.ok = false;
      rec.default_text = r.error;
    }
    return rec;
  }

  // 在页面里发一批 fetch（一个也算一批）。recs 与 steps 一一对应。
  async fetchBatch(steps, recs) {
    const first = steps[0];
    const { page } = this.slot(first);
    for (const st of steps) {
      if (userKey(st.user) !== userKey(first.user)) throw new Error('并发的子步骤用了不同的用户，驱动没有这种写法');
      if (new URL(st.url).origin !== new URL(first.url).origin) throw new Error('并发的子步骤不同源，驱动没有这种写法');
    }
    const preFail = await this.ensurePage(page, this.preUrlFor(first.url), recs[0]);
    if (preFail !== null) {
      for (const rec of recs) {
        rec.ok = false;
        rec.default_text = preFail;
        rec.pre_failed = true;
      }
      return;
    }
    const reqs = steps.map((st) => ({
      url: st.url,
      method: st.method || 'GET',
      b64: st.body_file ? fs.readFileSync(st.body_file).toString('base64') : null,
    }));
    let out;
    try {
      out = await withTimeout(page.evaluate(inPageFetch, reqs), this.timeoutMs, '页面里的 fetch ');
    } catch (e) {
      for (const rec of recs) {
        rec.ok = false;
        rec.default_text = errText(e);
      }
      return;
    }
    steps.forEach((st, i) => this.fetchResult(st, out[i], recs[i]));
  }

  async runStep(st) {
    const t0 = Date.now();
    if (st.op === 'sleep') {
      this.windows.push({ id: st.id, t0, kids: [] });
      await sleep(st.ms || 0);
      return [this.blank(st, { ms: st.ms || 0 })];
    }
    if (st.op === 'parallel') {
      const kids = st.steps || [];
      this.windows.push({ id: st.id, t0, kids: kids.map((k) => k.id) });
      const parent = this.blank(st, { children: kids.map((k) => k.id) });
      const recs = kids.map((k) => this.blank(k));
      try {
        if (kids.some((k) => k.op !== 'request')) throw new Error('parallel 里只支持 request 步骤');
        await this.fetchBatch(kids, recs);
      } catch (e) {
        for (const rec of recs) {
          if (rec.ok === null) {
            rec.ok = false;
            rec.default_text = errText(e);
          }
        }
      }
      parent.ms = Date.now() - t0;
      return [parent, ...recs];
    }
    this.windows.push({ id: st.id, t0, kids: [] });
    const rec = this.blank(st);
    try {
      if (st.op === 'request') {
        const verb = st.method || 'GET';
        if (verb === 'GET' && !st.body_file) {
          const { page } = this.slot(st);
          const r = await this.gotoStep(page, st.url);
          rec.ok = r.ok;
          rec.status = r.status;
          rec.default_text = r.text;
          rec.body_sha256 = r.body ? sha256(r.body) : null;
          if (r.finalUrl) rec.final_url = r.finalUrl;
        } else {
          await this.fetchBatch([st], [rec]);
        }
      } else if (st.op === 'ws') {
        const { page } = this.slot(st);
        const preFail = await this.ensurePage(page, st.page || this.preUrlFor(st.url.replace(/^ws/, 'http')), rec);
        if (preFail !== null) {
          rec.ok = false;
          rec.default_text = preFail;
          rec.pre_failed = true;
        } else {
          const waitMs = Math.max(1000, this.timeoutMs - 2000);
          const r = await withTimeout(
            page.evaluate(inPageWebSocket, { url: st.url, waitMs }),
            this.timeoutMs,
            '页面里的 WebSocket ',
          );
          rec.ok = r.opened;
          rec.status = r.opened ? 101 : null;
          rec.default_text = r.events.join('\n');
        }
      } else {
        rec.ok = false;
        rec.default_text = `驱动不认识的步骤类型：${st.op}`;
      }
    } catch (e) {
      rec.ok = false;
      rec.default_text = errText(e);
    }
    rec.ms = Date.now() - t0;
    return [rec];
  }

  // 浏览器关闭以后：把 requestfailed 和 NetLog 的内容按时间窗归给各步。
  attachExtra() {
    const how = this.browserName === 'chromium' ? EXTRA_HOW_CHROMIUM : EXTRA_HOW_FIREFOX;
    let netlog = null;
    if (this.netlogPath) {
      netlog = parseNetLog(this.netlogPath);
      if (netlog.error) this.note(netlog.error);
    }
    const byId = new Map(this.result.steps.map((s) => [s.id, s]));
    const end = this.closedAt || Date.now();
    this.windows.forEach((w, i) => {
      if (byId.get(w.id) && byId.get(w.id).op === 'sleep') return;
      const t0 = w.t0;
      // 时间窗到下一个不是 sleep 的步骤开始为止（sleep 期间发生的事算前一步的）
      let t1 = end + 1;
      for (let j = i + 1; j < this.windows.length; j++) {
        const s = byId.get(this.windows[j].id);
        if (s && s.op === 'sleep') continue;
        t1 = this.windows[j].t0;
        break;
      }
      const lines = [];
      lines.push("page.on('requestfailed')：");
      const fl = this.failures.filter((f) => f.t >= t0 && f.t < t1);
      if (fl.length) for (const f of fl) lines.push(`${f.verb} ${f.url} ${f.text}`);
      else lines.push('（没有）');
      if (netlog) {
        lines.push('NetLog（--log-net-log）：');
        if (netlog.error) lines.push(`（${netlog.error}）`);
        const evs = netlog.events.filter((e) => e.t >= t0 && e.t < t1);
        if (evs.length) for (const e of evs) lines.push(...netLogLines(e, t0));
        else if (!netlog.error) lines.push('（这一步的时间窗里没有 CONNECT 或 SOCKS 的事件）');
      }
      const text = lines.join('\n');
      for (const id of w.kids.length ? w.kids : [w.id]) {
        const s = byId.get(id);
        if (!s) continue;
        s.extra_text = text;
        s.extra_how = how;
      }
    });
  }
}

function writeResult(file, result) {
  const tmp = file + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(result, null, 1) + '\n');
  fs.renameSync(tmp, file);
}

async function runCase(browserName, kase, result) {
  const runner = new Runner(browserName, kase, result);
  const usesCreds = flatSteps(kase.steps).some((st) => st.user !== null && st.user !== undefined);
  const socks = kase.proxy.scheme !== 'http';
  try {
    await runner.open();
  } catch (e) {
    const msg = errText(e);
    if (socks && usesCreds && /does not support socks5 proxy authentication/i.test(msg)) {
      result.unsupported =
        'Playwright 不接受给 SOCKS5 代理配凭据：照常调用了一次，launch 抛出 ' + JSON.stringify(msg.split('\n')[0]);
      result.launch_error = msg;
    } else {
      result.launch_error = msg;
      for (const st of flatSteps(kase.steps)) {
        const rec = runner.blank(st);
        if (st.op === 'request' || st.op === 'ws') {
          rec.ok = false;
          rec.default_text = msg;
        }
        if (st.op === 'parallel') rec.children = (st.steps || []).map((k) => k.id);
        result.steps.push(rec);
      }
    }
    await runner.close();
    return;
  }
  try {
    for (const st of kase.steps || []) {
      const recs = await runner.runStep(st);
      result.steps.push(...recs);
    }
  } catch (e) {
    result.notes.push('执行步骤时驱动出错：' + errText(e));
  }
  await runner.close();
  try {
    runner.attachExtra();
  } catch (e) {
    result.notes.push('整理额外信息时出错：' + errText(e));
  }
}

async function versions(browserName) {
  const v = { node: process.version, browser: browserName, playwright: null, browser_version: null, executables: [] };
  try {
    const { pw, version } = loadPlaywright();
    v.playwright = version;
    const browser = await pw[browserName].launch();
    try {
      v.browser_version = browser.version();
      v.executables = childExecutables();
    } finally {
      await browser.close();
    }
  } catch (e) {
    v.error = errText(e).split('\n')[0];
  }
  try {
    v.certutil = fs.existsSync('/usr/bin/certutil') ? 'present' : 'absent';
  } catch {
    /* 留空 */
  }
  return v;
}

async function main(argv) {
  let browserName = null;
  let versionsOnly = false;
  const rest = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--browser') browserName = argv[++i];
    else if (a.startsWith('--browser=')) browserName = a.slice('--browser='.length);
    else if (a === '--versions') versionsOnly = true;
    else rest.push(a);
  }
  if (!Object.hasOwn(VARIANTS, browserName || '')) {
    process.stderr.write('用法：driver.mjs --browser chromium|firefox (<用例.json> <结果.json> | --versions)\n');
    return 2;
  }
  if (versionsOnly) {
    process.stdout.write(JSON.stringify(await versions(browserName)) + '\n');
    return 0;
  }
  if (rest.length !== 2) {
    process.stderr.write('用法：driver.mjs --browser chromium|firefox <用例.json> <结果.json>\n');
    return 2;
  }
  const kase = JSON.parse(fs.readFileSync(rest[0], 'utf8'));
  const result = {
    variant: VARIANTS[browserName],
    versions: { node: process.version, browser: browserName, playwright: null, browser_version: null, executables: [] },
    config: null,
    unsupported: null,
    steps: [],
    notes: [],
  };
  let written = false;
  const flush = () => {
    if (written) return;
    written = true;
    try {
      writeResult(rest[1], result);
    } catch (e) {
      process.stderr.write('写结果文件失败：' + errText(e) + '\n');
    }
  };
  const fatal = (what) => (e) => {
    result.notes.push(`${what}：${errText(e)}`);
    flush();
    process.exit(0);
  };
  process.on('uncaughtException', fatal('未捕获的异常'));
  process.on('unhandledRejection', fatal('未处理的 Promise 拒绝'));
  try {
    result.versions.playwright = loadPlaywright().version;
    await runCase(browserName, kase, result);
  } catch (e) {
    result.notes.push('驱动出错：' + errText(e));
  }
  flush();
  return 0;
}

main(process.argv.slice(2)).then(
  (code) => process.exit(code),
  (e) => {
    process.stderr.write(errText(e) + '\n');
    process.exit(0);
  },
);
