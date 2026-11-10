// node 五列共用的部分：错误的写法、步骤的执行、结果文件、版本号。
// 只用 Node 自带的模块；被测的库由各列的模块自己引入。

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

export const HERE = path.dirname(fileURLToPath(import.meta.url));
export const BODY_HEAD = 4096;
export const STEP_MARK = '@@KAOJU-STEP';
export const REDIRECT_CODES = [301, 302, 303, 307, 308];
export const MAX_HOPS = 5;

// ---------- 版本 ----------

export function pkgVersion(...parts) {
  try {
    const p = path.join(HERE, 'node_modules', ...parts, 'package.json');
    return JSON.parse(fs.readFileSync(p, 'utf8')).version;
  } catch {
    return null;
  }
}

export function pinned() {
  try {
    return JSON.parse(fs.readFileSync(path.join(HERE, 'package.json'), 'utf8')).dependencies || {};
  } catch {
    return {};
  }
}

export function nodeVersions() {
  return {
    node: process.versions.node,
    openssl: process.versions.openssl,
    'node 内置的 undici': process.versions.undici,
    v8: process.versions.v8,
    llhttp: process.versions.llhttp,
  };
}

/** 读出若干个包装在 node_modules 里的版本，并和 package.json 钉的版本比。 */
export function withPackages(base, top, nested = {}) {
  const v = { ...base };
  const want = pinned();
  const diff = [];
  for (const name of top) {
    v[name] = pkgVersion(name);
    if (want[name] !== undefined && want[name] !== v[name]) {
      diff.push(`${name}：装的是 ${v[name]}，package.json 钉的是 ${want[name]}`);
    }
  }
  for (const [label, parts] of Object.entries(nested)) v[label] = pkgVersion(...parts);
  v.matches_package_json = diff.length === 0;
  if (diff.length) v.package_json_diff = diff;
  return v;
}

// ---------- 文字 ----------

/**
 * 把一个错误写成文字：类型、code、消息，沿 cause 链（以及 AggregateError 的 errors）逐层写下来。
 * 不写调用栈（里面是本机路径），不把错误对象上的其他属性整个序列化（axios 的 config、socks 的 options 里有凭据）。
 * 标签故意不用“方法”“认证”这类词：矩阵的 R119、R120 在这段文字里找它们，只应该找到客户端自己的话。
 */
export function errLines(e, indent = '', seen = new Set()) {
  const out = [];
  if (e === null || typeof e !== 'object') {
    out.push(`${indent}抛出的不是 Error：${String(e)}`);
    return out;
  }
  if (seen.has(e)) {
    out.push(`${indent}（循环引用）`);
    return out;
  }
  seen.add(e);
  const ctor = e.constructor && e.constructor.name ? e.constructor.name : '?';
  const name = e.name === undefined ? '?' : String(e.name);
  const kind = ctor === name ? name : `${name}（构造函数 ${ctor}）`;
  const code = e.code === undefined ? '' : ` code=${String(e.code)}`;
  out.push(`${indent}${kind}${code}: ${String(e.message)}`);
  if (Array.isArray(e.errors)) {
    e.errors.forEach((x, i) => {
      out.push(`${indent}  errors[${i}]:`);
      out.push(...errLines(x, indent + '    ', seen));
    });
  }
  if (e.cause !== undefined && e.cause !== null) {
    out.push(`${indent}  cause:`);
    out.push(...errLines(e.cause, indent + '    ', seen));
  }
  return out;
}

export function bodyHead(buf) {
  return buf.subarray(0, BODY_HEAD).toString('utf8');
}

export function sha256(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

export function basicToken(user) {
  return 'Basic ' + Buffer.from(`${user.user}:${user.pass}`).toString('base64');
}

/** 代理 URL：凭据写在 userinfo 里，用户名、密码各自 encodeURIComponent。 */
export function proxyUrlWithUserinfo(scheme, px, user) {
  const cred = user == null ? '' : `${encodeURIComponent(user.user)}:${encodeURIComponent(user.pass)}@`;
  return `${scheme}://${cred}${px.host}:${px.port}`;
}

export function stepTimeoutMs(run, st) {
  const s = st.timeout_s ?? run.timeout_s ?? 15;
  return Math.round(s * 1000);
}

export function readBody(st) {
  return st.body_file ? fs.readFileSync(st.body_file) : null;
}

export function userOf(run, st) {
  return st.user === null || st.user === undefined ? null : run.users[st.user];
}

export function distinctUsers(run) {
  const seen = new Set();
  const walk = (steps) => {
    for (const st of steps || []) {
      if (st.op === 'parallel') walk(st.steps);
      else if (st.user !== null && st.user !== undefined) seen.add(st.user);
    }
  };
  walk(run.steps);
  return seen.size;
}

// ---------- http / https 模块的一次请求（node-http-env、node-agents 共用） ----------

/** start(cb) 要发起请求并返回 req；这里只负责把响应读完。 */
export function collect(start) {
  return new Promise((resolve, reject) => {
    let req;
    try {
      req = start((res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => resolve({ req, res, body: Buffer.concat(chunks) }));
        res.on('error', reject);
      });
    } catch (e) {
      reject(e);
      return;
    }
    req.on('error', reject);
  });
}

/** Node 的 http、https 不跟随重定向，也没有开关；follow 为真的步骤由驱动自己循环。 */
export async function followLoop(st, once) {
  let url = st.url;
  const hops = [];
  for (let i = 0; ; i++) {
    const r = await once(url, i);
    const loc = r.res.headers.location;
    if (st.follow && REDIRECT_CODES.includes(r.res.statusCode) && loc && i < MAX_HOPS) {
      hops.push(`${r.res.statusCode} ${url} -> ${loc}`);
      url = new URL(loc, url).href;
      continue;
    }
    return { ...r, hops, url };
  }
}

export function nodeResponseLines(r) {
  const { req, res, body, hops, url } = r;
  const lines = [
    `res.statusCode: ${res.statusCode}`,
    `res.statusMessage: ${res.statusMessage}`,
    `res.httpVersion: ${res.httpVersion}`,
    `req.reusedSocket: ${req.reusedSocket}`,
  ];
  if (hops && hops.length) {
    lines.push(`最后请求的 URL: ${url}`);
    for (const h of hops) lines.push(`驱动自己跟随的跳转: ${h}`);
  }
  lines.push('res.rawHeaders:');
  for (let i = 0; i + 1 < res.rawHeaders.length; i += 2) lines.push(`${res.rawHeaders[i]}: ${res.rawHeaders[i + 1]}`);
  lines.push(`正文（前 ${BODY_HEAD} 字节）:`);
  lines.push(bodyHead(body));
  return lines;
}

// ---------- diagnostics_channel（node-fetch-env、node-undici 共用） ----------

function headerText(h) {
  if (Buffer.isBuffer(h)) return h.toString('latin1');
  if (Array.isArray(h)) return h.map(headerText).join(', ');
  return String(h);
}

/** undici:request:headers 频道里 CONNECT 请求的响应：状态行和响应头。 */
export function connectMessageLines(msg) {
  const { request, response } = msg || {};
  if (!request || !response || request.method !== 'CONNECT') return null;
  const lines = [`CONNECT ${request.path} 的响应: ${response.statusCode} ${response.statusText ?? ''}`];
  const hs = response.headers;
  if (Array.isArray(hs)) {
    for (let i = 0; i + 1 < hs.length; i += 2) lines.push(`  ${headerText(hs[i])}: ${headerText(hs[i + 1])}`);
  } else if (hs && typeof hs === 'object') {
    for (const [k, v] of Object.entries(hs)) lines.push(`  ${k}: ${headerText(v)}`);
  }
  return lines;
}

// ---------- 步骤的执行 ----------

export function placeholder(st, more = {}) {
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
    ...more,
  };
}

/** 进程级的异常：Node 默认会因此退出；驱动接住，记到当时正在跑的步骤上。 */
export const strays = [];
export function installStrayHandlers() {
  process.on('uncaughtException', (e) => {
    strays.push({ kind: 'uncaughtException', lines: errLines(e) });
  });
  process.on('unhandledRejection', (e) => {
    strays.push({ kind: 'unhandledRejection', lines: errLines(e) });
  });
}

/**
 * 执行一个 request 或 ws 步骤。client.request(st, ctx) / client.ws(st, ctx) 返回
 * { ok, status, body(Buffer 或 null), lines(default_text 的各行) }，或者抛出错误。
 * ctx：signal（按用例的 timeout_s 到点中止）、extra（额外手段看到的行）、parallel。
 */
export async function runStep(client, run, st, parallel) {
  const res = placeholder(st);
  const ms = stepTimeoutMs(run, st);
  const signal = AbortSignal.timeout(ms);
  const extra = [];
  const strayFrom = strays.length;
  const t0 = performance.now();
  let wd;
  const watchdog = new Promise((resolve) => {
    wd = setTimeout(() => resolve({ watchdog: true }), ms + 3000);
  });
  let out;
  try {
    const fn = st.op === 'ws' ? client.ws : client.request;
    if (typeof fn !== 'function') throw new Error(`驱动：这一列没有实现 ${st.op} 步骤`);
    const p = Promise.resolve().then(() => fn.call(client, st, { signal, extra, parallel }));
    p.catch(() => {});
    out = await Promise.race([p, watchdog]);
  } catch (e) {
    out = { error: e };
  }
  clearTimeout(wd);
  res.ms = Math.round(performance.now() - t0);
  let lines;
  if (out && out.watchdog) {
    res.ok = false;
    lines = [
      `驱动：这一步在 ${(ms + 3000) / 1000} 秒内既没有成功也没有报错（传给客户端的 AbortSignal.timeout(${ms}) 也没有让它结束），驱动放弃等待`,
    ];
  } else if (out && out.error !== undefined) {
    res.ok = false;
    lines = errLines(out.error);
  } else {
    res.ok = !!out.ok;
    res.status = out.status ?? null;
    if (out.body) res.body_sha256 = sha256(out.body);
    lines = out.lines;
  }
  const mine = strays.slice(strayFrom);
  if (mine.length) {
    lines = lines.concat(
      mine.flatMap((s) => [
        `这一步期间出现了进程级的 ${s.kind}（Node 默认会打印它然后退出进程；驱动装了处理函数，进程才活了下来）:`,
        ...s.lines.map((l) => '  ' + l),
      ]),
    );
  }
  res.default_text = lines.join('\n');
  if (client.extraHow && !parallel && (!client.extraApplies || client.extraApplies(st))) {
    res.extra_how = client.extraHow;
    res.extra_text = extra.length ? extra.join('\n') : '（这个手段在这一步没有给出任何内容）';
  } else if (client.extraHow && extra.length) {
    // 能准确归到这一步的额外信息（比如挂在请求对象上的事件），并发时也记
    res.extra_how = client.extraHow;
    res.extra_text = extra.join('\n');
  }
  return res;
}

export function writeJson(file, obj) {
  const tmp = file + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(obj, null, 1) + '\n');
  fs.renameSync(tmp, file);
}

export function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}
