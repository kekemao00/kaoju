// 列 node-axios：axios 自带的 proxy 选项（请求配置），不传 httpAgent、httpsAgent。

import { BODY_HEAD, errLines, nodeVersions, readBody, userOf, withPackages } from './common.mjs';

export function versions() {
  return withPackages(nodeVersions(), ['axios', 'follow-redirects', 'proxy-from-env'], {
    'axios 自带的 https-proxy-agent': ['axios', 'node_modules', 'https-proxy-agent'],
    'axios 自带的 agent-base': ['axios', 'node_modules', 'agent-base'],
  });
}

function isSocks(run) {
  return run.proxy.scheme !== 'http';
}

function proxyConfig(run, st) {
  const u = userOf(run, st);
  const p = { protocol: run.proxy.scheme, host: run.proxy.host, port: run.proxy.port };
  if (u) p.auth = { username: u.user, password: u.pass };
  return p;
}

function callText(run, st) {
  const p = JSON.stringify(proxyConfig(run, st));
  if (st.body_file) {
    return `await axios.post(${JSON.stringify(st.url)}, buf, { headers: { 'Content-Type': 'application/octet-stream' }, proxy: ${p}, signal })   // buf 是 ${st.body_file} 的全部内容`;
  }
  return `await axios.request({ method: ${JSON.stringify(st.method || 'GET')}, url: ${JSON.stringify(st.url)}, proxy: ${p}, signal })`;
}

export function plan(run) {
  const notes = [];
  const cfg = ["import axios from 'axios'   // 用默认导出的那一个实例，整个用例不换"];
  const walk = (steps, ind) => {
    for (const st of steps || []) {
      if (st.op === 'sleep') cfg.push(`${ind}${st.id}: await new Promise(r => setTimeout(r, ${st.ms}))`);
      else if (st.op === 'parallel') {
        cfg.push(`${ind}${st.id}: await Promise.all([   // 同一轮里全部发出`);
        walk(st.steps, ind + '    ');
        cfg.push(`${ind}])`);
      } else if (st.op === 'request') cfg.push(`${ind}${st.id}: ${callText(run, st)}`);
      else cfg.push(`${ind}${st.id}: （${st.op}：这一列不跑）`);
    }
  };
  walk(run.steps, '');
  cfg.push(
    '// signal = AbortSignal.timeout(用例的 timeout_s)；其余配置一概不传（maxRedirects、validateStatus、responseType、timeout、httpAgent、httpsAgent 都是默认）。' +
      '信任测试 CA 用环境变量 NODE_EXTRA_CA_CERTS（进程启动前设好）',
  );
  notes.push(
    '凭据用 proxy.auth 的 username、password，原始字符串，不转义；两个用户就是每个请求传各自的 proxy.auth。重定向是 axios 默认就跟随的（follow-redirects）。',
  );
  let unsupported = null;
  if (isSocks(run)) {
    unsupported =
      'axios 的 proxy 选项只有 HTTP 代理这一种做法：README 的 proxy 一节只讲 http 和 https 两种 protocol，lib/adapters/http.js 的 setProxy 也只有“https 目标建 CONNECT 隧道、http 目标改写成绝对形式”两条路，没有 SOCKS 的实现' +
      '（要走 SOCKS 得自己传 httpAgent、httpsAgent，那不是这一列）。' +
      `仍然把 protocol 写成 ${JSON.stringify(run.proxy.scheme)} 试了一次，客户端的反应记在各步里；代理端口上出现的不是 SOCKS5 握手时，说明 axios 把它当成了 HTTP 代理。`;
  }
  return { attempt: true, unsupported, env: {}, config: cfg.join('\n'), notes };
}

function dataText(data) {
  if (data === undefined) return '（undefined）';
  if (typeof data === 'string') return data.slice(0, BODY_HEAD);
  if (Buffer.isBuffer(data)) return data.subarray(0, BODY_HEAD).toString('utf8');
  try {
    return 'JSON.stringify(data) = ' + JSON.stringify(data).slice(0, BODY_HEAD);
  } catch {
    return String(data).slice(0, BODY_HEAD);
  }
}

function responseLines(res, prefix) {
  const lines = [`${prefix}.status: ${res.status}`, `${prefix}.statusText: ${res.statusText}`, `${prefix}.headers:`];
  const hs = res.headers && typeof res.headers.toJSON === 'function' ? res.headers.toJSON() : res.headers || {};
  for (const [k, v] of Object.entries(hs)) lines.push(`${k}: ${Array.isArray(v) ? v.join(', ') : v}`);
  lines.push(`${prefix}.data（前 ${BODY_HEAD} 个字符；默认的 responseType 下 JSON 正文已被 axios 解析成对象）:`);
  lines.push(dataText(res.data));
  return lines;
}

export async function create(run) {
  const axios = (await import('axios')).default;
  return {
    notes: [
      'default_text：成功时是 res.status、res.statusText、res.headers、res.data；axios 抛 AxiosError 时是错误的类型、code、消息和 cause 链，' +
        '带 error.response 的（代理或源站回了非 2xx）再加上 error.response 的 status、statusText、headers、data，这种情况记 ok=true、status=error.response.status' +
        '（error.config、error.request 不记，里面有凭据）。' +
        'responseType 保持默认，res.data 是解析后的对象或字符串，拿不到原始字节，所以 body_sha256 留空。没有额外手段：axios 不暴露内部的隧道 Agent。',
    ],
    async request(st, ctx) {
      const body = readBody(st);
      const proxy = proxyConfig(run, st);
      let res;
      try {
        if (body) {
          res = await axios.post(st.url, body, { headers: { 'Content-Type': 'application/octet-stream' }, proxy, signal: ctx.signal });
        } else {
          res = await axios.request({ method: st.method || 'GET', url: st.url, proxy, signal: ctx.signal });
        }
      } catch (e) {
        if (e && e.response && typeof e.response.status === 'number') {
          return { ok: true, status: e.response.status, body: null, lines: [...errLines(e), ...responseLines(e.response, 'error.response')] };
        }
        throw e;
      }
      return { ok: true, status: res.status, body: null, lines: responseLines(res, 'res') };
    },
  };
}
