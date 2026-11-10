// 列 node-http-env：Node 内置的 http、https 模块，代理靠环境变量加 NODE_USE_ENV_PROXY=1。

import http from 'node:http';
import https from 'node:https';
import { collect, followLoop, nodeResponseLines, nodeVersions, readBody } from './common.mjs';
import { envPlan } from './envcommon.mjs';

const EXTRA_HOW =
  '环境变量 NODE_DEBUG=https（doc/api/cli.md 的 NODE_DEBUG）：https 模块把调试信息打到标准错误，其中 onProxyData 一段是代理对 CONNECT 回的整块数据' +
  '（状态行、响应头，以及同一块里的正文）。这是调试输出，格式不保证。驱动只摘出 onProxyData 开头的段落，其余的调试输出（请求选项的转储等）不记。';

export function versions() {
  return nodeVersions();
}

function callText(st) {
  const mod = st.url.startsWith('https:') ? 'https' : 'http';
  if (st.body_file) {
    return `req = ${mod}.request(${JSON.stringify(st.url)}, { method: ${JSON.stringify(st.method)}, headers: { 'Content-Type': 'application/octet-stream', 'Content-Length': buf.length }, signal }, cb); req.end(buf)   // buf 是 ${st.body_file} 的全部内容`;
  }
  if (!st.method || st.method === 'GET') return `${mod}.get(${JSON.stringify(st.url)}, { signal }, cb)`;
  return `req = ${mod}.request(${JSON.stringify(st.url)}, { method: ${JSON.stringify(st.method)}, signal }, cb); req.end()`;
}

export function plan(run) {
  const p = envPlan(run, { NODE_DEBUG: 'https' });
  if (!p.attempt) return p;
  const cfg = [
    p.cmd,
    '// 脚本里按 URL 的协议选 http 或 https 模块，用全局 Agent，没有引入任何包；signal = AbortSignal.timeout(用例的 timeout_s)；cb 里把响应读完',
  ];
  const walk = (steps, ind) => {
    for (const st of steps || []) {
      if (st.op === 'sleep') cfg.push(`${ind}${st.id}: await new Promise(r => setTimeout(r, ${st.ms}))`);
      else if (st.op === 'parallel') {
        cfg.push(`${ind}${st.id}: await Promise.all([   // 同一轮里全部发出`);
        walk(st.steps, ind + '    ');
        cfg.push(`${ind}])`);
      } else {
        cfg.push(
          `${ind}${st.id}: ${callText(st)}` +
            (st.follow ? '   // 这两个模块不跟随重定向：响应是 301、302、303、307、308 且有 Location 时，驱动用 new URL(location, 当前URL) 再发一次同样写法的 GET' : ''),
        );
      }
    }
  };
  walk(run.steps, '');
  p.notes.push('NODE_DEBUG=https 只让 https 模块往标准错误多打印，不改变发出的字节；它是为 extra_text 加的。');
  return { ...p, config: cfg.join('\n') };
}

export async function create() {
  return {
    notes: [
      'default_text：成功时是 res.statusCode、res.statusMessage、res.httpVersion、req.reusedSocket、res.rawHeaders、正文前 4096 字节；' +
        '失败时是 error 事件给的错误的类型、code、消息和 cause 链（错误对象上文档没写的 statusCode 属性不记）。' +
        'follow 为真的步骤由驱动自己循环着跟随重定向，那几行测到的是驱动的循环加上模块对每一跳的处理。',
    ],
    async request(st, ctx) {
      const body = readBody(st);
      const r = await followLoop(st, (url) => {
        const mod = new URL(url).protocol === 'https:' ? https : http;
        return collect((cb) => {
          if (body) {
            const req = mod.request(
              url,
              { method: st.method, headers: { 'Content-Type': 'application/octet-stream', 'Content-Length': body.length }, signal: ctx.signal },
              cb,
            );
            req.end(body);
            return req;
          }
          if (!st.method || st.method === 'GET') return mod.get(url, { signal: ctx.signal }, cb);
          const req = mod.request(url, { method: st.method, signal: ctx.signal }, cb);
          req.end();
          return req;
        });
      });
      return { ok: true, status: r.res.statusCode, body: r.body, lines: nodeResponseLines(r) };
    },
  };
}

/** 外层调用：从内层标准错误里每一步的那一段摘出 onProxyData 的段落，作为 extra_text。 */
export function postprocess(result, perStepStderr) {
  for (const s of result.steps) {
    if (s.op !== 'request' || !(s.id in perStepStderr)) continue;
    const lines = perStepStderr[s.id];
    const keep = [];
    let on = false;
    for (const line of lines) {
      const m = /^HTTPS \d+: (.*)$/.exec(line);
      if (m) {
        on = m[1].startsWith('onProxyData ');
        if (on) keep.push(m[1]);
      } else if (on) keep.push(line);
    }
    s.extra_how = EXTRA_HOW;
    s.extra_text = keep.length ? keep.join('\n') : '（NODE_DEBUG=https 在这一步没有打印 onProxyData）';
  }
}
