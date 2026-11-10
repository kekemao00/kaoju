// 列 node-fetch-env：Node 内置的 fetch（以及内置的 WebSocket），代理靠环境变量加 NODE_USE_ENV_PROXY=1。

import dc from 'node:diagnostics_channel';
import { BODY_HEAD, bodyHead, connectMessageLines, nodeVersions, readBody } from './common.mjs';
import { envPlan } from './envcommon.mjs';

export function versions() {
  return nodeVersions();
}

function callText(st) {
  if (st.op === 'ws') return `new WebSocket(${JSON.stringify(st.url)})`;
  if (st.body_file) {
    return `await fetch(${JSON.stringify(st.url)}, { method: ${JSON.stringify(st.method)}, body: <Buffer，${st.body_file} 的全部内容>, headers: { 'content-type': 'application/octet-stream' }, signal })`;
  }
  const m = st.method && st.method !== 'GET' ? `method: ${JSON.stringify(st.method)}, ` : '';
  return `await fetch(${JSON.stringify(st.url)}, { ${m}signal })`;
}

export function plan(run) {
  const p = envPlan(run);
  if (!p.attempt) return p;
  const cfg = [p.cmd, '// 脚本里用全局的 fetch，没有引入任何包；signal = AbortSignal.timeout(用例的 timeout_s)，其余选项一概不传（重定向保持默认的 follow）'];
  const walk = (steps, ind) => {
    for (const st of steps || []) {
      if (st.op === 'sleep') cfg.push(`${ind}${st.id}: await new Promise(r => setTimeout(r, ${st.ms}))`);
      else if (st.op === 'parallel') {
        cfg.push(`${ind}${st.id}: await Promise.all([   // 同一轮里全部发出`);
        walk(st.steps, ind + '    ');
        cfg.push(`${ind}])`);
      } else cfg.push(`${ind}${st.id}: ${callText(st)}${st.op === 'ws' ? '' : '; await res.arrayBuffer()'}`);
    }
  };
  walk(run.steps, '');
  return { ...p, config: cfg.join('\n') };
}

export async function create() {
  const client = {
    sink: null,
    extraHow:
      "node:diagnostics_channel 订阅 'undici:request:headers' 频道，只记 CONNECT 请求的响应（状态码、原因短语、响应头；拿不到正文）。" +
      '依据是 undici 自己的文档 docs/docs/api/DiagnosticsChannel.md；Node 的文档没有提到内置 fetch 也往这个频道发布，这里是实测能收到。',
    notes: [
      'default_text：成功时是 res.status、res.statusText、res.url、res.redirected、res.headers、正文前 4096 字节；' +
        '失败时是错误的类型、code、消息，沿 cause 链逐层写出。extra_text 只在串行的步骤里记（频道是进程级的，并发时分不清是哪一步的）。',
    ],
    async request(st, ctx) {
      if (!ctx.parallel) this.sink = ctx.extra;
      const init = { signal: ctx.signal };
      const body = readBody(st);
      if (body) {
        init.method = st.method;
        init.body = body;
        init.headers = { 'content-type': 'application/octet-stream' };
      } else if (st.method && st.method !== 'GET') {
        init.method = st.method;
      }
      const res = await fetch(st.url, init);
      const buf = Buffer.from(await res.arrayBuffer());
      const lines = [
        `res.status: ${res.status}`,
        `res.statusText: ${res.statusText}`,
        `res.url: ${res.url}`,
        `res.redirected: ${res.redirected}`,
        'res.headers:',
      ];
      for (const [k, v] of res.headers) lines.push(`${k}: ${v}`);
      lines.push(`正文（前 ${BODY_HEAD} 字节）:`);
      lines.push(bodyHead(buf));
      return { ok: true, status: res.status, body: buf, lines };
    },
    ws(st, ctx) {
      if (!ctx.parallel) this.sink = ctx.extra;
      return new Promise((resolve) => {
        const lines = [];
        let opened = false;
        let settled = false;
        const finish = () => {
          if (settled) return;
          settled = true;
          resolve({ ok: opened, status: null, body: null, lines });
        };
        let ws;
        try {
          ws = new WebSocket(st.url);
        } catch (e) {
          lines.push(`new WebSocket 抛出：${e && e.name}: ${e && e.message}`);
          finish();
          return;
        }
        lines.push(`new WebSocket(${JSON.stringify(st.url)})`);
        ws.addEventListener('open', () => {
          opened = true;
          lines.push(`open 事件：protocol=${JSON.stringify(ws.protocol)} extensions=${JSON.stringify(ws.extensions)}`);
        });
        ws.addEventListener('message', (ev) => {
          lines.push(`message 事件：${typeof ev.data === 'string' ? ev.data.slice(0, 200) : '（二进制）'}`);
        });
        ws.addEventListener('error', (ev) => {
          const e = ev && ev.error;
          const m = (ev && ev.message) || (e && e.message) || '';
          lines.push(`error 事件：${m}`);
          let c = e && e.cause;
          for (let i = 0; c && i < 5; i++, c = c.cause) lines.push(`  cause: ${c.name}${c.code ? ' code=' + c.code : ''}: ${c.message}`);
        });
        ws.addEventListener('close', (ev) => {
          lines.push(`close 事件：code=${ev.code} reason=${JSON.stringify(ev.reason)} wasClean=${ev.wasClean}`);
          finish();
        });
        ctx.signal.addEventListener('abort', () => {
          lines.push('驱动：到了用例的时限还没有等到 close 事件，调用 ws.close() 后不再等');
          try {
            ws.close();
          } catch {
            /* 已经关了 */
          }
          setTimeout(finish, 500);
        });
      });
    },
  };
  dc.subscribe('undici:request:headers', (msg) => {
    const lines = connectMessageLines(msg);
    if (lines && client.sink) client.sink.push(...lines);
  });
  return client;
}
