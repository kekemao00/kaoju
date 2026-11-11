// 列 node-undici：npm 的 undici，显式的 ProxyAgent 作 fetch 的 dispatcher。

import dc from 'node:diagnostics_channel';
import {
  BODY_HEAD,
  basicToken,
  bodyHead,
  connectMessageLines,
  nodeVersions,
  proxyUrlWithUserinfo,
  readBody,
  userOf,
  withPackages,
} from './common.mjs';

export function versions() {
  return withPackages(nodeVersions(), ['undici']);
}

function isSocks(run) {
  return run.proxy.scheme === 'socks5' || run.proxy.scheme === 'socks5h';
}

/** 返回 [构造参数, 写法的文字]。 */
function agentArgs(run, user) {
  const px = run.proxy;
  if (isSocks(run)) {
    const url = proxyUrlWithUserinfo('socks5', px, user);
    return [url, `new ProxyAgent(${JSON.stringify(url)})`];
  }
  const uri = `http://${px.host}:${px.port}`;
  if (user == null) return [uri, `new ProxyAgent(${JSON.stringify(uri)})`];
  const token = basicToken(user);
  return [
    { uri, token },
    `new ProxyAgent({ uri: ${JSON.stringify(uri)}, token: 'Basic ' + Buffer.from(${JSON.stringify(user.user)} + ':' + ${JSON.stringify(user.pass)}).toString('base64') })`,
  ];
}

function callText(st, name) {
  if (st.body_file) {
    return `await fetch(${JSON.stringify(st.url)}, { method: ${JSON.stringify(st.method)}, body: <Buffer，${st.body_file} 的全部内容>, headers: { 'content-type': 'application/octet-stream' }, dispatcher: ${name}, signal })`;
  }
  const m = st.method && st.method !== 'GET' ? `method: ${JSON.stringify(st.method)}, ` : '';
  return `await fetch(${JSON.stringify(st.url)}, { ${m}dispatcher: ${name}, signal })`;
}

function agentName(st) {
  return st.user === null || st.user === undefined ? 'agentNoCred' : `agentUser${st.user}`;
}

export function plan(run) {
  const notes = [];
  const cfg = ["import { ProxyAgent, fetch } from 'undici'   // fetch 也是 npm 这一份的，不是全局的"];
  const declared = new Set();
  const walk = (steps, ind) => {
    for (const st of steps || []) {
      if (st.op === 'sleep') cfg.push(`${ind}${st.id}: await new Promise(r => setTimeout(r, ${st.ms}))`);
      else if (st.op === 'parallel') {
        cfg.push(`${ind}${st.id}: await Promise.all([   // 同一轮里全部发出`);
        walk(st.steps, ind + '    ');
        cfg.push(`${ind}])`);
      } else if (st.op === 'request') {
        const name = agentName(st);
        if (!declared.has(name)) {
          declared.add(name);
          cfg.push(`${ind}const ${name} = ${agentArgs(run, userOf(run, st))[1]}   // 第一次用到时构造，之后整个用例都用这一个实例`);
        }
        cfg.push(`${ind}${st.id}: ${callText(st, name)}; await res.arrayBuffer()`);
      } else cfg.push(`${ind}${st.id}: （${st.op}：这一列不跑）`);
    }
  };
  walk(run.steps, '');
  cfg.push('// signal = AbortSignal.timeout(用例的 timeout_s)；其余选项一概不传。信任测试 CA 用环境变量 NODE_EXTRA_CA_CERTS（进程启动前设好），没有传 requestTls、connect 之类的选项');
  if (isSocks(run)) {
    notes.push(
      `用例给的代理写法是 ${run.proxy.scheme}://。undici 的 ProxyAgent 只认 socks5:// 和 socks://，不区分“客户端解析”和“代理解析”` +
        '（docs/docs/api/Socks5ProxyAgent.md：域名一律交给代理），两种都写成 socks5://。SOCKS5 的凭据写在 URL 的 userinfo 里（用户名、密码各自 encodeURIComponent），ProxyAgent 没有别的入口。',
    );
  } else {
    notes.push('HTTP 代理的凭据用文档的写法：构造参数 token: "Basic " + base64(用户名:密码)。每个用户一个 ProxyAgent，按请求传 dispatcher。');
  }
  return { attempt: true, unsupported: null, env: {}, config: cfg.join('\n'), notes };
}

export async function create(run) {
  const { ProxyAgent, fetch } = await import('undici');
  const agents = new Map();
  const client = {
    sink: null,
    extraHow:
      "node:diagnostics_channel 订阅 'undici:request:headers' 频道（undici 文档 docs/docs/api/DiagnosticsChannel.md），只记 CONNECT 请求的响应：状态码、原因短语、响应头；拿不到正文。",
    notes: [
      'default_text：成功时是 res.status、res.statusText、res.url、res.redirected、res.headers、正文前 4096 字节；' +
        '失败时是错误的类型、code、消息，沿 cause 链逐层写出（ProxyAgent 构造时抛的错也记在用到它的那一步）。' +
        'extra_text 只在串行的步骤里记（频道是进程级的，并发时分不清是哪一步的）。',
    ],
    agentFor(st) {
      const name = agentName(st);
      if (!agents.has(name)) agents.set(name, new ProxyAgent(agentArgs(run, userOf(run, st))[0]));
      return agents.get(name);
    },
    async request(st, ctx) {
      if (!ctx.parallel) this.sink = ctx.extra;
      const init = { dispatcher: this.agentFor(st), signal: ctx.signal };
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
  };
  dc.subscribe('undici:request:headers', (msg) => {
    const lines = connectMessageLines(msg);
    if (lines && client.sink) client.sink.push(...lines);
  });
  return client;
}
