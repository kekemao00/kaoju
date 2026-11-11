// 列 node-agents：Node 内置的 http、https 模块，agent 选项传 http-proxy-agent、https-proxy-agent 或 socks-proxy-agent。

import http from 'node:http';
import https from 'node:https';
import {
  collect,
  followLoop,
  nodeResponseLines,
  nodeVersions,
  proxyUrlWithUserinfo,
  readBody,
  userOf,
  withPackages,
} from './common.mjs';

const EXTRA_HOW =
  "req.on('proxyConnect', (connect) => …)：https-proxy-agent 在读完代理对 CONNECT 的响应以后，在请求对象（和 Agent 实例）上发这个事件，" +
  '参数是 { statusCode, statusText, headers }，拿不到正文。依据是上游仓库的变更记录（6.1.0：Emit "proxyConnect" event on HTTP request object）和 dist/index.js；' +
  '随包发布的 README 和类型声明里都没有提到它。只有经 HTTP 代理访问 https:// 目标的步骤有这个手段。';

export function versions() {
  return withPackages(nodeVersions(), ['http-proxy-agent', 'https-proxy-agent', 'socks-proxy-agent', 'agent-base', 'socks']);
}

function isSocks(run) {
  return run.proxy.scheme !== 'http';
}

function agentKey(st) {
  return st.user === null || st.user === undefined ? 'NoCred' : `User${st.user}`;
}

/** 这一步（这一跳）用哪个 Agent：[变量名, 类名]。 */
function agentPick(run, st, isHttps) {
  const k = agentKey(st);
  if (isSocks(run)) return [`socksAgent${k}`, 'SocksProxyAgent'];
  return isHttps ? [`httpsAgent${k}`, 'HttpsProxyAgent'] : [`httpAgent${k}`, 'HttpProxyAgent'];
}

function agentUrl(run, st) {
  return proxyUrlWithUserinfo(run.proxy.scheme, run.proxy, userOf(run, st));
}

function callText(st, name) {
  const mod = st.url.startsWith('https:') ? 'https' : 'http';
  if (st.body_file) {
    return `req = ${mod}.request(new URL(${JSON.stringify(st.url)}), { method: ${JSON.stringify(st.method)}, agent: ${name}, headers: { 'Content-Type': 'application/octet-stream' }, signal }, cb); req.end(buf)   // buf 是 ${st.body_file} 的全部内容`;
  }
  return `req = ${mod}.request(new URL(${JSON.stringify(st.url)}), { method: ${JSON.stringify(st.method || 'GET')}, agent: ${name}, signal }, cb); req.end()`;
}

export function plan(run) {
  const notes = [];
  const cfg = [
    "import http from 'node:http'; import https from 'node:https'",
    isSocks(run)
      ? "import { SocksProxyAgent } from 'socks-proxy-agent'"
      : "import { HttpProxyAgent } from 'http-proxy-agent'; import { HttpsProxyAgent } from 'https-proxy-agent'",
  ];
  const declared = new Set();
  const declare = (st, isHttps, ind) => {
    const [name, cls] = agentPick(run, st, isHttps);
    if (!declared.has(name)) {
      declared.add(name);
      cfg.push(`${ind}const ${name} = new ${cls}(${JSON.stringify(agentUrl(run, st))})   // 第一次用到时构造，只传代理 URL、不传选项；之后整个用例都用这一个实例`);
    }
    return name;
  };
  const walk = (steps, ind) => {
    for (const st of steps || []) {
      if (st.op === 'sleep') cfg.push(`${ind}${st.id}: await new Promise(r => setTimeout(r, ${st.ms}))`);
      else if (st.op === 'parallel') {
        cfg.push(`${ind}${st.id}: await Promise.all([   // 同一轮里全部发出`);
        walk(st.steps, ind + '    ');
        cfg.push(`${ind}])`);
      } else if (st.op === 'request') {
        const name = declare(st, st.url.startsWith('https:'), ind);
        cfg.push(
          `${ind}${st.id}: ${callText(st, name)}` +
            (st.follow
              ? '   // http、https 模块不跟随重定向：响应是 301、302、303、307、308 且有 Location 时，驱动用 new URL(location, 当前URL) 再发一次 GET，按下一跳的协议选模块和 Agent（同一个用户的那一对）'
              : ''),
        );
      } else cfg.push(`${ind}${st.id}: （${st.op}：这一列不跑）`);
    }
  };
  walk(run.steps, '');
  cfg.push(
    "// signal = AbortSignal.timeout(用例的 timeout_s)；cb 里把响应读完；另挂了 req.on('proxyConnect', …) 只为记录 extra_text。" +
      '信任测试 CA 用环境变量 NODE_EXTRA_CA_CERTS（进程启动前设好），没有传 ca 选项',
  );
  if (isSocks(run)) {
    notes.push(
      `代理 URL 的协议名照用例给的写（${run.proxy.scheme}://）：socks-proxy-agent 区分 socks5（客户端自己解析域名）和 socks5h（域名交给代理）。` +
        'http 和 https 两种目标都用同一个 SocksProxyAgent。凭据写在 URL 的 userinfo 里，用户名、密码各自 encodeURIComponent。',
    );
  } else {
    notes.push(
      '明文目标用 HttpProxyAgent，https 目标用 HttpsProxyAgent（两个包 README 的分工）。凭据写在代理 URL 的 userinfo 里，用户名、密码各自 encodeURIComponent。' +
        '每个用户一对 Agent，构造只传 URL（keepAlive 等选项保持默认）。',
    );
  }
  return { attempt: true, unsupported: null, env: {}, config: cfg.join('\n'), notes };
}

export async function create(run) {
  const classes = {};
  if (isSocks(run)) {
    classes.SocksProxyAgent = (await import('socks-proxy-agent')).SocksProxyAgent;
  } else {
    classes.HttpProxyAgent = (await import('http-proxy-agent')).HttpProxyAgent;
    classes.HttpsProxyAgent = (await import('https-proxy-agent')).HttpsProxyAgent;
  }
  const agents = new Map();
  return {
    extraHow: EXTRA_HOW,
    extraApplies: (st) => !isSocks(run) && st.op === 'request' && st.url.startsWith('https:'),
    notes: [
      'default_text：成功时是 res.statusCode、res.statusMessage、res.httpVersion、req.reusedSocket、res.rawHeaders、正文前 4096 字节；' +
        '失败时是 error 事件给的错误的类型、code、消息和 cause 链（socks 库错误对象上的 options 属性不记）。' +
        'Agent 构造时抛的错记在用到它的那一步。follow 为真的步骤由驱动自己循环着跟随重定向，那几行测到的是驱动的循环加上 Agent 对每一跳的处理。',
    ],
    agentFor(st, isHttps) {
      const [name, cls] = agentPick(run, st, isHttps);
      if (!agents.has(name)) agents.set(name, new classes[cls](agentUrl(run, st)));
      return agents.get(name);
    },
    async request(st, ctx) {
      const body = readBody(st);
      const r = await followLoop(st, (url, hop) => {
        const target = new URL(url);
        const isHttps = target.protocol === 'https:';
        const mod = isHttps ? https : http;
        const agent = this.agentFor(st, isHttps);
        return collect((cb) => {
          const first = hop === 0;
          const opts = { method: first ? st.method || 'GET' : 'GET', agent, signal: ctx.signal };
          if (first && body) opts.headers = { 'Content-Type': 'application/octet-stream' };
          const req = mod.request(target, opts, cb);
          req.on('proxyConnect', (c) => {
            if (!c || c.statusCode === undefined) return; // http-proxy-agent 的同名事件只带 socket
            ctx.extra.push(`proxyConnect（${target.host}）: statusCode=${c.statusCode} statusText=${c.statusText}`);
            for (const [k, v] of Object.entries(c.headers || {})) ctx.extra.push(`  ${k}: ${Array.isArray(v) ? v.join(', ') : v}`);
          });
          if (first && body) req.end(body);
          else req.end();
          return req;
        });
      });
      return { ok: true, status: r.res.statusCode, body: r.body, lines: nodeResponseLines(r) };
    },
  };
}
