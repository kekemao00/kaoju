// 两列环境变量写法（node-fetch-env、node-http-env）共用的部分。

import { distinctUsers, proxyUrlWithUserinfo } from './common.mjs';

/** 整个用例里用到的那一个用户（没有就是 null）。 */
export function theUser(run) {
  let idx = null;
  const walk = (steps) => {
    for (const st of steps || []) {
      if (st.op === 'parallel') walk(st.steps);
      else if (st.user !== null && st.user !== undefined) idx = st.user;
    }
  };
  walk(run.steps);
  return idx === null ? null : run.users[idx];
}

function sh(v) {
  return "'" + String(v).replace(/'/g, "'\\''") + "'";
}

/**
 * 环境变量写法的计划：变量怎么设、能不能试。
 * extraEnv 是这一列另外要加的变量（node-http-env 的 NODE_DEBUG）。
 */
export function envPlan(run, extraEnv = {}) {
  const notes = [];
  if (distinctUsers(run) > 1) {
    return {
      attempt: false,
      unsupported:
        '环境变量一个进程只有一份，node 启动时读一次（doc/api/http.md“Built-in Proxy Support”、doc/api/cli.md 的 NODE_USE_ENV_PROXY；' +
        '全局 dispatcher 和全局 Agent 在启动阶段按 process.env 建好），同一个进程里没有办法对不同的请求用不同的代理凭据。' +
        '文档里另有不靠环境变量的写法（Agent 的 proxyEnv 选项），那已经不是这一列。',
      notes,
    };
  }
  const user = theUser(run);
  const scheme = run.proxy.scheme;
  const url = proxyUrlWithUserinfo(scheme, run.proxy, user);
  const env = { NODE_USE_ENV_PROXY: '1', HTTP_PROXY: url, HTTPS_PROXY: url, ...extraEnv };
  const shown = { ...env, NODE_EXTRA_CA_CERTS: run.ca_file };
  const cmd = Object.entries(shown).map(([k, v]) => `${k}=${sh(v)}`).join(' ') + ' node <脚本>';
  notes.push(
    '代理和凭据全在环境变量里，在 node 进程启动之前设好：外层驱动读用例、拼变量，再启动内层 node 进程跑整个用例。' +
      '凭据写在代理 URL 的 userinfo 里，用户名、密码各自 encodeURIComponent。没有设 NO_PROXY。' +
      '信任测试 CA 用 NODE_EXTRA_CA_CERTS（往默认根证书里追加，不涉及代理）。',
  );
  let unsupported = null;
  if (scheme !== 'http') {
    unsupported =
      `这一列的代理只能写在 HTTP_PROXY、HTTPS_PROXY 里，文档（doc/api/http.md 的“Proxy URL Format”）只列了 http:// 和 https:// 两种代理 URL，没有 SOCKS5 的写法。` +
      `仍然把 ${scheme}:// 的地址照样写进这两个变量试了一次。`;
  }
  return { attempt: true, unsupported, env, cmd, notes };
}
