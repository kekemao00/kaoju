#!/usr/bin/env node
// node 五列的驱动：node-fetch-env、node-http-env、node-undici、node-agents、node-axios。
//
//   node driver.mjs --variant <列> <用例.json> <结果.json>
//   node driver.mjs --variant <列> --versions
//
// 约定见 research/phase2/PROTOCOL.md 的“驱动”一节；各列的写法和出处见本目录的 NOTES.md，
// 每列一个模块（<列>.mjs），共用的部分在 common.mjs。依赖用 npm ci 装在本目录的 node_modules。
//
// 分两层。外层（run.py 启动的这个进程）只读用例、拼环境变量，然后启动一个内层 node 进程跑整个用例：
// - NODE_EXTRA_CA_CERTS（信任测试 CA）和两列环境变量写法的 NODE_USE_ENV_PROXY、HTTP_PROXY、HTTPS_PROXY
//   都是 node 启动时读一次，进程里再改 process.env 不起作用，所以必须在内层启动之前放进它的环境。
// - 一个用例一个内层进程，从头到尾是同一个客户端实例。
// - 内层崩了、挂了，外层照样写出结果文件并正常退出。
// 外层不读、也不往下传外面的代理变量（run.py 给的环境本来就是干净的，这里再挡一次）。

import fs from 'node:fs';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  STEP_MARK,
  installStrayHandlers,
  placeholder,
  runStep,
  sleep,
  stepTimeoutMs,
  strays,
  errLines,
  writeJson,
} from './common.mjs';

const VARIANTS = ['node-fetch-env', 'node-http-env', 'node-undici', 'node-agents', 'node-axios'];
const SELF = fileURLToPath(import.meta.url);
const STDERR_KEEP = 6000;

function parseArgs(argv) {
  const a = { variant: null, versions: false, inner: false, rest: [] };
  const args = [...argv];
  while (args.length) {
    const x = args.shift();
    if (x === '--variant') a.variant = args.shift();
    else if (x.startsWith('--variant=')) a.variant = x.slice('--variant='.length);
    else if (x === '--versions') a.versions = true;
    else if (x === '--inner') a.inner = true;
    else a.rest.push(x);
  }
  return a;
}

async function loadColumn(variant) {
  if (!VARIANTS.includes(variant)) throw new Error(`不认识的列名：${variant}（只支持 ${VARIANTS.join('、')}）`);
  return import(`./${variant}.mjs`);
}

function cleanEnv() {
  const env = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (/^(https?|all|no|ftp|ws|wss)_proxy$/i.test(k)) continue;
    if (/^NODE_/.test(k) || /^npm_/i.test(k) || k === 'SSL_CERT_FILE' || k === 'SSL_CERT_DIR') continue;
    env[k] = v;
  }
  return env;
}

function flatSteps(steps, out = []) {
  for (const st of steps || []) {
    out.push(st);
    if (st.op === 'parallel') flatSteps(st.steps, out);
  }
  return out;
}

function totalBudgetMs(run) {
  let ms = 20000;
  for (const st of run.steps || []) {
    if (st.op === 'sleep') ms += st.ms || 0;
    else ms += stepTimeoutMs(run, st);
  }
  return ms;
}

// ---------- 外层 ----------

function runChild(args, env, budgetMs) {
  return new Promise((resolve) => {
    const t0 = Date.now();
    const child = spawn(process.execPath, args, { env, stdio: ['ignore', 'pipe', 'pipe'] });
    const out = [];
    const err = [];
    child.stdout.on('data', (c) => out.push(c));
    child.stderr.on('data', (c) => err.push(c));
    let killed = false;
    const timer = setTimeout(() => {
      killed = true;
      child.kill('SIGKILL');
    }, budgetMs);
    const done = (exit, sig, spawnError) => {
      clearTimeout(timer);
      resolve({
        exit,
        signal: sig,
        killed,
        spawnError,
        ms: Date.now() - t0,
        stdout: Buffer.concat(out).toString('utf8'),
        stderr: Buffer.concat(err).toString('utf8'),
      });
    };
    child.on('error', (e) => done(null, null, e));
    child.on('close', (code, sig) => done(code, sig, null));
  });
}

/** 把内层的标准错误按步骤标记切开：{步骤号: 文字}，以及标记之外的部分。 */
function splitStderr(text) {
  const per = {};
  const outside = [];
  let cur = null;
  for (const line of text.split('\n')) {
    if (line.startsWith(STEP_MARK + ' ')) {
      const [, id, what] = line.split(' ');
      cur = what === 'BEGIN' ? id : null;
      if (cur !== null && per[cur] === undefined) per[cur] = [];
      continue;
    }
    if (cur === null) outside.push(line);
    else per[cur].push(line);
  }
  return { per, outside: outside.join('\n') };
}

async function outer(variant, caseFile, resultFile) {
  const col = await loadColumn(variant);
  const run = JSON.parse(fs.readFileSync(caseFile, 'utf8'));
  const plan = col.plan(run);
  const base = {
    variant,
    versions: col.versions(),
    config: plan.config ?? null,
    unsupported: plan.unsupported ?? null,
    steps: [],
    notes: [...(plan.notes || [])],
  };
  if (!plan.attempt) {
    base.steps = flatSteps(run.steps).map((st) =>
      placeholder(st, st.op === 'sleep' || st.op === 'parallel' ? {} : { ok: false, default_text: `驱动：没有发出。${plan.unsupported}` }),
    );
    writeJson(resultFile, base);
    return;
  }
  const env = { ...cleanEnv(), NODE_EXTRA_CA_CERTS: run.ca_file, ...(plan.env || {}) };
  const r = await runChild([SELF, '--inner', '--variant', variant, caseFile, resultFile], env, totalBudgetMs(run));
  let result = null;
  try {
    result = JSON.parse(fs.readFileSync(resultFile, 'utf8'));
  } catch {
    result = null;
  }
  const { per, outside } = splitStderr(r.stderr);
  const how = r.spawnError
    ? `内层 node 进程没能启动：${errLines(r.spawnError).join(' / ')}`
    : r.killed
      ? `内层 node 进程在 ${Math.round(totalBudgetMs(run) / 1000)} 秒后还没结束，被外层杀掉`
      : `内层 node 进程的退出码是 ${r.exit}${r.signal ? `（信号 ${r.signal}）` : ''}`;
  const ended = !r.spawnError && !r.killed && r.exit === 0;
  if (result === null) {
    // 内层没写出任何结果：多半是在跑到驱动代码之前就退出了（启动阶段读环境变量时抛错）
    result = base;
    const text = [
      `${how}，没有执行到驱动的任何一步。它的标准错误（节选）：`,
      r.stderr.slice(0, STDERR_KEEP) || '（空）',
    ].join('\n');
    result.steps = flatSteps(run.steps).map((st) =>
      placeholder(st, st.op === 'sleep' || st.op === 'parallel' ? {} : { ok: false, default_text: text }),
    );
    if (result.unsupported) result.unsupported += ` 试了一次：${how}，标准错误的头一段：${r.stderr.trim().split('\n').slice(0, 6).join(' | ').slice(0, 600)}`;
  } else if (!ended || !result.finished) {
    // 写了一部分就没了：补齐缺的步骤
    const have = new Set(result.steps.map((s) => s.id));
    for (const st of flatSteps(run.steps)) {
      if (have.has(st.id)) continue;
      result.steps.push(
        placeholder(st, st.op === 'sleep' || st.op === 'parallel' ? {} : {
          ok: false,
          default_text: `${how}，这一步没有结果。标准错误（节选）：\n${(per[st.id] || []).join('\n').slice(-STDERR_KEEP) || outside.slice(-STDERR_KEEP) || '（空）'}`,
        }),
      );
    }
    result.notes.push(`${how}；结果文件不完整，缺的步骤由外层补上。`);
  }
  if (typeof col.postprocess === 'function') col.postprocess(result, per);
  result.process = { exit: r.exit, signal: r.signal, killed: r.killed, ms: r.ms };
  if (outside.trim()) result.notes.push('内层进程标准错误里不属于任何步骤的部分（节选）：' + outside.trim().slice(0, 2000));
  if (r.stdout.trim()) result.notes.push('内层进程的标准输出（节选）：' + r.stdout.trim().slice(0, 1000));
  delete result.finished;
  writeJson(resultFile, result);
}

// ---------- 内层 ----------

async function inner(variant, caseFile, resultFile) {
  installStrayHandlers();
  const col = await loadColumn(variant);
  const run = JSON.parse(fs.readFileSync(caseFile, 'utf8'));
  const plan = col.plan(run);
  const result = {
    variant,
    versions: col.versions(),
    config: plan.config ?? null,
    unsupported: plan.unsupported ?? null,
    steps: [],
    notes: [...(plan.notes || [])],
    finished: false,
  };
  const save = () => writeJson(resultFile, result);
  save();
  let client;
  try {
    client = await col.create(run);
  } catch (e) {
    const text = ['驱动：建立客户端时出错（引入库或构造对象）:', ...errLines(e)].join('\n');
    for (const st of flatSteps(run.steps)) {
      result.steps.push(placeholder(st, st.op === 'sleep' || st.op === 'parallel' ? {} : { ok: false, default_text: text }));
    }
    result.finished = true;
    save();
    return;
  }
  if (client.notes) result.notes.push(...client.notes);
  for (const st of run.steps || []) {
    if (st.op === 'sleep') {
      await sleep(st.ms || 0);
      result.steps.push(placeholder(st, { ms: st.ms || 0 }));
    } else if (st.op === 'parallel') {
      const kids = st.steps || [];
      result.steps.push(placeholder(st, { children: kids.map((k) => k.id) }));
      // 同一轮事件循环里把这一组全部发出，再一起等
      const rs = await Promise.all(kids.map((k) => runStep(client, run, k, true)));
      result.steps.push(...rs);
    } else if (st.op === 'request' || st.op === 'ws') {
      process.stderr.write(`\n${STEP_MARK} ${st.id} BEGIN\n`);
      const r = await runStep(client, run, st, false);
      process.stderr.write(`\n${STEP_MARK} ${st.id} END\n`);
      result.steps.push(r);
    } else {
      result.steps.push(placeholder(st, { ok: false, default_text: `驱动：不认识的步骤类型 ${st.op}，没有发出任何东西` }));
    }
    save();
  }
  const late = strays.length;
  await sleep(50); // 让刚结束的那一步可能留下的异步报错有机会冒出来
  if (strays.length > late) {
    result.notes.push('最后一步结束以后出现的进程级异常：' + strays.slice(late).map((s) => s.lines.join(' / ')).join(' | '));
  }
  result.finished = true;
  save();
}

// ---------- 入口 ----------

async function main() {
  const a = parseArgs(process.argv.slice(2));
  if (a.versions) {
    const col = await loadColumn(a.variant);
    const v = col.versions();
    const sorted = Object.fromEntries(Object.keys(v).sort().map((k) => [k, v[k]]));
    process.stdout.write(JSON.stringify(sorted) + '\n');
    return 0;
  }
  if (a.rest.length !== 2 || !a.variant) {
    process.stderr.write('用法：driver.mjs --variant <列> <用例.json> <结果.json> | --variant <列> --versions\n');
    return 2;
  }
  if (a.inner) {
    await inner(a.variant, a.rest[0], a.rest[1]);
    return 0;
  }
  try {
    await outer(a.variant, a.rest[0], a.rest[1]);
  } catch (e) {
    // 外层自己出了错也要留下结果文件
    writeJson(a.rest[1], {
      variant: a.variant,
      versions: null,
      config: null,
      unsupported: null,
      steps: [],
      notes: ['驱动外层出错：' + errLines(e).join(' / ')],
    });
  }
  return 0;
}

main().then(
  (code) => process.exit(code),
  (e) => {
    process.stderr.write('驱动出错：' + errLines(e).join('\n') + '\n');
    process.exit(1);
  },
);
