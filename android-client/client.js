#!/usr/bin/env node
/**
 * ChsiHook 安卓客户端（Termux / PC 双端）
 * 组合指纹 + 授权码验证 + 服务器下发加密逻辑 + CDP 本地注入 + 心跳复验
 *
 * 运行模式自动检测：
 *   Termux（$PREFIX 含 com.termux）→ 本地 getprop 取指纹，adb 走本机
 *   PC / 其他 → adb 连接模拟器/设备，getprop 经 adb shell 取
 *
 * 防破解：分发形态为 bytenode 字节码 / pkg 单文件 exe（源码不可见）
 */
'use strict';
const { execSync } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const os = require('os');

// 与服务器 SECRET 一致（字节码内不可见明文）
const SECRET = 'ChsiHook#v5#4a7d91f2#license';
const HERE = __dirname;
const CFG_PATH = path.join(HERE, 'config.json');

function log(...a) { console.log(new Date().toISOString().slice(11, 19), ...a); }
function sh(cmd) {
  return execSync(cmd, { encoding: 'utf8', timeout: 15000, stdio: ['ignore', 'pipe', 'ignore'] }).trim();
}
function sha256hex(s) { return crypto.createHash('sha256').update(s, 'utf8').digest('hex'); }

// ---------- 运行模式 ----------
const IS_TERMUX = (process.env.PREFIX || '').includes('com.termux');
const MODE = IS_TERMUX ? 'termux' : 'pc';

// ---------- 组合指纹 ----------
function propRemote(dev, name) { try { return sh(`adb -s ${dev} shell getprop ${name}`) || ''; } catch (e) { return ''; } }
function propLocal(name) { try { return sh(`getprop ${name}`) || ''; } catch (e) { return ''; } }
function cidLocal() { try { return sh('cat /sys/block/mmcblk0/device/cid') || ''; } catch (e) { return ''; } }
function cidRemote(dev) { try { return sh(`adb -s ${dev} shell cat /sys/block/mmcblk0/device/cid`) || ''; } catch (e) { return ''; } }

function collectParts(dev) {
  // 与 Termux 版 / PC 版使用完全相同的取值集合，保证同设备同指纹
  const names = ['ro.serialno', 'ro.boot.serialno'];
  const parts = [];
  for (const n of names) {
    const v = MODE === 'termux' ? propLocal(n) : propRemote(dev, n);
    if (v) parts.push(v);
  }
  const cid = MODE === 'termux' ? cidLocal() : cidRemote(dev);
  if (cid) parts.push(cid);
  return parts;
}

function deviceFingerprint(dev) {
  const parts = collectParts(dev);
  if (!parts.length) return null;
  const h = sha256hex(parts.slice().sort().join('|'));
  // 10 位数字设备码（通过管理页 qq 正则 ^\d{5,12}$）
  const big = BigInt('0x' + h.slice(0, 16));
  return String(big % 10000000000n).padStart(10, '0');
}

function fallbackId() {
  const p = path.join(HERE, '.devid');
  try { return fs.readFileSync(p, 'utf8').trim(); } catch (e) {}
  const id = String(BigInt('0x' + crypto.randomBytes(8).toString('hex')) % 10000000000n).padStart(10, '0');
  fs.writeFileSync(p, id);
  return id;
}

// ---------- 配置 ----------
function loadCfg() {
  try { return JSON.parse(fs.readFileSync(CFG_PATH, 'utf8')); } catch (e) { return {}; }
}
function saveCfg(c) { fs.writeFileSync(CFG_PATH, JSON.stringify(c, null, 2)); }

// ---------- 授权 ----------
function hmacSecret(qq, exp, nonce, jskey) {
  return crypto.createHmac('sha256', SECRET).update(`${qq}|${exp}|${nonce}|${jskey}`, 'utf8').digest('hex');
}
async function checkAuth(server, devCode, code) {
  const nonce = crypto.randomBytes(8).toString('hex');
  const r = await fetch(server.replace(/\/$/, '') + '/check', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ qq: devCode, code, bundle: 'chsi-android', ver: 'android-1.0', nonce }),
    signal: AbortSignal.timeout(15000),
  });
  const j = await r.json();
  if (!j.ok) return { ok: false, reason: j.reason || 'unknown' };
  const exp = typeof j.exp === 'string' ? Number(j.exp) : j.exp;
  if (!exp || exp < Date.now()) return { ok: false, reason: 'expired' };
  const expect = hmacSecret(devCode, exp, nonce, j.jskey);
  if (expect !== j.sig) return { ok: false, reason: 'sig_mismatch' };
  // jsig 校验（下发逻辑完整性）
  if (j.jsenc && j.jsig) {
    const jexpect = crypto.createHmac('sha256', j.jskey).update(`js|${j.jsver}|${exp}|${j.jsenc}`, 'utf8').digest('hex');
    if (jexpect !== j.jsig) return { ok: false, reason: 'jsig_mismatch' };
  }
  return { ok: true, j, exp };
}

// ---------- 解密下发逻辑 ----------
function jsDecrypt(jsencHex, jskeyHex) {
  const key = Buffer.from(jskeyHex, 'hex');
  const enc = Buffer.from(jsencHex, 'hex');
  const out = Buffer.alloc(enc.length);
  const blocks = Math.ceil(enc.length / 32);
  for (let b = 0; b < blocks; b++) {
    const inb = Buffer.alloc(36);
    key.copy(inb, 0);
    inb.writeUInt32LE(b, 32);
    const ks = crypto.createHash('sha256').update(inb).digest();
    const n = Math.min(32, enc.length - b * 32);
    for (let i = 0; i < n; i++) out[b * 32 + i] = enc[b * 32 + i] ^ ks[i];
  }
  return out.toString('utf8');
}

function buildRulesJs(fields) {
  const rules = Object.entries(fields || {}).map(
    ([k, v]) => `['${String(k).replace(/'/g, '')}','${String(v).replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/\n/g, '')}']`
  ).join(',');
  return `var RULES=[${rules}];var RENAME=[];var PHOTO='';`;
}

// ---------- CDP 注入 ----------
function adb(args) { return sh(`${process.env.ADB || 'adb'} ${args}`); }
function pickDevice() {
  const out = adb('devices');
  const lines = out.split('\n').slice(1).filter(l => l.includes('\tdevice'));
  return lines.length ? lines[0].split('\t')[0] : null;
}
function findDevtoolsSockets(dev) {
  const out = adb(`-s ${dev} shell cat /proc/net/unix`);
  const socks = [];
  for (const line of out.split('\n')) {
    const m = line.match(/(\S*devtools_remote\S*)$/i);
    if (m) socks.push(m[1]);
  }
  socks.sort((a, b) => (b.includes('tencent') || b.includes('mobileqq') ? 1 : 0) - (a.includes('tencent') || a.includes('mobileqq') ? 1 : 0));
  return socks;
}
async function listPages(port) {
  const r = await fetch(`http://127.0.0.1:${port}/json`, { signal: AbortSignal.timeout(4000) });
  return r.json();
}
function injectViaCDP(t, expr) {
  return new Promise((resolve) => {
    const ws = new WebSocket(t.webSocketDebuggerUrl);
    const timer = setTimeout(() => { try { ws.close(); } catch (e) {} resolve(false); }, 8000);
    ws.onopen = () => ws.send(JSON.stringify({ id: 1, method: 'Runtime.evaluate', params: { expression: expr, returnByValue: false } }));
    ws.onmessage = (ev) => {
      try { const m = JSON.parse(ev.data); if (m.id === 1) { clearTimeout(timer); try { ws.close(); } catch (e) {} resolve(!m.error); } } catch (e) {}
    };
    ws.onerror = () => { clearTimeout(timer); resolve(false); };
  });
}

// ---------- 主循环 ----------
let session = null;      // { exp, jsPlain, fields }
let authed = false;

async function ensureAuth(cfg, dev) {
  if (session && session.exp > Date.now() + 60000) return true;  // 会话有效
  const devCode = cfg.devCode;
  if (!devCode || !cfg.code) return false;
  const r = await checkAuth(cfg.server, devCode, cfg.code);
  if (!r.ok) { log('授权失败:', r.reason); authed = false; return false; }
  const jsPlain = r.j.jsenc ? jsDecrypt(r.j.jsenc, r.j.jskey) : null;
  session = { exp: r.exp, jsPlain };
  authed = true;
  log('✅ 授权有效，改写逻辑已就绪（到期', new Date(r.exp).toISOString().slice(11, 19), '）');
  return true;
}

async function mainLoop() {
  const cfg = loadCfg();
  if (!cfg.server) { log('config.json 缺 server'); process.exit(1); }
  const dev = MODE === 'termux' ? null : pickDevice();
  if (MODE !== 'termux' && !dev) { log('❌ 未发现 adb 设备'); return; }

  // 指纹（首次显示）
  let devCode = cfg.devCode;
  if (!devCode) {
    const fp = MODE === 'termux' ? deviceFingerprint('') : deviceFingerprint(dev);
    devCode = fp || fallbackId();
    cfg.devCode = devCode; saveCfg(cfg);
    log('本机设备码:', devCode, '（发给管理员换授权码）');
  }
  if (!cfg.code) { log('未配置授权码：编辑 config.json 填入 code 字段'); return; }

  const ok = await ensureAuth(cfg, dev);
  if (!ok) return;

  const payload = buildRulesJs(cfg.fields) + '\n' + (session.jsPlain || '');
  const FORWARD_PORT = 9222;
  let socketName = null;
  const injected = new Map();

  while (true) {
    try {
      if (MODE !== 'termux') {
        const d2 = pickDevice(); if (d2) cfg._dev = d2;
      }
      const socks = MODE === 'termux'
        ? findDevtoolsSockets('localhost:5555')
        : findDevtoolsSockets(cfg._dev || dev);
      if (!socks.length) throw new Error('no socket');
      if (socks[0] !== socketName) {
        socketName = socks[0];
        const devArg = MODE === 'termux' ? 'localhost:5555' : (cfg._dev || dev);
        adb(`-s ${devArg} forward tcp:${FORWARD_PORT} localabstract:${socketName}`);
        injected.clear();
        log('devtools socket:', socketName);
      }
      const pages = await listPages(FORWARD_PORT);
      for (const t of pages) {
        if (!t.url || !t.url.includes('chsi.com.cn')) continue;
        if (!t.webSocketDebuggerUrl) continue;
        if (injected.get(t.id) === t.url) continue;
        const ok2 = await injectViaCDP(t, payload);
        if (ok2) { injected.set(t.id, t.url); log('✅ 已注入:', t.url.slice(0, 80)); }
      }
      const alive = new Set(pages.map(p => p.id));
      for (const id of [...injected.keys()]) if (!alive.has(id)) injected.delete(id);
    } catch (e) {
      try {
        const socks = MODE === 'termux'
          ? findDevtoolsSockets('localhost:5555')
          : findDevtoolsSockets(cfg._dev || dev);
        if (socks.length && socks[0] !== socketName) {
          socketName = null;  // 下轮重 forward
        }
      } catch (e2) {}
    }
    await new Promise(r => setTimeout(r, 1500));
    // 心跳
    if (Date.now() > session.exp - 60000) {
      const ok3 = await ensureAuth(loadCfg(), dev);
      if (!ok3) { log('授权失效，停止注入，等待重新授权…'); return; }
    }
  }
}

// ---------- 入口 ----------
(async () => {
  log('ChsiHook 安卓客户端 · 模式:', MODE);
  const cfg = loadCfg();
  if (!cfg.server) {
    // 首次初始化
    cfg.server = 'http://192.168.1.101:8787';
    cfg.fields = cfg.fields || {
      '姓名': '', '性别': '', '学校名称': '清华大学', '层次': '本科',
      '专业': '智能科学与技术', '学制': '4 年', '学历类别': '普通高等教育',
      '学习形式': '普通全日制', '分院': '', '系所': '多智能体',
      '入学日期': '2025年08月31日', '学籍状态': '在籍（注册学籍）',
      '预计毕业日期': '2029年07月01日', '离校日期': '2029年07月01日',
      '在线验证码': 'DEMO1234ABCD5678', '更新日期': '',
      '学信网账号': '15100205862', '学信网密码': 'Aa123123',
    };
    saveCfg(cfg);
    log('已生成 config.json —— 填入 code（授权码）后重新运行');
  }
  // 显示设备码（无 devCode 时顺便生成）
  if (!cfg.devCode) {
    const dev = MODE === 'termux' ? null : pickDevice();
    const fp = deviceFingerprint(dev || '');
    cfg.devCode = fp || fallbackId();
    saveCfg(cfg);
    log('本机设备码:', cfg.devCode);
  }
  await mainLoop().catch(e => { log('异常:', e.message); process.exit(1); });
})();
