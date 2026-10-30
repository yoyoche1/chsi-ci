#!/usr/bin/env node
/**
 * ChsiHook 安卓客户端 v2（Termux / PC 双端）
 * 组合指纹 + 授权码 + 服务器下发加密逻辑 + CDP 本地注入 + 心跳
 * v2：config 内嵌；本地设置界面（姓名/性别/照片下拉）；其他字段用内置默认值
 */
'use strict';
const { execSync } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const http = require('http');

const SECRET = 'ChsiHook#v5#4a7d91f2#license';
// 可写目录：pkg exe 用 exe 所在目录，node 直跑用脚本目录
const WRITABLE = process.pkg ? path.dirname(process.execPath) : __dirname;
const CFG_PATH = path.join(WRITABLE, 'config.json');
const PHOTOS_DIR = path.join(WRITABLE, 'photos');
const GUI_PORT = 8901;

// ===== 内嵌默认配置（无需手工编辑 config）=====
const EMBED = {
  server: 'http://192.168.1.101:8787',
  fields: {
    '学校名称': '内蒙古民族大学', '层次': '本科', '专业': '智能科学与技术',
    '学制': '4 年', '学历类别': '普通高等教育', '学习形式': '普通全日制',
    '分院': '', '系所': '多智能体', '入学日期': '2025年08月31日',
    '学籍状态': '在籍（注册学籍）', '预计毕业日期': '2029年07月01日',
    '离校日期': '2029年07月01日', '在线验证码': 'DEMO1234ABCD5678',
    '学信网账号': '15100205862', '学信网密码': 'Aa123123',
  },
};

function log(...a) { console.log(new Date().toISOString().slice(11, 19), ...a); }
function sh(cmd) {
  try {
    return execSync(cmd, { encoding: 'utf8', timeout: 15000, stdio: ['ignore', 'pipe', 'ignore'] }).trim();
  } catch (e) { return ''; }   // adb 不存在/命令失败都返回空，绝不抛出
}
function sha256hex(s) { return crypto.createHash('sha256').update(s, 'utf8').digest('hex'); }
// 全局兜底：任何未捕获异常写 crash.log，不闪退
process.on('uncaughtException', (e) => {
  try { fs.appendFileSync(path.join(WRITABLE, 'crash.log'), new Date().toISOString() + ' ' + (e && e.stack || String(e)) + '\n'); } catch (e2) {}
  log('⚠ 异常已捕获:', e && e.message || e);
});
process.on('unhandledRejection', (e) => {
  try { fs.appendFileSync(path.join(WRITABLE, 'crash.log'), new Date().toISOString() + ' UNHANDLED ' + (e && e.stack || String(e)) + '\n'); } catch (e2) {}
});

// ---------- 覆盖配置（设置界面保存；姓名/性别/照片/授权码）----------
let OVR = { code: '', name: '', gender: '', photo: '' };
function loadOvr() {
  try { OVR = Object.assign(OVR, JSON.parse(fs.readFileSync(CFG_PATH, 'utf8'))); } catch (e) {}
}
function saveOvr() { fs.writeFileSync(CFG_PATH, JSON.stringify(OVR, null, 2)); }

// ---------- 运行模式 ----------
const IS_TERMUX = (process.env.PREFIX || '').includes('com.termux');
const MODE = IS_TERMUX ? 'termux' : 'pc';

// ---------- 组合指纹 ----------
function propRemote(dev, name) { try { return sh(`adb -s ${dev} shell getprop ${name}`) || ''; } catch (e) { return ''; } }
function propLocal(name) { try { return sh(`getprop ${name}`) || ''; } catch (e) { return ''; } }
function cidLocal() { try { return sh('cat /sys/block/mmcblk0/device/cid') || ''; } catch (e) { return ''; } }
function cidRemote(dev) { try { return sh(`adb -s ${dev} shell cat /sys/block/mmcblk0/device/cid`) || ''; } catch (e) { return ''; } }
function collectParts(dev) {
  const parts = [];
  for (const n of ['ro.serialno', 'ro.boot.serialno']) {
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
  const big = BigInt('0x' + h.slice(0, 16));
  return String(big % 10000000000n).padStart(10, '0');
}
function fallbackId() {
  const p = path.join(WRITABLE, '.devid');
  try { return fs.readFileSync(p, 'utf8').trim(); } catch (e) {}
  const id = String(BigInt('0x' + crypto.randomBytes(8).toString('hex')) % 10000000000n).padStart(10, '0');
  fs.writeFileSync(p, id);
  return id;
}

// ---------- 授权 ----------
async function checkAuth(server, devCode, code) {
  const nonce = crypto.randomBytes(8).toString('hex');
  const r = await fetch(server.replace(/\/$/, '') + '/check', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ qq: devCode, code, bundle: 'chsi-android', ver: 'android-2.0', nonce }),
    signal: AbortSignal.timeout(15000),
  });
  const j = await r.json();
  if (!j.ok) return { ok: false, reason: j.reason || 'unknown' };
  const exp = typeof j.exp === 'string' ? Number(j.exp) : j.exp;
  if (!exp || exp < Date.now()) return { ok: false, reason: 'expired' };
  const expect = crypto.createHmac('sha256', SECRET).update(`${devCode}|${exp}|${nonce}|${j.jskey}`, 'utf8').digest('hex');
  if (expect !== j.sig) return { ok: false, reason: 'sig_mismatch' };
  if (j.jsenc && j.jsig) {
    const jexpect = crypto.createHmac('sha256', j.jskey).update(`js|${j.jsver}|${exp}|${j.jsenc}`, 'utf8').digest('hex');
    if (jexpect !== j.jsig) return { ok: false, reason: 'jsig_mismatch' };
  }
  return { ok: true, j, exp };
}
function jsDecrypt(jsencHex, jskeyHex) {
  const key = Buffer.from(jskeyHex, 'hex');
  const enc = Buffer.from(jsencHex, 'hex');
  const out = Buffer.alloc(enc.length);
  for (let b = 0; b < Math.ceil(enc.length / 32); b++) {
    const inb = Buffer.alloc(36);
    key.copy(inb, 0);
    inb.writeUInt32LE(b, 32);
    const ks = crypto.createHash('sha256').update(inb).digest();
    const n = Math.min(32, enc.length - b * 32);
    for (let i = 0; i < n; i++) out[b * 32 + i] = enc[b * 32 + i] ^ ks[i];
  }
  return out.toString('utf8');
}

// ---------- 字段与照片 ----------
function effectiveFields() {
  const f = Object.assign({}, EMBED.fields);
  if (OVR.name) f['姓名'] = OVR.name;           // 空 = 不改写姓名
  if (OVR.gender) f['性别'] = OVR.gender;        // 空 = 不改写性别
  return f;
}
function buildRulesJs() {
  const f = effectiveFields();
  const rules = Object.entries(f).map(
    ([k, v]) => `['${String(k).replace(/'/g, '')}','${String(v).replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/\n/g, '')}']`
  ).join(',');
  let photo = '';
  if (OVR.photo) {
    const p = path.join(PHOTOS_DIR, OVR.photo);
    try {
      const ext = path.extname(p).toLowerCase().replace('.', '');
      photo = 'data:image/' + (ext === 'png' ? 'png' : 'jpeg') + ';base64,' + fs.readFileSync(p).toString('base64');
    } catch (e) { photo = ''; }
  }
  return `var RULES=[${rules}];var RENAME=[];var PHOTO='${photo}';`;
}
function listPhotos() {
  try {
    return fs.readdirSync(PHOTOS_DIR).filter(f => /\.(jpe?g|png)$/i.test(f));
  } catch (e) { return []; }
}

// ---------- 本地设置界面（127.0.0.1:8901）----------
let stateLog = [];
function slog(...a) { const s = new Date().toISOString().slice(11, 19) + ' ' + a.join(' '); console.log(s); stateLog.push(s); if (stateLog.length > 200) stateLog.shift(); }

const PAGE = `<!DOCTYPE html><html lang="zh"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ChsiHook 客户端设置</title><style>
*{box-sizing:border-box;margin:0;padding:0}body{font-family:-apple-system,'Segoe UI',sans-serif;background:#0d1117;color:#c9d1d9;padding:24px;max-width:520px;margin:0 auto}
h1{font-size:18px;margin-bottom:14px;color:#58a6ff}.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;margin-bottom:14px}
label{display:block;font-size:12px;color:#8b949e;margin:10px 0 4px}input,select{width:100%;padding:8px;background:#0d1117;color:#c9d1d9;border:1px solid #30363d;border-radius:6px;font-size:14px}
button{padding:8px 16px;background:#238636;color:#fff;border:0;border-radius:6px;font-size:14px;cursor:pointer;margin-top:12px}.dev{font-size:20px;color:#f0883e;font-weight:bold;user-select:all}
#msg{color:#3fb950;margin-top:10px;font-size:13px;min-height:18px}.hint{font-size:11px;color:#6e7681;margin-top:4px}
</style></head><body>
<h1>ChsiHook 安卓客户端</h1>
<div class="card"><label>设备码（发给管理员换授权码）</label><div class="dev" id="dev">…</div></div>
<div class="card"><label>授权码</label><input id="code" placeholder="CHSI-XXXX-XXXX-XXXX"><button onclick="save()">保存并应用</button>
<div class="hint">保存后自动连接授权服务器；下方日志出现「✅ 授权有效」即可</div></div>
<div class="card"><label>姓名（留空 = 不改写）</label><input id="name" placeholder="例如：张三"></div>
<div class="card"><label>性别</label><select id="gender"><option value="">不改写</option><option value="男">男</option><option value="女">女</option></select></div>
<div class="card"><label>照片（photos 文件夹里的 jpg/png）</label><select id="photo"><option value="">不换照片</option></select>
<div class="hint" id="pHint"></div></div>
<button onclick="save()">保存并应用</button>
<div id="msg"></div>
<div class="card" style="margin-top:14px"><label>运行日志</label><div id="logs" style="font-size:11px;color:#8b949e;white-space:pre-wrap;max-height:160px;overflow:auto"></div></div>
<script>
async function refresh(){const s=await (await fetch('/status')).json();
 document.getElementById('dev').textContent=s.devCode||'…';
 document.getElementById('code').value=s.code||'';
 document.getElementById('name').value=s.name||'';
 document.getElementById('gender').value=s.gender||'';
 const sel=document.getElementById('photo');sel.innerHTML='<option value="">不换照片</option>';
 (s.photos||[]).forEach(p=>{const o=document.createElement('option');o.value=p;o.textContent=p;if(p===s.photo)o.selected=true;sel.appendChild(o);});
 document.getElementById('pHint').textContent=(s.photos||[]).length?('共 '+s.photos.length+' 张——把新照片放进 photos 文件夹后刷新本页'):'photos 文件夹不存在或为空——把 jpg/png 放进去后刷新本页';
 document.getElementById('logs').textContent=(s.logs||[]).join('\\n');}
async function save(){const b={code:document.getElementById('code').value.trim(),name:document.getElementById('name').value.trim(),gender:document.getElementById('gender').value,photo:document.getElementById('photo').value};
 const r=await (await fetch('/save',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)})).json();
 document.getElementById('msg').textContent=r.ok?'已保存，正在应用…':'失败: '+(r.err||'');refresh();}
refresh();setInterval(refresh,5000);
</script></body></html>`;

let stateLogSeen = 0;
function startGui() {
  http.createServer((req, res) => {
    const u = req.url.split('?')[0];
    if (req.method === 'GET' && u === '/') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(PAGE);
    } else if (req.method === 'GET' && u === '/status') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ devCode: DEV_CODE || '', code: OVR.code, name: OVR.name, gender: OVR.gender, photo: OVR.photo, photos: listPhotos(), authed, logs: stateLog.slice(-40) }));
    } else if (req.method === 'POST' && u === '/save') {
      let body = '';
      req.on('data', (c) => { body += c; if (body.length > 1e5) req.destroy(); });
      req.on('end', () => {
        try {
          const j = JSON.parse(body || '{}');
          if (j.code !== undefined) OVR.code = String(j.code).trim();
          if (j.name !== undefined) OVR.name = String(j.name).trim().slice(0, 20);
          if (j.gender !== undefined) OVR.gender = String(j.gender).trim();
          if (j.photo !== undefined) {
            const p = String(j.photo);
            OVR.photo = listPhotos().includes(p) ? p : '';
          }
          saveOvr();
          authed = false;  // 码可能变了 → 立即重新授权
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end('{"ok":true}');
        } catch (e) { res.writeHead(400); res.end('{"ok":false}'); }
      });
    } else { res.writeHead(404); res.end(); }
  }).listen(GUI_PORT, '127.0.0.1', () => {
    slog('设置界面: http://127.0.0.1:' + GUI_PORT);
    if (process.platform === 'win32') {
      try { execSync('start "" "http://127.0.0.1:' + GUI_PORT + '"', { shell: 'cmd.exe', timeout: 5000, stdio: 'ignore' }); } catch (e) {}
    }
  });
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

// ---------- 会话与主循环 ----------
let session = null;
let authed = false;
let DEV_CODE = '';

async function ensureAuth(server, devCode) {
  if (session && session.exp > Date.now() + 60000 && authed) return true;
  if (!OVR.code) { slog('未填授权码——在设置界面填入后点保存'); authed = false; return false; }
  const r = await checkAuth(server, devCode, OVR.code);
  if (!r.ok) { slog('授权失败:', r.reason); authed = false; return false; }
  const jsPlain = r.j.jsenc ? jsDecrypt(r.j.jsenc, r.j.jskey) : null;
  session = { exp: r.exp, jsPlain };
  authed = true;
  slog('✅ 授权有效（到期', new Date(r.exp).toISOString().slice(11, 19), '）');
  return true;
}

async function mainLoop() {
  const dev0 = MODE === 'termux' ? null : pickDevice();
  if (MODE !== 'termux' && !dev0) { slog('❌ 未发现 adb 设备（模拟器没开或 adb connect 未执行）'); }

  let payload = '';
  let payloadTs = 0;
  let socketName = null;

  while (true) {
    try {
      const ok = await ensureAuth(EMBED.server, DEV_CODE);
      if (!ok) { await new Promise(r => setTimeout(r, 5000)); continue; }

      const devArg = MODE === 'termux' ? 'localhost:5555' : (pickDevice() || dev0);
      if (!devArg) { slog('❌ 未发现 adb 设备'); await new Promise(r => setTimeout(r, 5000)); continue; }
      const socks = findDevtoolsSockets(devArg);
      if (!socks.length) { slog('等待内核调试口（QQ 打开 debugx5.qq.com 勾选 Inspect 开关后杀 QQ 重开）…'); await new Promise(r => setTimeout(r, 5000)); continue; }
      if (socks[0] !== socketName) {
        socketName = socks[0];
        adb(`-s ${devArg} forward tcp:9222 localabstract:${socketName}`);
        slog('devtools socket:', socketName);
      }

      // 30 秒最多重建一次 payload（姓名/性别/照片改动后自动生效）
      if (!payload || Date.now() - payloadTs > 30000) {
        payload = buildRulesJs() + '\n' + (session.jsPlain || '');
        payloadTs = Date.now();
      }
      const pages = await listPages(9222);
      for (const t of pages) {
        if (!t.url || !t.url.includes('chsi.com.cn')) continue;
        if (!t.webSocketDebuggerUrl) continue;
        const ok2 = await injectViaCDP(t, payload);
        if (ok2) slog('✅ 已注入:', t.url.slice(0, 70));
      }
    } catch (e) { /* socket 断开等，下轮重试 */ }
    await new Promise(r => setTimeout(r, 1500));
    if (Date.now() > session.exp - 60000) {
      const ok3 = await ensureAuth(EMBED.server, DEV_CODE);
      if (!ok3) { slog('授权失效——在设置界面重新填码保存'); await new Promise(r => setTimeout(r, 5000)); }
    }
  }
}

// ---------- 入口 ----------
(async () => {
  log('ChsiHook 安卓客户端 v2 · 模式:', MODE);
  loadOvr();
  const dev = MODE === 'termux' ? null : pickDevice();
  DEV_CODE = (MODE === 'termux' ? deviceFingerprint('') : deviceFingerprint(dev)) || fallbackId();
  log('本机设备码:', DEV_CODE);
  try { if (!fs.existsSync(PHOTOS_DIR)) fs.mkdirSync(PHOTOS_DIR); } catch (e) {}
  startGui();
  await mainLoop().catch(e => { log('异常:', e.message); process.exit(1); });
})();
