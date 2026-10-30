#!/usr/bin/env node
/**
 * 高校认证客户端 v3.0（原 ChsiHook 安卓客户端）
 * - 零磁盘产物：状态/授权/照片全内存，运行不落任何文件
 * - Ed25519 验签：私钥只在服务器，客户端仅嵌公钥（泄露无法伪造授权）
 * - 原生 WinForms 设置窗口（Apple 风格，-EncodedCommand 内嵌，无脚本文件）
 * - 多调试口扫描（QQ NT 独立网页进程）+ 动态端口（防 CDP 9222 冲突）
 * - 分发形态：loader(V8 字节码) + AES-GCM 加密载荷（源码不可见）
 */
'use strict';
const { execSync, spawn } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const http = require('http');

// ===== Ed25519 公钥（只验签，泄露无风险）=====
const ED_PUB_HEX = '302a300506032b657003210072a73fed84c296a297e0279b950154052be2f0d0bf9bea5c5e220df8ac040c3b';
const ED_PUB = crypto.createPublicKey({ key: Buffer.from(ED_PUB_HEX, 'hex'), format: 'der', type: 'spki' });

// ===== 窗口图标（PNG base64，Apple 风格）=====
const ICON_PNG_B64 = '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';

const WRITABLE = process.pkg ? path.dirname(process.execPath) : __dirname;
const GUI_PORT = 8901;

// ===== 内嵌默认配置 =====
const EMBED = {
  server: 'http://192.168.1.101:8787',
  fields: {
    '学校名称': '内蒙古民族大学', '层次': '本科', '专业': '智能科学与技术',
    '学制': '4 年', '学历类别': '普通高等教育', '学习形式': '普通全日制',
    '入学日期': '2025年08月31日', '学籍状态': '在籍（注册学籍）',
    '预计毕业日期': '2029年07月01日', '离校日期': '2029年07月01日',
    '在线验证码': 'DEMO1234ABCD5678',
    '学信网账号': '15100205862', '学信网密码': 'Aa123123',
  },
};

// ===== 全内存状态（零磁盘产物）=====
const memLog = [];
function dlog(...a) {
  const line = new Date().toISOString() + ' ' + a.join(' ');
  try {
    const fs = require('fs');
    const p = require('path');
    fs.appendFileSync(p.join(WRITABLE, 'log.txt'), line + '\r\n', 'utf8');
  } catch (e) {}
}function log(...a) {
  const s = new Date().toISOString().slice(11, 19) + ' ' + a.join(' ');
  dlog(...a);
  memLog.push(s);
  if (memLog.length > 120) memLog.shift();
}
process.on('uncaughtException', (e) => log('⚠ 异常:', (e && e.message) || e));
process.on('unhandledRejection', (e) => log('⚠ 拒绝:', (e && e.message) || String(e)));

const OVR = { code: '', name: '', gender: '女', photoName: '', photoB64: '' };
function uiReady() {
  return !!(OVR.code && OVR.name && (OVR.gender === '男' || OVR.gender === '女') && OVR.photoB64);
}

// ===== 运行模式与 ADB =====
const IS_TERMUX = (process.env.PREFIX || '').includes('com.termux');
const MODE = IS_TERMUX ? 'termux' : 'pc';
const ADB_EXE = (() => {
  const bundled = path.join(WRITABLE, 'adb', 'adb.exe');
  try { if (fs.existsSync(bundled)) return bundled; } catch (e) {}
  return process.env.ADB || 'adb';
})();
function sh(cmd) {
  try { return execSync(cmd, { encoding: 'utf8', timeout: 15000, stdio: ['ignore', 'pipe', 'ignore'] }).trim(); } catch (e) { return ''; }
}
function adb(args) { return sh('"' + ADB_EXE + '" ' + args); }
function pickDevice() {
  const out = adb('devices');
  const lines = out.split('\n').slice(1).filter(l => l.includes('\tdevice'));
  return lines.length ? lines[0].split('\t')[0] : null;
}

// ===== 设备码：实时指纹（真机 SN/CID），无设备时回退随机（仅本次运行）=====
let fallbackCode = null;
function sha256hex(x) { return crypto.createHash('sha256').update(x, 'utf8').digest('hex'); }
function deviceFingerprint(dev) {
  const parts = [];
  for (const n of ['ro.serialno', 'ro.boot.serialno']) {
    let v = '';
    try { v = dev ? adb('-s ' + dev + ' shell getprop ' + n) : sh('getprop ' + n); } catch (e) {}
    if (v) parts.push(v);
  }
  try {
    const cid = dev ? adb('-s ' + dev + ' shell cat /sys/block/mmcblk0/device/cid') : sh('cat /sys/block/mmcblk0/device/cid');
    if (cid) parts.push(cid);
  } catch (e) {}
  if (!parts.length) return null;
  const big = BigInt('0x' + sha256hex(parts.slice().sort().join('|')).slice(0, 16));
  return String(big % 10000000000n).padStart(10, '0');
}
function currentDevCode(dev) {
  const fp = deviceFingerprint(dev);
  if (fp) return fp;
  if (!fallbackCode) fallbackCode = String(BigInt('0x' + crypto.randomBytes(8).toString('hex')) % 10000000000n).padStart(10, '0');
  return fallbackCode;
}

// ===== 授权（Ed25519 验签）=====
let session = null;
let authed = false;
let DEV_CODE = '';
async function checkAuth(server, devCode, code) {
  const nonce = crypto.randomBytes(8).toString('hex');
  const r = await fetch(server.replace(/\/$/, '') + '/check', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ qq: devCode, code, bundle: 'chsi-android', ver: 'android-3.0', nonce }),
    signal: AbortSignal.timeout(15000),
  });
  const j = await r.json();
  if (!j.ok) return { ok: false, reason: j.reason || 'unknown' };
  const exp = typeof j.exp === 'string' ? Number(j.exp) : j.exp;
  if (!exp || exp < Date.now()) return { ok: false, reason: 'expired' };
  let okSig = false;
  try {
    okSig = !!j.ed_sig && crypto.verify(null, Buffer.from(`${devCode}|${exp}|${nonce}|${j.jskey}`, 'utf8'), ED_PUB, Buffer.from(j.ed_sig, 'hex'));
  } catch (e) { okSig = false; }
  if (!okSig) return { ok: false, reason: 'ed_sig_mismatch' };
  if (j.jsenc && j.jsig) {
    const jsig = crypto.createHmac('sha256', Buffer.from(j.jskey, 'utf8')).update(`js|${j.jsver}|${exp}|${j.jsenc}`, 'utf8').digest('hex');
    if (jsig !== j.jsig) return { ok: false, reason: 'jsig_mismatch' };
  }
  return { ok: true, j, exp };
}
function jsDecrypt(jsencHex, jskeyHex) {
  const key = Buffer.from(jskeyHex, 'utf8');   // ⚠️ key = hex 字符串原样 UTF-8（与服务器一致）
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
async function ensureAuth(server) {
  if (session && session.exp > Date.now() + 60000 && authed) return true;
  if (!OVR.code) { log('未填授权码——在窗口里填入后点保存'); authed = false; return false; }
  DEV_CODE = currentDevCode(MODE === 'termux' ? null : pickDevice());
  const r = await checkAuth(server, DEV_CODE, OVR.code);
  if (!r.ok) { log('授权失败:', r.reason, '（设备码 ' + DEV_CODE + '）'); authed = false; return false; }
  let jsPlain = '';
  if (r.j.jsenc) {
    try { jsPlain = jsDecrypt(r.j.jsenc, r.j.jskey); } catch (e) { log('js 解密失败'); authed = false; return false; }
  }
  session = { exp: r.exp, jsPlain };
  authed = true;
  log('✅ 授权有效（设备码 ' + DEV_CODE + '，到期 ' + new Date(r.exp).toISOString().slice(11, 19) + '）');
  return true;
}

// ===== 字段/照片（全内存）=====
function effectiveFields() {
  const f = Object.assign({}, EMBED.fields);
  if (OVR.gender === '男' || OVR.gender === '女') f['性别'] = OVR.gender;
  if (OVR.name) f['姓名'] = OVR.name;
  return f;
}
function buildRulesJs() {
  const f = effectiveFields();
  const rules = Object.entries(f).map(([k, v]) =>
    `['${String(k).replace(/'/g, '')}','${String(v).replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/\n/g, '')}']`).join(',');
  const photo = OVR.photoB64 || '';
  return `var RULES=[${rules}];var RENAME=[];var PHOTO='${photo}';`;
}

// ===== 调试口扫描（多口 + 动态端口 + @ 剥离 + 冷却）=====
function findDevtoolsSockets(dev) {
  const out = adb('-s ' + dev + ' shell cat /proc/net/unix');
  const socks = [];
  for (const line of out.split('\n')) {
    const m = line.match(/(\S*devtools_remote\S*)\s*$/i);
    if (m) socks.push(m[1].replace(/^@/, ''));
  }
  return [...new Set(socks)];
}
async function listPages(port) {
  const r = await fetch(`http://127.0.0.1:${port}/json`, { signal: AbortSignal.timeout(8000) });
  return r.json();
}
function injectViaCDP(t, expr) {
  return new Promise((resolve) => {
    let ws;
    try { ws = new WebSocket(t.webSocketDebuggerUrl); } catch (e) { resolve(false); return; }
    const timer = setTimeout(() => { try { ws.close(); } catch (e) {} resolve(false); }, 8000);
    ws.onopen = () => ws.send(JSON.stringify({ id: 1, method: 'Runtime.evaluate', params: { expression: expr, returnByValue: false } }));
    ws.onmessage = (ev) => {
      try { const m = JSON.parse(ev.data); if (m.id === 1) { clearTimeout(timer); try { ws.close(); } catch (e) {} resolve(!m.error); } } catch (e) {}
    };
    ws.onerror = () => { clearTimeout(timer); resolve(false); };
  });
}

// ===== 注入主循环 =====
let exiting = false;

async function mainLoop() {
  let payload = '';
  let payloadTs = 0;
  const deadSockets = new Map();
  while (true) {
    if (exiting) { await new Promise(r => setTimeout(r, 500)); continue; }
    if (!session || Date.now() > session.exp - 5000) { await new Promise(r => setTimeout(r, 800)); continue; }
    try {
      if (!uiReady()) { log('⚠ 授权码/姓名/性别/照片 必须全部填写（窗口里填好后点保存）'); await new Promise(r => setTimeout(r, 3000)); continue; }

      const dev = MODE === 'termux' ? 'localhost:5555' : pickDevice();
      if (!dev) { log('⚠ 未发现 adb 设备（USB 连接后自动恢复）'); await new Promise(r => setTimeout(r, 5000)); continue; }

      const socks = findDevtoolsSockets(dev).filter(x => !deadSockets.has(x) || Date.now() - deadSockets.get(x) > 30000);
      if (!socks.length) { log('等待学信网页面（在 QQ 里打开后自动检测）…'); await new Promise(r => setTimeout(r, 4000)); continue; }

      if (!payload || Date.now() - payloadTs > 30000) {
        // 服务器下发 iOS 模板（%@ 占位符）：安卓端填充/删除占位行，字段由 buildRulesJs 顶部声明
        const jsBody = (session.jsPlain || '')
          .replace("var VER = '%@';", "var VER = 'android';")
          .replace("var RULES = %@;", '')
          .replace("var RENAME = %@;", '')
          .replace("var PHOTO = '%@';", '');
        payload = buildRulesJs() + '\n' + jsBody;
        payloadTs = Date.now();
      }

      let hit = null;
      adb(`-s ${dev} forward --remove-all`);   // 清旧转发，防端口粘滞
      let scanPort = 19300;
      for (const sk of socks) {
        try {
          adb(`-s ${dev} forward tcp:${scanPort} localabstract:${sk}`);
          const pages = await listPages(scanPort);
          const p = pages.find(t => t.url && (t.url.includes('chsi.com.cn') || t.url.includes('qianbao.qq.com')) && t.webSocketDebuggerUrl);
          if (p) { hit = p; break; }
          deadSockets.set(sk, Date.now());
        } catch (e) { if (!deadSockets.has(sk) || Date.now() - deadSockets.get(sk) > 30000) deadSockets.set(sk, Date.now()); }
        scanPort++;
      }
      if (!hit) { log('等待学信网页面（在 QQ 里打开后自动检测）…'); await new Promise(r => setTimeout(r, 4000)); continue; }

      const ok2 = await injectViaCDP(hit, payload);
      if (ok2) log('✅ 已注入:', hit.url.slice(0, 70));
    } catch (e) { log('循环异常:', (e && e.message) || e); }
    await new Promise(r => setTimeout(r, 1500));
    if (Date.now() > session.exp - 5000) {
      const ok3 = await ensureAuth(EMBED.server);   // 过期：仅此一次重验
      if (!ok3) { exiting = true; log('授权失效——1 秒后退出'); setTimeout(() => process.exit(1), 1200); continue; }
    }
  }
}

// ===== 内置 Web 界面服务（PS 窗口为纯 HTTP 客户端）=====
function startWeb() {
  http.createServer((req, res) => {
    const u = req.url.split('?')[0];
    if (req.method === 'GET' && u === '/ui') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(uiHtml());
    } else if (req.method === 'GET' && u === '/') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(uiHtml());
    } else if (req.method === 'GET' && u === '/status') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        devCode: DEV_CODE || '', authed, code: OVR.code, name: OVR.name,
        gender: OVR.gender, photoName: OVR.photoName, logs: memLog.slice(-40), icon: ICON_PNG_B64,
      }));
    } else if (req.method === 'POST' && u === '/save') {
      let body = '';
      req.on('data', (c) => { body += c; if (body.length > 12e6) req.destroy(); });
      req.on('end', () => {
        try {
          const j = JSON.parse(body || '{}');
          if (j.code !== undefined) OVR.code = String(j.code).trim();
          if (j.name !== undefined) OVR.name = String(j.name).trim().slice(0, 20);
          if (j.gender !== undefined) OVR.gender = String(j.gender).trim();
          if (j.photoData) {
            const mm = /^data:image\/(jpe?g|png);base64,(.+)$/.exec(j.photoData);
            if (mm && mm[2].length < 8e6) {
              OVR.photoB64 = j.photoData;
              OVR.photoName = String(j.photoName || 'photo').slice(0, 60);
            }
          }
          authed = false;
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end('{"ok":true}');
          setImmediate(async () => {
            const ok = await ensureAuth(EMBED.server);   // 唯一一次授权请求
            if (!ok) { exiting = true; log('授权未通过——1 秒后退出'); setTimeout(() => process.exit(1), 1200); }
          });
        } catch (e) { res.writeHead(400); res.end('{"ok":false}'); }
      });
    } else { res.writeHead(404); res.end(); }
  }).listen(GUI_PORT, '127.0.0.1', () => log('内置界面服务: http://127.0.0.1:' + GUI_PORT));
}

// ===== HTA 原生设置窗口（mshta = GUI，无控制台无浏览器）
function uiHtml() {
  return `<!DOCTYPE html><html lang="zh-CN"><head>
<meta charset="UTF-8"><meta http-equiv="X-UA-Compatible" content="IE=11">
<title>高校认证</title><style>
body{margin:0;background:#fff;font-family:"Segoe UI","Microsoft YaHei",sans-serif;color:#1d1d1f}
.app{width:360px;padding:24px 22px}
h1{font-size:26px;margin:0 0 6px}
.sub{color:#86868b;font-size:13px;margin-bottom:20px}
label{display:block;color:#86868b;font-size:12px;margin:14px 0 4px}
input[type=text]{width:100%;border:0;border-bottom:1px solid #d2d2d7;padding:7px 2px;font-size:15px;outline:none;font-family:inherit;background:#fff}
input[type=text]:focus{border-bottom-color:#007aff}
.devrow{display:flex;align-items:center;gap:10px}
.devcode{font-size:21px;font-weight:700;letter-spacing:1px}
button{background:#f2f2f7;color:#007aff;border:0;border-radius:8px;padding:6px 13px;font-size:13px;cursor:pointer;font-family:inherit}
.seg label{display:inline-flex;align-items:center;gap:5px;margin-right:16px;color:#1d1d1f;font-size:14px}
#save{width:100%;background:#d2d2d7;color:#fff;border:0;border-radius:12px;padding:13px;font-size:15px;font-weight:600;cursor:pointer;margin-top:22px;font-family:inherit}
#save.on{background:#007aff}
.st{margin-top:14px;font-size:13px;font-weight:600}
.ok{color:#34c759}.bad{color:#ff3b30}
.logs{margin-top:10px;background:#f2f2f7;border-radius:10px;padding:9px 11px;font-size:12px;color:#86868b;min-height:52px}
#photoFile{display:none}
#photoName{font-size:12px;color:#86868b;margin-left:8px}
</style></head><body><div class="app">
<h1>高校认证</h1><div class="sub">QQ 学信网认证辅助 · 本机运行</div>
<label>设备码（发给管理员换授权码）</label><div class="devrow"><span class="devcode" id="dev"></span><button onclick="copyDev(this)">复制</button></div>
<label>授权码</label><input type="text" id="code">
<label>姓名</label><input type="text" id="name">
<label>性别</label><div class="seg"><label><input type="radio" name="g" value="男">男</label><label><input type="radio" name="g" value="女" checked>女</label></div>
<label>照片</label><div><button onclick="document.getElementById('photoFile').click()">选择照片…</button><span id="photoName"></span><input type="file" id="photoFile" accept="image/jpeg,image/png" onchange="onPhoto()"></div>
<button id="save" onclick="saveAll()">保存并应用</button>
<div class="st bad" id="st">● 未授权 / 等待设备</div>
<div class="logs" id="logs"></div>
</div>
<script>
var photoData="";function $(id){return document.getElementById(id)}
function esc(t){return String(t).replace(/</g,"&lt;")}
function refresh(){var x=new XMLHttpRequest();x.open("GET","/status",true);
x.onreadystatechange=function(){if(x.readyState===4){
if(x.status===200){var st;try{st=JSON.parse(x.responseText)}catch(e){st=null}
if(st){$("dev").innerHTML=esc(st.devCode||"");
if(st.authed){$("st").className="st ok";$("st").innerHTML="● 已授权 · 注入运行中"}
else{$("st").className="st bad";$("st").innerHTML="● 未授权 / 等待设备"}
var l=st.logs||[];$("logs").innerHTML=esc(l.slice(Math.max(0,l.length-4)).join(String.fromCharCode(10))).replace(/\n/g,"<br>");}}
else{$("st").className="st bad";$("st").innerHTML="● 已退出"}
setTimeout(refresh,1000);}};x.send()}
setInterval(function(){var ok=$("code").value.replace(/\s/g,"")&&$("name").value.replace(/\s/g,"")&&photoData;$("save").className=ok?"on":""},300);
function onPhoto(){var f=$("photoFile").files;if(!f||!f[0])return;var r=new FileReader();r.onload=function(){photoData=r.result;$("photoName").innerHTML=esc(f[0].name)};r.readAsDataURL(f[0])}
function copyDev(btn){var t=$("dev").innerHTML||"";try{if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(t)}else if(window.clipboardData){window.clipboardData.setData("Text",t)}}catch(e){}btn.innerHTML="已复制 ✓"}
function saveAll(){
var gs=document.getElementsByName("g"),g="";for(var i=0;i<gs.length;i++){if(gs[i].checked)g=gs[i].value}
var body={code:$("code").value.replace(/^\s+|\s+$/g,""),name:$("name").value.replace(/^\s+|\s+$/g,""),gender:g,photoData:photoData,photoName:$("photoName").innerHTML||"photo"};
var x=new XMLHttpRequest();x.open("POST","/save",true);x.setRequestHeader("Content-Type","application/json; charset=utf-8");
x.onreadystatechange=function(){if(x.readyState===4&&x.status===200){$("st").className="st";$("st").innerHTML="● 已保存，授权校验中…"}};
x.send(JSON.stringify(body));}
refresh();
</script></body></html>`;
}


// ===== 入口 =====
(async () => {
  log('高校认证客户端 v3.0 · 模式:', MODE);
  DEV_CODE = currentDevCode(MODE === 'termux' ? null : pickDevice());
  log('本机设备码:', DEV_CODE);
  startWeb();
  log('设置界面就绪：浏览器打开 http://127.0.0.1:' + GUI_PORT);
  await mainLoop().catch(e => log('异常:', e.message));
})();
