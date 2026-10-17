(function(){
var VER = '%@';
var RULES = %@;
var RENAME = %@;
var PHOTO = '%@';   // v4.6.19：照片 data URI（空串 = 不改写图片）

if (window.__chsiRewriterInstalled && window.__chsiRewriterVer === VER) {
  return window.__chsiRewrite();
}
window.__chsiRewriterVer = VER;

var applied = [];

function norm(s){ return (s||'').replace(/\s+/g,''); }

function ruleValue(t){
  for (var i=0;i<RULES.length;i++){ if (t === RULES[i][0]) return RULES[i][1]; }
  return undefined;
}

function renameValue(t){
  for (var j=0;j<RENAME.length;j++){ if (t === RENAME[j][0]) return RENAME[j][1]; }
  return undefined;
}

function isKnownLabel(t){
  if (ruleValue(t) !== undefined) return true;
  for (var j=0;j<RENAME.length;j++){ if (t === RENAME[j][0] || t === RENAME[j][1]) return true; }
  return false;
}

// ---- 值元素改写：label 元素的紧邻兄弟 ----
function setSibling(el, value, label){
  var c = el.nextElementSibling;
  if (!c || c.children.length > 0) return;
  var cur = (c.textContent||'').trim();
  if (isKnownLabel(norm(cur))) return;
  if (value === ''){
    if (cur === '') { applied.push(label+'(已空)'); return; }
    c.textContent = '';
    applied.push(label+'(清空)');
    return;
  }
  if (cur === value) { applied.push(label+'(已)'); return; }
  c.textContent = value;
  applied.push(label);
}

// ---- 1. 按报告页三种结构改（等价仓库 JS 的三组正则）----
function rewriteByClass(){
  var sels = ['.label', 'span.text', '.col-left'];
  for (var s=0;s<sels.length;s++){
    var els;
    try { els = document.querySelectorAll(sels[s]); } catch(e){ continue; }
    for (var i=0;i<els.length;i++){
      var el = els[i];
      if (el.children.length > 0) continue;
      var t = norm(el.textContent);
      var val = ruleValue(t);
      if (val !== undefined){ setSibling(el, val, t); continue; }
      var nn = renameValue(t);
      if (nn !== undefined){
        var cur2 = (el.textContent||'').trim();
        if (cur2 !== nn){ el.textContent = nn; applied.push(t+'改名'); }
      }
    }
  }
}

// ---- 2. 任意标签元素兜底（结构变化时）----
function rewriteByLabel(label, value){
  var nodes = document.querySelectorAll('div,span,td,dt,dd,p,label,th');
  for (var i=0;i<nodes.length;i++){
    var el = nodes[i];
    if (el.children.length > 0) continue;
    if (norm(el.textContent) !== label) continue;
    setSibling(el, value, label);
  }
}

function renameByLabel(from, to){
  var nodes = document.querySelectorAll('div,span,td,dt,dd,p,label,th');
  for (var i=0;i<nodes.length;i++){
    var el = nodes[i];
    if (el.children.length > 0) continue;
    if (norm(el.textContent) !== from) continue;
    el.textContent = to;
    applied.push(from+'改名(text)');
  }
}

// ---- 3. 文本节点兜底（标签埋得更深时）----
function walkText(node){
  if (node.nodeType === 3){
    var t = norm(node.nodeValue);
    var val = ruleValue(t);
    if (val !== undefined){
      var p = node.parentNode;
      if (!p) return;
      var root = p.parentNode || p;
      var tw = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, null, false);
      var found = false, n;
      while ((n = tw.nextNode())){
        // v4.6.26：跳过纯空白文本节点 —— 「预计毕业日期」这类标签 div 里带
        //   换行/空白的页面，标签与值栏之间的空白节点会被误当值节点写入，
        //   页面上日期出现两遍（真实值栏 + 标签后内联各一份）。
        if (found && !isKnownLabel(norm(n.nodeValue)) && n.nodeValue.trim() !== ''){
          if (val === '' || n.nodeValue.trim() !== val){
            n.nodeValue = val;
            applied.push(t+'(text)');
          }
          break;
        }
        if (n === node) found = true;
      }
    } else {
      var to = renameValue(t);
      if (to !== undefined){
        var cur3 = node.nodeValue.trim();
        if (cur3 !== to){ node.nodeValue = to; applied.push(t+'改名(node)'); }
      }
    }
  } else {
    for (var c=0;c<node.childNodes.length;c++) walkText(node.childNodes[c]);
  }
}

// ---- v4.6.23：照片替换（精确目标头像，兜底最大图；图晚加载靠自轮询补换）----
// 页面实证（wap_bg.html / 验证报告手机版）：
//   <img src="/report/img/….jpg" width="58" data-caption="个人头像">
// 旧版「找最大图」在真机上没换到 —— 图未加载时 naturalWidth=0、页面
// logo 等干扰，且图片加载完成不触发 MutationObserver → 永不重试。
// v4.6.23 三级目标 + PHOTO 非空时自轮询 12s（换到才停）。
function photoSwap(){
  if (!PHOTO){
    // v4.6.24 诊断：PHOTO 为空 = 本机没设置照片（或 QQ 重装后内存配置丢了）
    if (!window.__chsiPd){ window.__chsiPd = 1; applied.push('PHOTO空'); }
    return;
  }
  // v4.6.36 页面门禁：只在**报告页**换照片。真机实证：钱包流程先落到
  //   「请输入验证码」页，页头 logo 也在 /report/img/ 下，照片被换进
  //   logo → 页面 DOM 被改 → 瑞数风控校验不过 → 「发起验证」系统繁忙
  //   （18 无照片功能所以从不触发；头像偶先加载时落报告页 = 时好时坏）。
  //   门禁：页面含「学籍/验证报告」字样，或存在 data-caption 头像 img。
  var onReport = false;
  try { onReport = !!document.querySelector('img[data-caption="个人头像"]'); } catch(e) {}
  // v4.6.36：门禁只认头像 img 硬特征（验证码页 body 含「学籍」字样，文本兜底会误放行）
  if (!onReport) return;   // 非报告页：零接触（连诊断行都不产生）
  var best = null, hitLv = 0;
  // ① 精确目标：data-caption="个人头像"
  try { best = document.querySelector('img[data-caption="个人头像"]'); } catch(e) {}
  if (best) hitLv = 1;
  // ② 次选：src = /report/img/数字j+16位以上hex.jpg（头像命名模式）
  //    v4.6.34 收紧：旧条件「只要 /report/img/ 前缀」会把页头「在线验证」
  //    的 logo 小图标（同目录）先撞上 —— 照片换到 logo 上（真机截图实证）。
  //    头像特征：文件名 234852072j567b04…64486e.jpg + width="58"。
  if (!best){
    var re2 = /^\/report\/img\/\d+j[0-9a-f]{16,}\.jpg$/i;
    for (var i=0;i<document.images.length;i++){
      var di2 = document.images[i];
      var s = di2.getAttribute('src') || '';
      var wA = parseInt(di2.getAttribute('width') || '0', 10) ||
               di2.naturalWidth || di2.width || 0;
      if (re2.test(s) && wA >= 50){ best = di2; hitLv = 2; break; }
    }
  }
  // ③ 兜底：最大可见图（跳过图标/占位小图）
  if (!best){
    var area = 0, mw = 0, mh = 0;
    for (var j=0;j<document.images.length;j++){
      var im = document.images[j];
      var w = im.naturalWidth || im.width || 0;
      var h = im.naturalHeight || im.height || 0;
      if (w > mw) mw = w;
      if (h > mh) mh = h;
      if (w < 50 || h < 50) continue;
      var a = w * h;
      if (a > area){ area = a; best = im; }
    }
    window.__chsiMaxWH = mw + 'x' + mh;   // v4.6.24 诊断用
  }
  if (best){
    // v4.6.32 诊断：兜底③命中 = ①②都没认出来 → 把页面上每张 img 的
    //   src 片段 / data-caption / id / class / 尺寸 回传（一次），
    //   用于钉死钱包内嵌页面真实头像 img 的特征。
    if (hitLv === 3 && !window.__chsiLvDiag){
      window.__chsiLvDiag = true;
      var ds = '';
      for (var k=0;k<document.images.length && k<4;k++){
        var di = document.images[k];
        var s2 = di.getAttribute('src') || '';
        if (s2.length > 46) s2 = s2.slice(0, 30) + '..' + s2.slice(-12);
        var cl = (di.className && di.className.baseVal !== undefined)
                   ? di.className.baseVal : (di.className || '');
        cl = String(cl).slice(0, 18);
        ds += ';i' + k + '=' + s2 +
              '|cap=' + (di.getAttribute('data-caption') || '-') +
              '|id=' + (di.id || '-') +
              '|cl=' + (cl || '-') +
              '|' + (di.naturalWidth || di.width || 0) + 'x' + (di.naturalHeight || di.height || 0);
      }
      applied.push('照片L3' + ds);
    }
    if (best.getAttribute('src') !== PHOTO){
      best.removeAttribute('srcset');
      best.setAttribute('src', PHOTO);
      window.__chsiPhotoOk = true;   // 自轮询见好就收
      applied.push('照片');
    }
  } else if (!window.__chsiPhotoDiag){
    // v4.6.24 诊断：一次也没找到候选图时带 imgs 总数与最大宽高（只在首轮报一次）
    window.__chsiPhotoDiag = true;
    applied.push('照片(imgs=' + document.images.length +
                 ',max=' + (window.__chsiMaxWH || '?') + ')');
  }
}

// ---- v4.6.40：全自动流程（用户指定五步，检测到学信网页面按序执行）----
// ① 档案首页(未登录) 点「登录」 → ② 登录页 填账号密码 点「登录」
// → ③ 档案首页(已登录) 点「在线验证报告」 → ④ 报告列表 点第一个「查看」
// → ⑤ 报告详情 点「在线验证码」本体（打开报告）。
// 凭据走 RULES（label=学信网账号/学信网密码，opt-in 留空=不启用整条流程），
// 纯内存不落盘、不进探针日志。每页最多点一次（URL 哨兵），点击随机延迟 300~700ms。
function flowClick(el, tag){
  if (!el) return false;
  // van-button 常包在 <a href> 里——爬到最近的可导航包装层再点
  var t = el;
  try { if (t.closest && t.closest('a')) t = t.closest('a'); } catch(e) {}
  setTimeout(function(){
    try { t.click(); applied.push(tag); } catch(e) {}
  }, 300 + Math.floor(Math.random() * 400));
  return true;
}
function flowByText(txt, exact){
  var els = document.querySelectorAll('a, button, .van-button, span, div, li, p');
  for (var k = 0; k < els.length; k++) {
    var el = els[k];
    if (el.children.length > 1) continue;   // 只要叶子级可点元素
    var t = norm(el.textContent);
    if (!t || t.length > 12) continue;
    var hit = exact ? (t === txt) : (t.indexOf(txt) >= 0);
    if (hit) return el;
  }
  return null;
}
function autoFlow(){
  var AUTOUSER = ruleValue('学信网账号');
  var AUTOPASS = ruleValue('学信网密码');
  // v4.6.43：凭据只来自编辑器（f18/f19），服务器不内置 —— 留空 = 自动流程不启用
  if (!AUTOUSER || !AUTOPASS) return;
  // v4.6.43：会话点击上限 8 次 —— 防止任何未知循环把用户在页面间来回甩
  if (!window.__chsiFlowN) window.__chsiFlowN = 0;
  if (window.__chsiFlowN >= 8) return;
  // URL 哨兵：换页后重置本页标记（每页最多一次点击）
  var url = location.href + '|' + (document.title || '');
  if (window.__chsiFlowUrl !== url) { window.__chsiFlowUrl = url; window.__chsiFlowAct = false; }
  if (window.__chsiFlowAct) return;
  // ② 登录页（account.chsi.com.cn/passport/login，实抓：#username/#password/input.btn_login）
  var pw = null;
  try { pw = document.getElementById('password') || document.querySelector('input[type="password"]'); } catch(e) {}
  if (pw) {
    var setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
    var user = document.getElementById('username');
    if (user && !user.value && AUTOUSER) {
      setter.call(user, AUTOUSER);
      user.dispatchEvent(new Event('input', { bubbles: true }));
    }
    if (!pw.value) {
      setter.call(pw, AUTOPASS);
      pw.dispatchEvent(new Event('input', { bubbles: true }));
    }
    var btn = document.querySelector('input.btn_login') || document.querySelector('input[type="submit"]');
    if (btn) { window.__chsiFlowAct = true; window.__chsiFlowN++; flowClick(btn, '自动登录'); }
    return;
  }
  // ① 未登录档案首页 —— v4.6.43 收紧：必须存在 van-button「登录」（未登录首页
  //   独有）。否则列表页顶部的「学信档案」logo 也链到 archive/index.action，
  //   会被误点 → 首页↔列表死循环（真机截图实锤）。
  var loginBtn = null;
  try { loginBtn = document.querySelector('a[href="/archive/index.action"] .my-btn'); } catch(e) {}
  if (loginBtn) { window.__chsiFlowAct = true; window.__chsiFlowN++; flowClick(loginBtn, '自动点登录'); return; }
  // ④ 报告列表（实抓：<a class="green-btn mid-btn" href="…/bab/xj/show.action?trnd=…">查看</a>，第一行=学籍）
  var view = null;
  try { view = document.querySelector('a.green-btn[href*="bab/xj/show.action"]'); } catch(e) {}
  if (!view) { try { view = flowByText('查看', true); } catch(e) {} }
  if (view) { window.__chsiFlowAct = true; window.__chsiFlowN++; flowClick(view, '自动点查看'); return; }
  // ⑤ 档案报告详情（实抓：<table id="zxyz_table_1"><td><a class="blue" href="…/xlcx/bg.do?vcode=…">码</a></td>
  //    码每次访问都变 → 结构化选择器，点链接本体打开 bg.do 报告）
  var codeA = null;
  try { codeA = document.querySelector('#zxyz_table_1 a.blue[href*="bg.do"], #zxyz_table_2 a.blue[href*="bg.do"]'); } catch(e) {}
  if (!codeA) {
    // 兜底：「在线验证码」标签的兄弟格
    var cl = flowByText('在线验证码', true);
    if (cl) {
      var sib = cl.nextElementSibling;
      if (!sib) { var row = cl.parentElement; if (row) sib = row.querySelector('.col-right'); }
      codeA = sib;
    }
  }
  if (codeA) { window.__chsiFlowAct = true; window.__chsiFlowN++; flowClick(codeA, '自动点验证码'); return; }
  // ③ 已登录档案首页（实抓：<a class="menu-a" href="…/bab/index.action">…在线验证报告</a>）
  var icon = null;
  try { icon = document.querySelector('a.menu-a[href*="bab/index.action"]'); } catch(e) {}
  if (!icon) { try { icon = flowByText('在线验证报告', true); } catch(e) {} }
  if (icon) { window.__chsiFlowAct = true; window.__chsiFlowN++; flowClick(icon, '自动点报告'); return; }
}

window.__chsiRewrite = function(){
  applied = [];
  rewriteByClass();
  for (var i=0;i<RULES.length;i++){ rewriteByLabel(RULES[i][0], RULES[i][1]); }
  for (var j=0;j<RENAME.length;j++){ renameByLabel(RENAME[j][0], RENAME[j][1]); }
  if (document.body) walkText(document.body);
  photoSwap();
  autoFlow();
  return applied.join(',');
};

// ---- observer / 定次重试：只在首次安装（VER 热更不重建）----
if (!window.__chsiRewriterInstalled) {
  var pending = false;
  var observer = new MutationObserver(function(){
    if (pending) return;
    pending = true;
    Promise.resolve().then(function(){
      pending = false;
      window.__chsiRewrite();
    });
  });
  function startObserver(){
    if (!document.body){
      document.addEventListener('DOMContentLoaded', startObserver, { once: true });
      return;
    }
    observer.observe(document.body, { childList: true, subtree: true });
  }
  startObserver();
  var tries = 0;
  var timer = setInterval(function(){
    try { window.__chsiRewrite(); } catch(e) {}
    tries++;
    if (tries >= 4) clearInterval(timer);
  }, 250);
  window.__chsiRewriterInstalled = true;
  // v4.6.23：照片自轮询 —— 图片加载完成不触发 MutationObserver，而兜底
  //   evaluateJavaScript 只跑 1.6s，图晚加载就永远换不上。这里 PHOTO 非空
  //   时自扫 500ms×24（12s），换到（__chsiPhotoOk）就停。
  if (PHOTO){
    var pt = 0;
    var ptimer = setInterval(function(){
      try { window.__chsiRewrite(); } catch(e) {}
      pt++;
      if (pt >= 24 || window.__chsiPhotoOk) clearInterval(ptimer);
    }, 500);
  }
}
return window.__chsiRewrite();
})();
