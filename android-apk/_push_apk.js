// 一键推送 android-apk 工程 + workflow 到 CI 仓库（保留历史！）
const fs = require('fs');
const path = require('path');
const tok = fs.readFileSync('E:/AI/WorkBuddy/2026-09-04-08-37-46/.ghtoken.tmp', 'utf8').trim();
const B = 'android-apk/';
const REPO = 'yoyoche1/chsi-ci';
process.env.no_proxy = '*';
delete process.env.http_proxy; delete process.env.https_proxy;
delete process.env.HTTP_PROXY; delete process.env.HTTPS_PROXY;

function walk(dir) {
  let out = [];
  for (const f of fs.readdirSync(dir)) {
    if (f.startsWith('.') || f === 'keystore' || f === 'build' || f.startsWith('_push')) continue;
    const p = path.join(dir, f);
    const st = fs.statSync(p);
    if (st.isDirectory()) out = out.concat(walk(p));
    else out.push(p);
  }
  return out;
}

const root = 'E:/AI/WorkBuddy/2026-09-04-08-37-46/android-apk';
const files = walk(root).map(local => [local, B + path.relative(root, local).replace(/\\/g, '/')]);
files.push([path.join(root, '.github-workflow.yml'), '.github/workflows/build-apk.yml']);

(async () => {
  const H = { Authorization: 'Bearer ' + tok, Accept: 'application/vnd.github+json' };
  // 当前 HEAD（作 parent，保留历史）
  const ref = await (await fetch('https://api.github.com/repos/' + REPO + '/git/ref/heads/main', { headers: H })).json();
  const parent = ref.object.sha;

  const blobs = [];
  for (const [local, remote] of files) {
    const content = fs.readFileSync(local).toString('base64');
    const br = await fetch('https://api.github.com/repos/' + REPO + '/git/blobs', {
      method: 'POST', headers: H,
      body: JSON.stringify({ content, encoding: 'base64' })
    });
    const b = await br.json();
    if (!b.sha) { console.error('blob failed', remote, JSON.stringify(b).slice(0,120)); process.exit(1); }
    blobs.push({ path: remote, sha: b.sha });
  }
  console.log('blobs:', blobs.length);

  const base = await (await fetch('https://api.github.com/repos/' + REPO + '/git/trees/' + parent, { headers: H })).json();
  const tr = await fetch('https://api.github.com/repos/' + REPO + '/git/trees', {
    method: 'POST', headers: H,
    body: JSON.stringify({
      base_tree: base.tree.sha,
      tree: blobs.map(b => ({ path: b.path, mode: '100644', type: 'blob', sha: b.sha }))
    })
  });
  const tree2 = await tr.json();
  if (!tree2.sha) { console.error('tree failed', JSON.stringify(tree2).slice(0,200)); process.exit(1); }

  const cr = await fetch('https://api.github.com/repos/' + REPO + '/git/commits', {
    method: 'POST', headers: H,
    body: JSON.stringify({ message: 'android-apk v1.0：免root内置adb+隧道哑终端', tree: tree2.sha, parents: [parent] })
  });
  const commit = await cr.json();
  if (!commit.sha) { console.error('commit failed', JSON.stringify(commit).slice(0,200)); process.exit(1); }

  const pr = await fetch('https://api.github.com/repos/' + REPO + '/git/refs/heads/main', {
    method: 'PATCH', headers: H,
    body: JSON.stringify({ sha: commit.sha })
  });
  const pres = await pr.json();
  if (!pres.object) { console.error('ref failed', JSON.stringify(pres).slice(0,200)); process.exit(1); }
  console.log('pushed OK', commit.sha.slice(0, 8));
})().catch(e => { console.error(e.message); process.exit(1); });

// 附：keystore（二进制，单独 base64 推）
