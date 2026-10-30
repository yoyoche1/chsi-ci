'use strict';
// 构建期加密：client.js → app-enc.json（AES-256-GCM，密钥 2 分片：k1 入载荷、k2 注入 core.js 后编译成字节码）
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const key = crypto.randomBytes(32);
const iv = crypto.randomBytes(12);
const k1 = crypto.randomBytes(32);
const k2 = Buffer.alloc(32);
for (let i = 0; i < 32; i++) k2[i] = key[i] ^ k1[i];
const srcRaw = fs.readFileSync(path.join(__dirname, 'client.js'), 'utf8');
const src = srcRaw.split('\n').filter(l => !l.startsWith('#!')).join('\n');
const c = crypto.createCipheriv('aes-256-gcm', key, iv);
const data = Buffer.concat([c.update(src, 'utf8'), c.final()]);
const out = {
  alg: 'aes-256-gcm',
  iv: iv.toString('base64'),
  data: Buffer.concat([data, c.getAuthTag()]).toString('base64'),
  k1: k1.toString('base64'),
};
fs.writeFileSync(path.join(__dirname, 'app-enc.json'), JSON.stringify(out));
let core = fs.readFileSync(path.join(__dirname, 'core.js'), 'utf8').replace('__K2_B64__', k2.toString('base64'));
fs.writeFileSync(path.join(__dirname, 'core_ci.js'), core);
console.log('app-enc.json + core_ci.js built (k2 injected into bytecode source)');
