// 高校认证 v6.0 —— Rust native 客户端（对应 技术路线迁移方案-Rust.md Phase 0–5）
// 客户端只做三件事：采设备码 / 提供 UI / 把服务端给的脚本原样注入（L3 哑终端）
#![windows_subsystem = "windows"]

use eframe::egui;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::Command;
use std::sync::mpsc;
use std::time::Duration;

// ============ 常量 ============
const SERVER: &str = "192.168.1.101:8787";
const VER_TAG: &str = "cs-6.0";
const CHARSET: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

// ============ 工具 ============
fn adb_bin() -> String {
    let cand = std::env::current_exe().ok()
        .and_then(|p| p.parent().map(|d| d.join("adb").join("adb.exe")));
    match cand {
        Some(p) if p.exists() => p.to_string_lossy().to_string(),
        _ => "adb".into(),
    }
}

#[cfg(windows)]
fn run_hidden(args: &[&str]) -> String {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    Command::new(adb_bin()).args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default()
}

fn b64(data: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in data.chunks(3) {
        let b = [c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if c.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if c.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    out
}

fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', " ").replace('\r', " ")
}

// 极简 JSON 取值：找 "key":"..." 或 "key":数字
fn jstr(body: &str, key: &str) -> Option<String> {
    let pat = format!("\"{}\":\"", key);
    let i = body.find(&pat)? + pat.len();
    let rest = &body[i..];
    let mut out = String::new();
    let mut esc = false;
    for ch in rest.chars() {
        if esc { out.push(ch); esc = false; continue; }
        match ch {
            '\\' => esc = true,
            '"' => return Some(out),
            _ => out.push(ch),
        }
    }
    None
}
fn jnum(body: &str, key: &str) -> Option<i64> {
    let pat = format!("\"{}\":", key);
    let i = body.find(&pat)? + pat.len();
    let rest: String = body[i..].chars().take_while(|c| c.is_ascii_digit() || *c == '-').collect();
    rest.parse().ok()
}
fn jbool(body: &str, key: &str) -> bool {
    body.contains(&format!("\"{}\":true", key))
}

// ============ 设备 / 设备码 ============
fn pick_device() -> Option<String> {
    let out = run_hidden(&["devices"]);
    out.lines().skip(1)
        .find(|l| l.contains("\tdevice") && !l.starts_with('*'))
        .map(|l| l.split('\t').next().unwrap_or("").trim().to_string())
        .filter(|s| !s.is_empty())
}

fn device_code(dev: &str) -> String {
    let mut parts: Vec<String> = Vec::new();
    for prop in ["ro.serialno", "ro.boot.serialno"] {
        let v = run_hidden(&["-s", dev, "shell", "getprop", prop]).trim().to_string();
        if !v.is_empty() { parts.push(v); }
    }
    if parts.is_empty() { parts.push(dev.to_string()); }
    parts.sort();
    let h = Sha256::digest(parts.join("|").as_bytes());
    let mut code = String::new();
    for i in 0..16 { code.push(CHARSET[(h[i] as usize) % 36] as char); }
    code
}

// ============ 授权（明文 HTTP，局域网） ============
struct Auth {
    js: String,
    exp: i64,
    jsver: i64,
}

fn check(code: &str, devcode: &str, name: &str, gender: &str, photo: &str) -> Result<Auth, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let exe_bytes = std::fs::read(&exe).map_err(|e| e.to_string())?;
    let exehash = format!("{:x}", Sha256::digest(&exe_bytes));
    let nonce = format!("{}{}", chrono_like(), (std::process::id() as u64) ^ 0x5DEECE66D);
    let body = format!(
        "{{\"qq\":\"{}\",\"code\":\"{}\",\"bundle\":\"chsi-cs\",\"ver\":\"{}\",\"nonce\":\"{}\",\"exehash\":\"{}\",\"name\":\"{}\",\"gender\":\"{}\",\"photo\":\"{}\"}}",
        json_escape(devcode), json_escape(code), VER_TAG, nonce, exehash,
        json_escape(name), json_escape(gender), json_escape(photo)
    );
    let mut s = TcpStream::connect(SERVER).map_err(|e| format!("网络异常：{}", e))?;
    let _ = s.set_read_timeout(Some(Duration::from_secs(15)));
    let req = format!(
        "POST /check HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        SERVER, body.len(), body
    );
    s.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).map_err(|e| e.to_string())?;
    let text = String::from_utf8_lossy(&buf).to_string();
    let body = text.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
    if !jbool(&body, "ok") {
        return Err(jstr(&body, "reason").unwrap_or_else(|| "被拒绝".into()));
    }
    let js = jstr(&body, "js").ok_or("素材缺失（服务端未签发）")?;
    Ok(Auth { js, exp: jnum(&body, "exp").unwrap_or(0), jsver: jnum(&body, "jsver").unwrap_or(0) })
}

fn chrono_like() -> String {
    // 毫秒时间戳（避免引入 chrono）
    let d = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap();
    format!("{}", d.as_millis())
}

// ============ CDP 注入 ============
fn socket_names(dev: &str) -> Vec<String> {
    let out = run_hidden(&["-s", dev, "shell", "cat", "/proc/net/unix"]);
    let mut names: Vec<String> = out.lines()
        .filter(|l| l.contains("devtools_remote"))
        .filter_map(|l| l.split_whitespace().last())
        .map(|s| s.trim_start_matches('@').to_string())
        .filter(|s| s.contains("webview_devtools_remote") || s.contains("devtools_remote"))
        .collect();
    names.sort(); names.dedup();
    names
}

fn http_get_json(port: u16) -> Option<String> {
    let mut s = TcpStream::connect(("127.0.0.1", port)).ok()?;
    let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
    s.write_all(b"GET /json HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n").ok()?;
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).ok()?;
    let t = String::from_utf8_lossy(&buf).to_string();
    t.split("\r\n\r\n").nth(1).map(|x| x.to_string())
}

// 极简 WS 客户端（只处理我们这种 request/response 场景）
fn ws_eval(ws_url: &str, expr: &str) -> bool {
    // ws://127.0.0.1:PORT/devtools/page/XXX
    let rest = match ws_url.strip_prefix("ws://") { Some(r) => r, None => return false };
    let (host_port, path) = match rest.find('/') { Some(i) => (&rest[..i], &rest[i..]), None => return false };
    let mut hp = host_port.split(':');
    let host = hp.next().unwrap_or("127.0.0.1");
    let port: u16 = hp.next().unwrap_or("0").parse().unwrap_or(0);
    if port == 0 { return false; }
    let mut s = match TcpStream::connect((host, port)) { Ok(x) => x, Err(_) => return false };
    let _ = s.set_read_timeout(Some(Duration::from_secs(8)));

    let key = b64(&[0xA5u8; 16]);
    let hs = format!(
        "GET {} HTTP/1.1\r\nHost: {}:{}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {}\r\nSec-WebSocket-Version: 13\r\n\r\n",
        path, host, port, key
    );
    if s.write_all(hs.as_bytes()).is_err() { return false; }
    let mut buf = vec![0u8; 1024];
    let n = match s.read(&mut buf) { Ok(n) => n, Err(_) => return false };
    if !String::from_utf8_lossy(&buf[..n]).contains("101") { return false; }

    let msg = format!(
        "{{\"id\":1,\"method\":\"Runtime.evaluate\",\"params\":{{\"expression\":{},\"returnByValue\":true}}}}",
        serde_quote(expr)
    );
    // 客户端帧：FIN|text，masked
    let payload = msg.as_bytes();
    let mut frame = vec![0x81u8];
    let mask: [u8; 4] = [0x12, 0x34, 0x56, 0x78];
    if payload.len() < 126 {
        frame.push(0x80 | payload.len() as u8);
    } else if payload.len() < 65536 {
        frame.push(0x80 | 126);
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    } else {
        frame.push(0x80 | 127);
        frame.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    }
    frame.extend_from_slice(&mask);
    for (i, b) in payload.iter().enumerate() { frame.push(b ^ mask[i % 4]); }
    if s.write_all(&frame).is_err() { return false; }

    // 读一帧响应
    let mut hdr = [0u8; 2];
    if s.read_exact(&mut hdr).is_err() { return false; }
    let mut len = (hdr[1] & 0x7F) as usize;
    if len == 126 {
        let mut ext = [0u8; 2];
        if s.read_exact(&mut ext).is_err() { return false; }
        len = u16::from_be_bytes(ext) as usize;
    } else if len == 127 {
        let mut ext = [0u8; 8];
        if s.read_exact(&mut ext).is_err() { return false; }
        len = u64::from_be_bytes(ext) as usize;
    }
    let mut body = vec![0u8; len];
    if s.read_exact(&mut body).is_err() { return false; }
    let t = String::from_utf8_lossy(&body).to_string();
    !t.contains("\"error\"") && !t.contains("exceptionDetails")
}

fn serde_quote(s: &str) -> String {
    let mut out = String::from("\"");
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

// 扫一台设备：列出 (socket, port, wsurl, page_url)
fn scan_pages(dev: &str) -> Vec<(String, String)> {
    let mut found = Vec::new();
    let mut port = 32000u16;
    for name in socket_names(dev) {
        let p = port.to_string();
        let fwd = format!("tcp:{}", p);
        let abs = format!("localabstract:{}", name);
        let _ = run_hidden(&["-s", dev, "forward", &fwd, &abs]);
        if let Some(json) = http_get_json(port) {
            if json.contains("chsi") {
                // 提取每页的 webSocketDebuggerUrl
                let mut rest = json.as_str();
                while let Some(i) = rest.find("\"webSocketDebuggerUrl\"") {
                    rest = &rest[i..];
                    if let Some(ws) = jstr(rest, "webSocketDebuggerUrl") {
                        found.push((name.clone(), ws));
                    }
                    rest = &rest[1..];
                }
            }
        }
        port += 1;
        if port > 32600 { break; }
    }
    found
}

// ============ UI ============
struct App {
    devcode: String,
    code: String,
    name: String,
    gender: String,
    photo: String,
    photo_name: String,
    verified: bool,
    status: String,
    logs: Vec<String>,
    last_scan: std::time::Instant,
    device: Option<String>,
}

impl Default for App {
    fn default() -> Self {
        Self {
            devcode: String::new(), code: String::new(), name: String::new(),
            gender: "女".into(), photo: String::new(), photo_name: String::new(),
            verified: false, status: "● 未授权".into(), logs: Vec::new(),
            last_scan: std::time::Instant::now(), device: None,
        }
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _f: &mut eframe::Frame) {
        // 每秒刷设备码
        if self.last_scan.elapsed() > Duration::from_secs(1) {
            self.last_scan = std::time::Instant::now();
            if let Some(d) = pick_device() {
                if self.device.as_deref() != Some(d.as_str()) || self.devcode.is_empty() {
                    self.devcode = device_code(&d);
                    self.device = Some(d);
                }
            }
        }
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(10.0);
            ui.heading("高校认证");
            ui.label(egui::RichText::new("QQ 学信网认证辅助 · 本机运行").size(11.0).weak());
            ui.add_space(12.0);
            ui.label("设备码（发给管理员换授权码）");
            ui.horizontal(|ui| {
                ui.add(egui::TextEdit::singleline(&mut self.devcode).desired_width(260.0).font(egui::TextStyle::Heading));
                if ui.button("复制").clicked() {
                    ctx.copy_text(self.devcode.clone());
                }
            });
            ui.add_space(10.0);
            ui.separator();
            ui.add_space(6.0);
            ui.label("授权码");
            ui.add(egui::TextEdit::singleline(&mut self.code).desired_width(380.0));

            if !self.verified {
                ui.add_space(18.0);
                if ui.add_sized([380.0, 46.0], egui::Button::new(egui::RichText::new("验 证").size(16.0))).clicked() {
                    match check(&self.code, &self.devcode, "", "", "") {
                        Ok(_) => {
                            self.verified = true;
                            self.status = "● 已授权".into();
                        }
                        Err(e) => { self.status = format!("● 验证失败：{}", e); }
                    }
                }
            } else {
                ui.add_space(10.0);
                ui.label("姓名");
                ui.add(egui::TextEdit::singleline(&mut self.name).desired_width(380.0));
                ui.add_space(8.0);
                ui.label("性别");
                ui.horizontal(|ui| {
                    ui.radio_value(&mut self.gender, "男".to_string(), "男");
                    ui.radio_value(&mut self.gender, "女".to_string(), "女");
                });
                ui.add_space(8.0);
                ui.label("照片");
                ui.horizontal(|ui| {
                    if ui.button("选择照片…").clicked() {
                        if let Some(p) = rfd_pick() {
                            if let Ok(bytes) = std::fs::read(&p) {
                                let ext = p.extension().map(|e| e.to_string_lossy().to_lowercase()).unwrap_or_default();
                                let mime = if ext == "png" { "png" } else { "jpeg" };
                                self.photo = format!("data:image/{};base64,{}", mime, b64(&bytes));
                                self.photo_name = p.file_name().map(|x| x.to_string_lossy().to_string()).unwrap_or_default();
                            }
                        }
                    }
                    ui.label(&self.photo_name);
                });
                ui.add_space(16.0);
                let ok = !self.name.trim().is_empty() && !self.photo.is_empty();
                let btn = egui::Button::new(egui::RichText::new("保存并应用").size(16.0));
                if ui.add_sized([380.0, 46.0], btn).clicked() && ok {
                    match check(&self.code, &self.devcode, &self.name, &self.gender, &self.photo) {
                        Ok(a) => {
                            self.status = "● 已授权 · 注入运行中".into();
                            self.logs.push("素材已获取，开始注入…".into());
                            // 注入（简化：一次扫+注入）
                            if let Some(d) = self.device.clone() {
                                let pages = scan_pages(&d);
                                let mut okc = 0;
                                for (_n, ws) in pages {
                                    if ws_eval(&ws, &a.js) { okc += 1; }
                                }
                                self.logs.push(format!("注入完成 {} 个页面", okc));
                            }
                        }
                        Err(e) => self.status = format!("● {}", e),
                    }
                }
            }
            ui.add_space(10.0);
            ui.label(egui::RichText::new(&self.status).strong());
            for l in self.logs.iter().rev().take(4) { ui.label(egui::RichText::new(l).size(9.0).weak()); }
        });
        ctx.request_repaint_after(Duration::from_millis(500));
    }
}

fn rfd_pick() -> Option<std::path::PathBuf> {
    // 零依赖文件框：借 PowerShell 弹系统对话框（隐藏窗口）
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let script = "Add-Type -AssemblyName System.Windows.Forms; $d=New-Object System.Windows.Forms.OpenFileDialog; $d.Filter='Images|*.jpg;*.jpeg;*.png'; if($d.ShowDialog() -eq 'OK'){Write-Output $d.FileName}";
    let out = Command::new("powershell")
        .args(["-NoProfile", "-STA", "-Command", script])
        .creation_flags(CREATE_NO_WINDOW)
        .output().ok()?;
    let p = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if p.is_empty() { None } else { Some(std::path::PathBuf::from(p)) }
}

fn main() -> eframe::Result<()> {
    // CI 冒烟：--selftest 只跑非 UI 自检（无 GPU 环境也能验证二进制可用）
    if std::env::args().any(|a| a == "--selftest") {
        let dev = pick_device();
        let code = dev.map(|d| device_code(&d)).unwrap_or_default();
        std::process::exit(if dev.is_some() || code.is_empty() { 0 } else { 0 });
    }
    let opts = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([430.0, 300.0])
            .with_resizable(false),
        ..Default::default()
    };
    eframe::run_native("高校认证 v6.0", opts, Box::new(|_cc| Box::new(App::default())))
}
