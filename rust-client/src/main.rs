// 高校认证 v6.3 —— Rust native 客户端
// 哑终端：采设备码 / UI / 把服务端给的脚本原样注入（L3）
#![windows_subsystem = "windows"]

use eframe::egui;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const SERVER: &str = "192.168.1.101:8787";
const VER_TAG: &str = "cs-6.3";
const CHARSET: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

// ============ adb（内置，首次解压到 LOCALAPPDATA）============
static ADB_EXE: &[u8] = include_bytes!("../assets/adb.exe");
static ADB_DLL1: &[u8] = include_bytes!("../assets/AdbWinApi.dll");
static ADB_DLL2: &[u8] = include_bytes!("../assets/AdbWinUsbApi.dll");

fn ensure_adb() -> String {
    let base = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| std::env::temp_dir().to_string_lossy().to_string());
    let dir = std::path::Path::new(&base).join("chsi").join("adb");
    let exe = dir.join("adb.exe");
    let need = !exe.exists()
        || std::fs::metadata(&exe).map(|m| m.len()).unwrap_or(0) != ADB_EXE.len() as u64;
    if need {
        let _ = std::fs::create_dir_all(&dir);
        let _ = std::fs::write(&exe, ADB_EXE);
        let _ = std::fs::write(dir.join("AdbWinApi.dll"), ADB_DLL1);
        let _ = std::fs::write(dir.join("AdbWinUsbApi.dll"), ADB_DLL2);
    }
    exe.to_string_lossy().to_string()
}

#[cfg(windows)]
fn run_hidden(args: &[&str]) -> String {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    Command::new(ensure_adb()).args(args)
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

#[derive(Clone)]
struct Auth { js: String, exp: i64 }

fn check(code: &str, devcode: &str, name: &str, gender: &str, photo: &str) -> Result<Auth, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let exe_bytes = std::fs::read(&exe).map_err(|e| e.to_string())?;
    let exehash = format!("{:x}", Sha256::digest(&exe_bytes));
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis();
    let nonce = format!("{}{}", now, std::process::id());
    let body = format!(
        "{{\"qq\":\"{}\",\"code\":\"{}\",\"bundle\":\"chsi-cs\",\"ver\":\"{}\",\"nonce\":\"{}\",\"exehash\":\"{}\",\"name\":\"{}\",\"gender\":\"{}\",\"photo\":\"{}\"}}",
        json_escape(devcode), json_escape(code), VER_TAG, nonce, exehash,
        json_escape(name), json_escape(gender), json_escape(photo)
    );
    let mut s = TcpStream::connect(SERVER).map_err(|e| format!("网络异常：{}", e))?;
    let _ = s.set_read_timeout(Some(Duration::from_secs(20)));
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
    Ok(Auth { js, exp: jnum(&body, "exp").unwrap_or(0) })
}

fn socket_names(dev: &str) -> Vec<String> {
    let out = run_hidden(&["-s", dev, "shell", "cat", "/proc/net/unix"]);
    let mut names: Vec<String> = out.lines()
        .filter(|l| l.contains("devtools_remote"))
        .filter_map(|l| l.split_whitespace().last())
        .map(|s| s.trim_start_matches('@').to_string())
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

fn ws_eval(ws_url: &str, expr: &str) -> bool {
    let rest = match ws_url.strip_prefix("ws://") { Some(r) => r, None => return false };
    let (host_port, path) = match rest.find('/') { Some(i) => (&rest[..i], &rest[i..]), None => return false };
    let mut hp = host_port.split(':');
    let host = hp.next().unwrap_or("127.0.0.1");
    let port: u16 = hp.next().unwrap_or("0").parse().unwrap_or(0);
    if port == 0 { return false; }
    let mut s = match TcpStream::connect((host, port)) { Ok(x) => x, Err(_) => return false };
    let _ = s.set_read_timeout(Some(Duration::from_secs(10)));

    let key = b64(&[0xA5u8; 16]);
    let hs = format!(
        "GET {} HTTP/1.1\r\nHost: {}:{}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {}\r\nSec-WebSocket-Version: 13\r\n\r\n",
        path, host, port, key
    );
    if s.write_all(hs.as_bytes()).is_err() { return false; }
    let mut buf = vec![0u8; 2048];
    let n = match s.read(&mut buf) { Ok(n) => n, Err(_) => return false };
    if !String::from_utf8_lossy(&buf[..n]).contains("101") { return false; }

    let msg = format!(
        "{{\"id\":1,\"method\":\"Runtime.evaluate\",\"params\":{{\"expression\":{},\"returnByValue\":true}}}}",
        quote_js(expr)
    );
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
    let mut body = vec![0u8; len.min(8 * 1024 * 1024)];
    if s.read_exact(&mut body).is_err() { return false; }
    let t = String::from_utf8_lossy(&body).to_string();
    !t.contains("\"error\"") && !t.contains("exceptionDetails")
}

fn quote_js(s: &str) -> String {
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

fn scan_pages(dev: &str) -> Vec<(String, String)> {
    let mut found = Vec::new();
    let mut port = 32000u16;
    for name in socket_names(dev) {
        let fwd = format!("tcp:{}", port);
        let abs = format!("localabstract:{}", name);
        let _ = run_hidden(&["-s", dev, "forward", &fwd, &abs]);
        if let Some(json) = http_get_json(port) {
            if json.contains("chsi") {
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

// ============ 共享状态 ============
#[derive(Default)]
struct Shared {
    status: String,
    logs: Vec<String>,
}

struct App {
    devcode: String,
    code: String,
    name: String,
    gender: String,
    photo: String,
    photo_name: String,
    verified: bool,
    running: bool,
    shared: Arc<Mutex<Shared>>,
    last_scan: Instant,
    device: Option<String>,
}

impl Default for App {
    fn default() -> Self {
        Self {
            devcode: String::new(), code: String::new(), name: String::new(),
            gender: "女".into(), photo: String::new(), photo_name: String::new(),
            verified: false, running: false,
            shared: Arc::new(Mutex::new(Shared { status: "● 未授权".into(), logs: Vec::new() })),
            last_scan: Instant::now(), device: None,
        }
    }
}

fn log_line(sh: &Arc<Mutex<Shared>>, msg: &str) {
    if let Ok(mut s) = sh.lock() {
        s.logs.push(msg.to_string());
        if s.logs.len() > 30 { s.logs.remove(0); }
    }
}
fn set_status(sh: &Arc<Mutex<Shared>>, msg: &str) {
    if let Ok(mut s) = sh.lock() { s.status = msg.to_string(); }
}

// 注入循环：素材过期自动重新申请；每 1.5 秒扫页面并注入
fn inject_loop(sh: Arc<Mutex<Shared>>, code: String, devcode: String, name: String, gender: String, photo: String) {
    let mut auth: Option<Auth> = None;
    let mut last_dev: Option<String> = None;
    loop {
        let need = match &auth {
            None => true,
            Some(a) => a.exp - now_ms() < 60_000,
        };
        if need {
            match check(&code, &devcode, &name, &gender, &photo) {
                Ok(a) => {
                    auth = Some(a);
                    log_line(&sh, "素材已获取（5分钟内有效）");
                    set_status(&sh, "● 已授权 · 注入运行中");
                }
                Err(e) => {
                    log_line(&sh, &format!("素材申请失败：{}", e));
                    set_status(&sh, "● 素材申请失败，重试中…");
                    std::thread::sleep(Duration::from_secs(3));
                    continue;
                }
            }
        }

        let dev = pick_device();
        if dev.is_none() {
            if last_dev.is_some() { log_line(&sh, "设备断开，等待重连…"); }
            last_dev = None;
            std::thread::sleep(Duration::from_secs(2));
            continue;
        }
        let d = dev.unwrap();
        if last_dev.as_deref() != Some(d.as_str()) {
            log_line(&sh, &format!("设备已连接：{}", d));
            last_dev = Some(d.clone());
        }

        let pages = scan_pages(&d);
        if pages.is_empty() {
            log_line(&sh, "等待学信网页面打开…");
        } else {
            let js = match &auth { Some(a) => a.js.clone(), None => String::new() };
            let mut okn = 0;
            for (_n, ws) in pages {
                if ws_eval(&ws, &js) { okn += 1; }
            }
            if okn > 0 { log_line(&sh, &format!("注入成功 {} 个页面", okn)); }
        }
        std::thread::sleep(Duration::from_millis(1500));
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64
}

fn install_cjk_font(ctx: &egui::Context) {
    for p in ["C:/Windows/Fonts/simhei.ttf", "C:/Windows/Fonts/Deng.ttf", "C:/Windows/Fonts/msyh.ttc"] {
        if let Ok(bytes) = std::fs::read(p) {
            let mut fonts = egui::FontDefinitions::default();
            fonts.font_data.insert("cjk".into(), egui::FontData::from_owned(bytes));
            if let Some(fam) = fonts.families.get_mut(&egui::FontFamily::Proportional) { fam.insert(0, "cjk".into()); }
            if let Some(fam) = fonts.families.get_mut(&egui::FontFamily::Monospace) { fam.push("cjk".into()); }
            ctx.set_fonts(fonts);
            return;
        }
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _f: &mut eframe::Frame) {
        if self.last_scan.elapsed() > Duration::from_secs(1) {
            self.last_scan = Instant::now();
            if let Some(d) = pick_device() {
                if self.device.as_deref() != Some(d.as_str()) || self.devcode.is_empty() {
                    self.devcode = device_code(&d);
                    self.device = Some(d);
                }
            }
        }
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(6.0);
            ui.heading("高校认证");
            ui.label(egui::RichText::new("QQ 学信网认证辅助 · 本机运行").size(11.0).weak());
            ui.add_space(8.0);
            ui.label("设备码（发给管理员换授权码）");
            ui.horizontal(|ui| {
                ui.add(egui::TextEdit::singleline(&mut self.devcode).desired_width(300.0));
                if ui.button("复制").clicked() { ctx.copy_text(self.devcode.clone()); }
            });
            ui.add_space(6.0);
            ui.separator();
            ui.add_space(4.0);
            ui.label("授权码");
            ui.add(egui::TextEdit::singleline(&mut self.code).desired_width(360.0));

            if !self.verified {
                ui.add_space(12.0);
                if ui.add_sized([360.0, 40.0], egui::Button::new(egui::RichText::new("验 证").size(15.0))).clicked() {
                    match check(&self.code, &self.devcode, "", "", "") {
                        Ok(_) => {
                            self.verified = true;
                            if let Ok(mut s) = self.shared.lock() { s.status = "● 已授权".into(); }
                        }
                        Err(e) => { if let Ok(mut s) = self.shared.lock() { s.status = format!("● 验证失败：{}", e); } }
                    }
                }
            } else {
                ui.add_space(4.0);
                ui.label("姓名");
                ui.add(egui::TextEdit::singleline(&mut self.name).desired_width(360.0));
                ui.add_space(4.0);
                ui.label("性别");
                ui.horizontal(|ui| {
                    ui.radio_value(&mut self.gender, "男".to_string(), "男");
                    ui.radio_value(&mut self.gender, "女".to_string(), "女");
                });
                ui.add_space(4.0);
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
                ui.add_space(8.0);
                let ok = !self.name.trim().is_empty() && !self.photo.is_empty() && !self.running;
                let label = if self.running { "注入中…" } else { "保存并应用" };
                if ui.add_enabled(ok, egui::Button::new(egui::RichText::new(label).size(15.0)).min_size(egui::vec2(360.0, 40.0))).clicked() {
                    self.running = true;
                    let sh = self.shared.clone();
                    let (c, d, n, g, p) = (self.code.clone(), self.devcode.clone(), self.name.clone(), self.gender.clone(), self.photo.clone());
                    std::thread::spawn(move || inject_loop(sh, c, d, n, g, p));
                }
            }
            ui.add_space(8.0);
            let (st, logs) = {
                let s = self.shared.lock().unwrap();
                (s.status.clone(), s.logs.clone())
            };
            ui.label(egui::RichText::new(st).strong());
            for l in logs.iter().rev().take(5) {
                ui.label(egui::RichText::new(l).size(9.5).weak());
            }
        });
        ctx.request_repaint_after(Duration::from_millis(500));
    }
}

fn rfd_pick() -> Option<std::path::PathBuf> {
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
    if std::env::args().any(|a| a == "--selftest") {
        if let Some(d) = pick_device() { let _ = device_code(&d); }
        std::process::exit(0);
    }
    let opts = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([500.0, 660.0])
            .with_min_inner_size([460.0, 560.0]),
        ..Default::default()
    };
    eframe::run_native("高校认证 v6.3", opts, Box::new(|cc| {
        install_cjk_font(&cc.egui_ctx);
        Box::new(App::default())
    }))
}
