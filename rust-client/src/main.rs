// 高校认证 v8.0 —— Rust native 客户端（行为与 .NET v5.1 对齐）
// 哑终端：采设备码 / UI / 把服务端给的脚本原样注入（L3）
#![windows_subsystem = "windows"]

use eframe::egui;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const SERVER_HTTP: &str = "[2408:8214:3a12:9d20:d851:ebff:fe55:bd27]:8787";
const SERVER_HOST: &str = "[2408:8214:3a12:9d20:d851:ebff:fe55:bd27]:8787";
const SERVER_WS: &str = "ws://[2408:8214:3a12:9d20:d851:ebff:fe55:bd27]:8787/tunnel";
const VER_TAG: &str = "cs-8.0";
const CHARSET: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

// ============ adb（内置）============
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

fn run_cmd_hidden(prog: &str, args: &[&str]) -> String {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    Command::new(prog).args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default()
}

fn adb(args: &[&str]) -> String {
    run_cmd_hidden(&ensure_adb(), args)
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

// ============ 设备码 + 轮换（与 .NET 一致：HKCU\Software\ChsiAuth used）============
const AZ: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

fn rotate(code: &str) -> String {
    let mut ch: Vec<u8> = code.to_uppercase().into_bytes();
    for i in (0..ch.len()).rev() {
        let idx = AZ.iter().position(|c| *c == ch[i]);
        match idx {
            None => ch[i] = b'0',
            Some(v) if v < 35 => { ch[i] = AZ[v + 1]; return String::from_utf8_lossy(&ch).to_string(); }
            _ => ch[i] = b'0',
        }
    }
    String::from_utf8_lossy(&ch).to_string()
}

fn used_count() -> u32 {
    let out = run_cmd_hidden("reg", &["query", r"HKCU\Software\ChsiAuth", "/v", "used"]);
    for line in out.lines() {
        if line.contains("used") {
            if let Some(v) = line.split_whitespace().last() {
                if let Ok(n) = v.parse::<u32>() { return n; }
            }
        }
    }
    0
}

fn mark_used(n: u32) {
    let _ = run_cmd_hidden("reg", &["add", r"HKCU\Software\ChsiAuth", "/v", "used", "/d", &n.to_string(), "/f"]);
}

fn pick_device() -> Option<String> {
    let out = adb(&["devices"]);
    out.lines().skip(1)
        .find(|l| l.contains("\tdevice") && !l.starts_with('*'))
        .map(|l| l.split('\t').next().unwrap_or("").trim().to_string())
        .filter(|s| !s.is_empty())
}

fn device_code(dev: &str) -> String {
    let mut parts: Vec<String> = Vec::new();
    for prop in ["ro.serialno", "ro.boot.serialno"] {
        let v = adb(&["-s", dev, "shell", "getprop", prop]).trim().to_string();
        if !v.is_empty() { parts.push(v); }
    }
    if parts.is_empty() { parts.push(dev.to_string()); }
    parts.sort();
    let h = Sha256::digest(parts.join("|").as_bytes());
    let mut code = String::new();
    for i in 0..16 { code.push(CHARSET[(h[i] as usize) % 36] as char); }
    for _ in 0..used_count() { code = rotate(&code); }
    code
}

// ============ 授权 ============
#[derive(Clone)]
struct Auth { js: String, exp: i64 }

fn check(code: &str, devcode: &str, name: &str, gender: &str, photo: &str) -> Result<Auth, String> {
    check_inner(code, devcode, name, gender, photo, false)
}

fn check_probe(code: &str, devcode: &str) -> Result<(), String> {
    check_inner(code, devcode, "", "", "", true).map(|_| ())
}

fn check_inner(code: &str, devcode: &str, name: &str, gender: &str, photo: &str, probe: bool) -> Result<Auth, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let exe_bytes = std::fs::read(&exe).map_err(|e| e.to_string())?;
    let exehash = format!("{:x}", Sha256::digest(&exe_bytes));
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis();
    let nonce = format!("{}{}", now, std::process::id());
    let body = format!(
        "{{\"qq\":\"{}\",\"code\":\"{}\",\"bundle\":\"chsi-cs\",\"ver\":\"{}\",\"nonce\":\"{}\",\"exehash\":\"{}\",\"name\":\"{}\",\"gender\":\"{}\",\"photo\":\"{}\"{}}}",
        json_escape(devcode), json_escape(code), VER_TAG, nonce, exehash,
        json_escape(name), json_escape(gender), json_escape(photo),
        if probe { ",\"probe\":1" } else { "" }
    );
    let mut s = TcpStream::connect(SERVER_HTTP).map_err(|e| format!("网络异常：{}", e))?;
    let _ = s.set_read_timeout(Some(Duration::from_secs(20)));
    let req = format!(
        "POST /check HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        SERVER_HOST, body.len(), body
    );
    s.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).map_err(|e| e.to_string())?;
    let text = String::from_utf8_lossy(&buf).to_string();
    let payload = text.split("\r\n\r\n").nth(1).unwrap_or("").trim().to_string();
    // 严格判定：必须是 {"ok":true, ...
    if !payload.starts_with("{\"ok\":true") {
        let reason = jstr(&payload, "reason").unwrap_or_else(|| "被拒绝".into());
        let reason = match reason.as_str() {
            "code_invalid" | "no_license" => "授权码无效",
            "qq_not_match" | "device_mismatch" => "授权码不属于本设备",
            "replay" => "请求重复，请重试",
            "client_modified" | "ver_blocked" => "客户端被修改或版本过旧",
            "service_disabled" => "授权服务已停用",
            "missing_name" => "请输入姓名",
            "bad_gender" => "请选择性别",
            "bad_photo" => "照片格式不支持",
            "photo_too_large" => "照片过大（上限 8MB）",
            "bad_device" | "missing" | "bad_json" => "请求参数无效",
            other => other,
        };
        return Err(reason.to_string());
    }
    let js = jstr(&payload, "js").unwrap_or_default();
    if !probe && js.is_empty() { return Err("素材缺失（服务端未签发）".into()); }
    Ok(Auth { js, exp: jnum(&payload, "exp").unwrap_or(0) })
}

// ============ v8 哑终端：TCP 隧道（注入全部在云端）============
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;

const T_OPEN: u8 = 0x01;
const T_DATA: u8 = 0x02;
const T_CLOSE: u8 = 0x03;

fn frame(t: u8, id: u32, body: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(5 + body.len());
    v.push(t);
    v.extend_from_slice(&id.to_be_bytes());
    v.extend_from_slice(body);
    v
}

async fn tunnel_loop(url: String, target: String, sh: Arc<Mutex<Shared>>) {
    loop {
        match tokio_tungstenite::connect_async(&url).await {
            Ok((ws, _)) => {
                log_line(&sh, "☁ 隧道已连接，云端注入中…");
                set_status(&sh, "● 已授权 · 云端注入中");
                let (mut sink, mut stream) = ws.split();
                let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(256);
                let writer = tokio::spawn(async move {
                    while let Some(v) = rx.recv().await {
                        if sink.send(Message::Binary(v)).await.is_err() { break; }
                    }
                });
                let mut streams: std::collections::HashMap<u32, tokio::sync::mpsc::Sender<Vec<u8>>> =
                    std::collections::HashMap::new();
                while let Some(msg) = stream.next().await {
                    let data = match msg {
                        Ok(Message::Binary(b)) => b,
                        Ok(Message::Close(_)) => break,
                        Err(_) => break,
                        _ => continue,
                    };
                    if data.len() < 5 { continue; }
                    let t = data[0];
                    let id = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
                    let body = data[5..].to_vec();
                    match t {
                        T_OPEN => {
                            let (up_tx, mut up_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
                            streams.insert(id, up_tx);
                            let tx2 = tx.clone();
                            let target = target.clone();
                            tokio::spawn(async move {
                                let mut tcp = match TcpStream::connect(&target).await {
                                    Ok(x) => x,
                                    Err(_) => { let _ = tx2.send(frame(T_CLOSE, id, &[])).await; return; }
                                };
                                let mut buf = vec![0u8; 16384];
                                loop {
                                    tokio::select! {
                                        n = tcp.read(&mut buf) => {
                                            match n {
                                                Ok(0) | Err(_) => break,
                                                Ok(n) => { let _ = tx2.send(frame(T_DATA, id, &buf[..n])).await; }
                                            }
                                        }
                                        Some(d) = up_rx.recv() => {
                                            if tcp.write_all(&d).await.is_err() { break; }
                                        }
                                        else => break,
                                    }
                                }
                                let _ = tx2.send(frame(T_CLOSE, id, &[])).await;
                            });
                        }
                        T_DATA => {
                            if let Some(txs) = streams.get(&id) {
                                let _ = txs.send(body).await;
                            }
                        }
                        T_CLOSE => { streams.remove(&id); }
                        _ => {}
                    }
                }
                writer.abort();
                log_line(&sh, "隧道断开，3 秒后重连…");
            }
            Err(e) => {
                log_line(&sh, &format!("隧道连接失败：{}", e));
                set_status(&sh, "● 隧道连接失败，重试中…");
            }
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}

// ============ 共享状态 ============
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
    exiting: bool,
    exit_at: Option<Instant>,
    shared: Arc<Mutex<Shared>>,
    last_scan: Instant,
    device: Option<String>,
}

impl Default for App {
    fn default() -> Self {
        Self {
            devcode: String::new(), code: String::new(), name: String::new(),
            gender: "女".into(), photo: String::new(), photo_name: String::new(),
            verified: false, running: false, exiting: false, exit_at: None,
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

// v8：保存并应用 → /prepare 拿 token → 起隧道（不做任何注入）
fn start_cloud(code: String, devcode: String, name: String, gender: String, photo: String, sh: Arc<Mutex<Shared>>) {
    let exe = match std::env::current_exe() { Ok(p) => p, Err(_) => return };
    let exehash = match std::fs::read(&exe) { Ok(b) => format!("{:x}", Sha256::digest(&b)), Err(_) => String::new() };
    let nonce = format!("{}{}", now_ms(), std::process::id());
    let body = format!(
        "{{\"device\":\"{}\",\"code\":\"{}\",\"nonce\":\"{}\",\"ver\":\"{}\",\"exehash\":\"{}\",\"name\":\"{}\",\"gender\":\"{}\",\"photo\":\"{}\"}}",
        json_escape(&devcode), json_escape(&code), nonce, VER_TAG, exehash,
        json_escape(&name), json_escape(&gender), json_escape(&photo)
    );
    let mut s = match TcpStream::connect(SERVER_HTTP) {
        Ok(x) => x,
        Err(e) => { log_line(&sh, &format!("网络异常：{}", e)); return; }
    };
    let _ = s.set_read_timeout(Some(Duration::from_secs(20)));
    let req = format!(
        "POST /prepare HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        SERVER_HOST, body.len(), body
    );
    if s.write_all(req.as_bytes()).is_err() {
        log_line(&sh, "请求发送失败");
        return;
    }
    let mut buf = Vec::new();
    let _ = s.read_to_end(&mut buf);
    let text = String::from_utf8_lossy(&buf).to_string();
    let payload = text.split("\r\n\r\n").nth(1).unwrap_or("").trim().to_string();
    if !payload.starts_with("{\"ok\":true") {
        let reason = jstr(&payload, "reason").unwrap_or_else(|| "被拒绝".into());
        log_line(&sh, &format!("素材申请失败：{}", reason));
        set_status(&sh, "● 素材申请失败（2 秒后退出）");
        std::thread::sleep(Duration::from_secs(2));
        std::process::exit(1);
    }
    let token = jstr(&payload, "token").unwrap_or_default();

    // adb 端口转发（固定 19222）
    let dev = match pick_device() {
        Some(d) => d,
        None => { log_line(&sh, "未检测到设备"); set_status(&sh, "● 未检测到设备（USB 调试？）"); return; }
    };
    let socks = {
        let out = adb(&["-s", &dev, "shell", "cat", "/proc/net/unix"]);
        let mut v: Vec<String> = out.lines()
            .filter(|l| l.contains("devtools_remote"))
            .filter_map(|l| l.split_whitespace().last())
            .map(|x| x.trim_start_matches('@').to_string())
            .collect();
        v.sort(); v.dedup(); v
    };
    if socks.is_empty() {
        log_line(&sh, "未找到 webview 调试口（TBS Inspector 是否开启？）");
        set_status(&sh, "● 未找到调试口");
        return;
    }
    let _ = adb(&["-s", &dev, "forward", "tcp:19222", &format!("localabstract:{}", socks[0])]);
    log_line(&sh, &format!("已转发调试口 → 127.0.0.1:19222（{}）", socks[0].chars().take(32).collect::<String>()));

    let url = format!("{}?token={}&device={}", SERVER_WS, token, devcode);
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
        rt.block_on(tunnel_loop(url, "127.0.0.1:19222".to_string(), sh));
    });
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
        if self.last_scan.elapsed() > Duration::from_secs(1) && !self.running {
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
                    match check_probe(&self.code, &self.devcode) {
                        Ok(_) => {
                            self.verified = true;
                            if let Ok(mut s) = self.shared.lock() { s.status = "● 已授权".into(); }
                        }
                        Err(e) => {
                            if let Ok(mut s) = self.shared.lock() { s.status = format!("● 验证失败：{}", e); }
                            self.exiting = true;
                            self.exit_at = Some(Instant::now());
                        }
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
                        match rfd_pick() {
                            Some(p) => match compress_photo(&p) {
                                Some((data, size)) => {
                                    self.photo = data;
                                    self.photo_name = format!("{} (压缩后{}KB)", p.file_name().map(|x| x.to_string_lossy().to_string()).unwrap_or_default(), size / 1024);
                                    log_line(&self.shared, &format!("已选择照片：{}", self.photo_name));
                                }
                                None => {
                                    self.photo_name = "读取/压缩失败".into();
                                    log_line(&self.shared, "照片读取或压缩失败（仅支持 jpg/png）");
                                }
                            },
                            None => {
                                log_line(&self.shared, "未选择文件（对话框取消或路径解析失败）");
                            }
                        }
                    }
                    ui.label(&self.photo_name);
                });
                ui.add_space(8.0);
                let ok = !self.code.trim().is_empty() && !self.name.trim().is_empty()
                    && (self.gender == "男" || self.gender == "女")
                    && !self.photo.is_empty() && !self.running;
                let label = if self.running { "注入中…" } else { "保存并应用" };
                if ui.add_enabled(ok, egui::Button::new(egui::RichText::new(label).size(15.0)).min_size(egui::vec2(360.0, 40.0))).clicked() {
                    self.running = true;
                    let sh = self.shared.clone();
                    let (c, d, n, g, p) = (self.code.clone(), self.devcode.clone(), self.name.clone(), self.gender.clone(), self.photo.clone());
                    std::thread::spawn(move || start_cloud(c, d, n, g, p, sh));
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
            if self.exiting {
                ui.add_space(6.0);
                ui.label(egui::RichText::new("授权未通过，2 秒后退出…").weak());
            }
        });
        if let Some(t) = self.exit_at {
            if t.elapsed() > Duration::from_secs(2) { std::process::exit(1); }
        }
        ctx.request_repaint_after(Duration::from_millis(400));
    }
}

// v7.0：照片压缩到最长边 200px JPEG q80（与 .NET v5.1 一致，载荷 ~20KB）
fn compress_photo(path: &std::path::Path) -> Option<(String, usize)> {
    let img = image::open(path).ok()?;
    let thumb = img.thumbnail(200, 200);
    let mut buf: Vec<u8> = Vec::new();
    let mut cur = std::io::Cursor::new(&mut buf);
    thumb.write_to(&mut cur, image::ImageFormat::Jpeg).ok()?;
    Some((format!("data:image/jpeg;base64,{}", b64(&buf)), buf.len()))
}

fn rfd_pick() -> Option<std::path::PathBuf> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let script = "[Console]::OutputEncoding=[Text.Encoding]::UTF8; Add-Type -AssemblyName System.Windows.Forms; $d=New-Object System.Windows.Forms.OpenFileDialog; $d.Filter='Images|*.jpg;*.jpeg;*.png'; if($d.ShowDialog() -eq 'OK'){Write-Output $d.FileName}";
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
            .with_inner_size([500.0, 680.0])
            .with_min_inner_size([460.0, 560.0]),
        ..Default::default()
    };
    eframe::run_native("高校认证 v6.4", opts, Box::new(|cc| {
        install_cjk_font(&cc.egui_ctx);
        Box::new(App::default())
    }))
}
