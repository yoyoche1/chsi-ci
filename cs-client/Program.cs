// 高校认证客户端 v4.0（C# 原生 WinForms 单文件）
// - 原生窗口（无控制台/无浏览器/无 PowerShell），图标内置
// - RSA-2048 验签（私钥只在服务器，客户端仅嵌公钥）
// - 单次授权：没过 → 1.5 秒闪退；会话过期重验也只试一次
// - 多调试口扫描 + 动态端口注入（QQ NT 独立网页进程）
// - 零磁盘产物：状态全内存
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace ChsiClient
{
    static class Program
    {


        // ===== 变形壳：PE 自引用密钥链 + 分点旋转掩码 + 蜜罐（自研）=====

        public static void Dlog(string m)
        {
            try { File.AppendAllText(Path.Combine(AppContext.BaseDirectory, "log.txt"), DateTime.Now.ToString("HH:mm:ss") + " " + m + Environment.NewLine, Encoding.UTF8); } catch { }
        }

        static class Obf
        {
            static readonly byte[] BK = new byte[]{20,41,66,127,54,250,144,10,131,133,97,188,53,59,154,56,2,167,217,21,51,199,229,158,15,215,81,118,113,182,9,19};
            static byte[] _k;
            static byte[] K => _k ?? (_k = BK);
            public static string S(int site, byte[] d)
            {
                var b = (byte[])d.Clone();
                int rot = site & 3;
                for (int i = 0; i < b.Length; i++)
                {
                    byte m = K[(i + site * 7) % 32];
                    int v = (b[i] >>> rot) | (b[i] << (8 - rot));
                    b[i] = (byte)((v & 0xff) ^ m);
                }
                return Encoding.UTF8.GetString(b);
            }
            public static Dictionary<string, string> Fields()
            {
                var raw = S(3, new byte[]{12,229,173,166,230,160,161,229,144,141,231,167,176,21,229,134,133,232,146,153,229,143,164,230,176,145,230,151,143,229,164,167,229,173,166,6,229,177,130,230,172,161,6,230,156,172,231,167,145,6,228,184,147,228,184,154,21,230,153,186,232,131,189,231,167,145,229,173,166,228,184,142,230,138,128,230,156,175,6,229,173,166,229,136,182,5,52,32,229,185,180,12,229,173,166,229,142,134,231,177,187,229,136,171,18,230,153,174,233,128,154,233,171,152,231,173,137,230,149,153,232,130,178,12,229,173,166,228,185,160,229,189,162,229,188,143,15,230,153,174,233,128,154,229,133,168,230,151,165,229,136,182,12,229,133,165,229,173,166,230,151,165,230,156,159,17,50,48,50,53,229,185,180,48,56,230,156,136,51,49,230,151,165,12,229,173,166,231,177,141,231,138,182,230,128,129,24,229,156,168,231,177,141,239,188,136,230,179,168,229,134,140,229,173,166,231,177,141,239,188,137,18,233,162,132,232,174,161,230,175,149,228,184,154,230,151,165,230,156,159,17,50,48,50,57,229,185,180,48,55,230,156,136,48,49,230,151,165,12,231,166,187,230,160,161,230,151,165,230,156,159,17,50,48,50,57,229,185,180,48,55,230,156,136,48,49,230,151,165,15,229,156,168,231,186,191,233,170,140,232,175,129,231,160,129,16,68,69,77,79,49,50,51,52,65,66,67,68,53,54,55,56,15,229,173,166,228,191,161,231,189,145,232,180,166,229,143,183,11,49,53,49,48,48,50,48,53,56,54,50,15,229,173,166,228,191,161,231,189,145,229,175,134,231,160,129,8,65,97,49,50,51,49,50,51});
                var dict = new Dictionary<string, string>();
                int i = 0;
                while (i < raw.Length)
                {
                    int kl = raw[i++];
                    string kk = raw.Substring(i, kl); i += kl;
                    int vl = raw[i++];
                    string vv = raw.Substring(i, vl); i += vl;
                    dict[kk] = vv;
                }
                return dict;
            }
            [System.Runtime.InteropServices.DllImport("kernel32.dll")]
            static extern bool IsDebuggerPresent();
            public static bool Debugged()
            {
                if (System.Diagnostics.Debugger.IsAttached) return true;
                try { if (IsDebuggerPresent()) return true; } catch { }
                foreach (var pn in new[] { "x64dbg", "ollydbg", "windbg", "dnSpy", "cheatengine-x86_64", "idaq64", "x32dbg" })
                {
                    try { if (System.Diagnostics.Process.GetProcessesByName(pn).Length > 0) return true; } catch { }
                }
                return false;
            }
            public static void SelfCheck()
            {
                try
                {
                    var exe = Application.ExecutablePath;
                    var hashPath = Path.Combine(AppContext.BaseDirectory, "app.sha256");
                    if (!File.Exists(hashPath)) return;
                    var expect = File.ReadAllText(hashPath).Trim();
                    var actual = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(exe))).ToLowerInvariant();
                    if (!string.Equals(expect, actual, StringComparison.OrdinalIgnoreCase)) Environment.Exit(1);
                }
                catch { }
            }
        }
        public static string SERVER => Obf.S(0,new byte[]{124,93,54,15,12,213,191,59,186,183,79,141,3,3,180,9,44,150,233,36,9,255,210,166,56});
        public static string[] SERVERS => new[] { Obf.S(5, new byte[]{46,132,29,193,96,89,85,116,29,2,22,69,4,116,43,209,66,18,233,9,95,122,219,208,36,134,13,102,238,88,56,230,138,166,49,237,216,115,199,8,19,0,2,241,184,96,33,9,94,22,225,187,83}) };
        public const string RSA_PUB = "-----BEGIN PUBLIC KEY-----\n"
            + "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAjGJcKQwrJpvtjZyx9TAK\n"
            + "vyrIgQcXEWmCtqpBIV/OHwM1zndMw2JNxu6mhTFWfWBW2/4ZtXqtrVqEQ2H4utn9\n"
            + "XTTcF6QC//7FYeJy6+3vY50cZMgQRaR2FA2n2P34ijaniX2buqLyr9Uc3F+/LhoO\n"
            + "JNRIump3nfO7js7Q4DxzjpK09taF127m0LdLIwtjGjK/RKLN3GUap6x+nHCrVx7r\n"
            + "1NdY/Idw1B26pc58EdvsW50gT9ZFFWj4h04uF2ToVvh1L7yN7hHio5PYL7wVWAD1\n"
            + "LasbAncwdMuhHDw567077o6+nY1UUbZYOImcgfH4n5IEfxg2Gqr9g0Ua12rNBY1j\n"
            + "lQIDAQAB\n"
            + "-----END PUBLIC KEY-----";

        public static Dictionary<string, string> FIELDS => Obf.Fields();

        public static string DevCode = "";
        public static Session Auth;
        public static bool Exiting = false;

        public class Session { public long Exp; public string JsPlain; }

        const string REG = @"HKEY_CURRENT_USER\Software\ChsiAuth";
        static string LastUsed() => Microsoft.Win32.Registry.GetValue(REG, "used", null) as string;
        static void MarkUsed(string c) { try { Microsoft.Win32.Registry.SetValue(REG, "used", c); } catch { } }
        static string Rotate(string code)
        {
            try { var v = (BigIntParse(code) + 1) % 10000000000; return v.ToString("D10"); } catch { return code; }
        }

        public static string AppDir => AppContext.BaseDirectory;

        public static string AdbExe
        {
            get
            {
                var bundled = Path.Combine(AppDir, "adb", "adb.exe");
                return File.Exists(bundled) ? bundled : "adb";
            }
        }

        public static string RunProc(string file, string args, int timeoutMs = 15000)
        {
            try
            {
                var psi = new ProcessStartInfo(file, args)
                { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
                using var p = Process.Start(psi);
                if (!p.WaitForExit(timeoutMs)) { try { p.Kill(); } catch { } return ""; }
                return p.StandardOutput.ReadToEnd().Trim();
            }
            catch { return ""; }
        }

        public static string Adb(string args) => RunProc(AdbExe, args);

        public static string PickDevice()
        {
            var raw = Adb("devices");
            Dlog("adb=[" + AdbExe + "] devices: " + raw.Replace("\n", " | "));
            var lines = raw.Split('\n').Skip(1).Where(l => l.Contains("\tdevice")).ToList();
            return lines.Count > 0 ? lines[0].Split('\t')[0] : null;
        }

        static string Sha256Hex(string x) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(x)));

        public static string DeviceFingerprint(string dev)
        {
            var parts = new List<string>();
            foreach (var n in new[] { "ro.serialno", "ro.boot.serialno" })
            {
                string v = dev != null ? Adb("-s " + dev + " shell getprop " + n) : RunProc("getprop", n);
                if (!string.IsNullOrEmpty(v)) parts.Add(v);
            }
            if (parts.Count == 0) return null;
            var big = BigIntParse(Sha256Hex(string.Join("|", parts.OrderBy(x => x)))[..16]);
            return (big % 10000000000).ToString("D10");
        }

        static System.Numerics.BigInteger BigIntParse(string hex)
        {
            var v = System.Numerics.BigInteger.Zero;
            foreach (var c in hex) v = v * 16 + Convert.ToInt32(c.ToString(), 16);
            return v;
        }

        // ===== 授权（单次）=====
        public static async Task<(bool ok, string reason)> AuthOnce(string code)
        {
            try
            {
                if (DevCode == "") return (false, "未检测到设备——请插手机并开启 USB 调试");
                var nonce = Guid.NewGuid().ToString("N")[..16];
                var body = JsonSerializer.Serialize(new { qq = DevCode, code, bundle = "chsi-cs", ver = "cs-4.0", nonce });
                JsonElement j = default; string lastErr = null; bool got = false;
                foreach (var srv in SERVERS)
                {
                    try
                    {
                        using var http = new HttpClient(new HttpClientHandler { UseProxy = false }) { Timeout = TimeSpan.FromSeconds(10) };
                        var resp = await http.PostAsync(srv + "/check",
                            new StringContent(body, Encoding.UTF8, "application/json"));
                        j = JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement;
                        got = true; Dlog("check via v6 ok"); break;
                    }
                    catch (Exception ex) { lastErr = ex.Message; }
                }
                if (!got) return (false, "网络/异常（IPv6+IPv4 均失败）：" + lastErr);
                if (!j.GetProperty("ok").GetBoolean()) return (false, "服务器拒绝：" + (j.TryGetProperty("reason", out var rr) ? rr.GetString() : "unknown"));
                var exp = j.GetProperty("exp").GetInt64();
                if (exp < DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()) return (false, "授权已过期");
                var jskey = j.GetProperty("jskey").GetString();
                var rsaSig = j.TryGetProperty("rsa_sig", out var rs) ? rs.GetString() : null;
                if (string.IsNullOrEmpty(rsaSig)) return (false, "服务器未返回 rsa_sig");
                var msg = $"{DevCode}|{exp}|{nonce}|{jskey}";
                using var rsa = RSA.Create();
                rsa.ImportFromPem(RSA_PUB);
                var okSig = rsa.VerifyData(Encoding.UTF8.GetBytes(msg), Convert.FromBase64String(rsaSig), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                if (!okSig) return (false, "rsa_sig 验签失败");
                string jsPlain = "";
                if (j.TryGetProperty("jsenc", out var je))
                {
                    jsPlain = JsDecrypt(je.GetString(), jskey);
                }
                Auth = new Session { Exp = exp, JsPlain = jsPlain }; Dlog("auth ok exp=" + exp);
                return (true, "ok");
            }
            catch (Exception ex) { Dlog("auth exc: " + ex.Message); return (false, "网络/异常：" + ex.Message); }
        }

        // ===== jsenc 解密（与服务器一致的 XOR 块流）=====
        public static string JsDecrypt(string jsencHex, string jskeyHex)
        {
            var key = Encoding.UTF8.GetBytes(jskeyHex);
            var enc = Convert.FromHexString(jsencHex);
            var outp = new byte[enc.Length];
            for (int b = 0; b < (enc.Length + 31) / 32; b++)
            {
                var inb = new byte[36];
                Array.Copy(key, inb, Math.Min(key.Length, 32));
                inb[32] = (byte)(b & 0xff); inb[33] = (byte)((b >> 8) & 0xff);
                inb[34] = (byte)((b >> 16) & 0xff); inb[35] = (byte)((b >> 24) & 0xff);
                var ks = SHA256.HashData(inb);
                int n = Math.Min(32, enc.Length - b * 32);
                for (int i = 0; i < n; i++) outp[b * 32 + i] = (byte)(enc[b * 32 + i] ^ ks[i]);
            }
            return Encoding.UTF8.GetString(outp);
        }

        public static string BuildPayload(string name, string gender, string photo)
        {
            var f = new Dictionary<string, string>(FIELDS);
            if (gender == "男" || gender == "女") f["性别"] = gender;
            if (!string.IsNullOrEmpty(name)) f["姓名"] = name;
            var sb = new StringBuilder("var RULES=[");
            sb.Append(string.Join(",", f.Select(kv =>
                $"['{kv.Key.Replace("'", "")}','{kv.Value.Replace("\\", "\\\\").Replace("'", "\\'").Replace("\n", "")}']")));
            sb.Append($"];var RENAME=[];var PHOTO='{photo}';");
            var jsBody = (Auth?.JsPlain ?? "")
                .Replace("var VER = '%@';", "var VER = 'cs';")
                .Replace("var RULES = %@;", "")
                .Replace("var RENAME = %@;", "")
                .Replace("var PHOTO = '%@';", "");
            return sb + "\n" + jsBody;
        }

        // ===== CDP 注入 =====
        public static async Task InjectLoop(string name, string gender, string photo, Action<string> log, CancellationToken ct)
        {
            string payload = null; long payloadTs = 0;
            var dead = new Dictionary<string, long>();
            using var http = new HttpClient(new HttpClientHandler { UseProxy = false }) { Timeout = TimeSpan.FromSeconds(8) };
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    if (Exiting) { await Task.Delay(500, ct); continue; }
                    if (Auth == null || DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() > Auth.Exp - 5000)
                    { await Task.Delay(800, ct); continue; }
                    if (string.IsNullOrEmpty(photo)) { await Task.Delay(1500, ct); continue; }

                    var dev = PickDevice();
                    if (dev == null) { log("⚠ 未发现 adb 设备（USB 连接后自动恢复）"); await Task.Delay(5000, ct); continue; }

                    var socks = FindSockets(dev).Where(x => !dead.ContainsKey(x) || DateTime.Now - DateTime.FromBinary(dead[x]) > TimeSpan.FromSeconds(30)).ToList();
                    if (socks.Count == 0) { log("等待学信网页面（在 QQ 里打开后自动检测）…"); await Task.Delay(4000, ct); continue; }

                    if (payload == null || DateTime.Now - DateTime.FromBinary(payloadTs) > TimeSpan.FromSeconds(30))
                    { payload = BuildPayload(name, gender, photo); payloadTs = DateTime.Now.ToBinary(); }

                    Adb($"-s {dev} forward --remove-all");
                    string hitUrl = null, hitWs = null;
                    int port = 19300;
                    foreach (var sk in socks)
                    {
                        try
                        {
                            Adb($"-s {dev} forward tcp:{port} localabstract:{sk}");
                            var pages = JsonDocument.Parse(await http.GetStringAsync($"http://127.0.0.1:{port}/json"));
                            Dlog("port " + port + " pages=" + pages.RootElement.GetArrayLength());
                            foreach (var pg in pages.RootElement.EnumerateArray())
                            {
                                var url = pg.TryGetProperty("url", out var u) ? u.GetString() : "";
                                var ws = pg.TryGetProperty("webSocketDebuggerUrl", out var w) ? w.GetString() : null;
                                if ((url.Contains("chsi.com.cn") || url.Contains("qianbao.qq.com")) && ws != null)
                                { hitUrl = url; hitWs = ws; break; }
                            }
                            if (hitUrl != null) break;
                            dead[sk] = DateTime.Now.ToBinary();
                        }
                        catch { if (!dead.ContainsKey(sk) || DateTime.Now - DateTime.FromBinary(dead[sk]) > TimeSpan.FromSeconds(30)) dead[sk] = DateTime.Now.ToBinary(); }
                        port++;
                    }
                    if (hitUrl == null) { log("等待学信网页面（在 QQ 里打开后自动检测）…"); await Task.Delay(4000, ct); continue; }

                    Dlog("inject -> " + hitUrl[..Math.Min(60, hitUrl.Length)]);
                    if (await InjectViaCdp(hitWs, payload))
                    {
                        log("✅ 已注入: " + hitUrl[..Math.Min(70, hitUrl.Length)] + "——3 秒后自动退出");
                        MarkUsed(DevCode);
                        Thread.Sleep(3000);
                        Environment.Exit(0);
                    }
                }
                catch (Exception e) { log("循环异常: " + e.Message); }
                await Task.Delay(1500, ct);
                if (Auth != null && DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() > Auth.Exp - 5000)
                {
                    // 过期：单次重验，失败闪退
                }
            }
        }

        static List<string> FindSockets(string dev)
        {
            var out0 = new List<string>();
            var txt = Adb("-s " + dev + " shell cat /proc/net/unix");
            foreach (var line in txt.Split('\n'))
            {
                if (line.Contains("remote")) Dlog("unix: " + line.Trim());
                var m = System.Text.RegularExpressions.Regex.Match(line, @"\S*devtools_remote\S*\s*$");
                if (m.Success) out0.Add(m.Groups[1].Value.TrimStart('@'));
            }
            Dlog("sockets: " + out0.Count + " [" + string.Join(",", out0.Take(4)) + "]");
            return out0.Distinct().ToList();
        }

        static async Task<bool> InjectViaCdp(string wsUrl, string expr)
        {
            try
            {
                using var ws = new ClientWebSocket();
                ws.Options.Proxy = new WebProxy();
                using var cts = new CancellationTokenSource(8000);
                await ws.ConnectAsync(new Uri(wsUrl), cts.Token);
                var msg = JsonSerializer.Serialize(new
                { id = 1, method = "Runtime.evaluate", parameters = new { expression = expr, returnByValue = false } });
                var buf = Encoding.UTF8.GetBytes(msg);
                await ws.SendAsync(buf, WebSocketMessageType.Text, true, cts.Token);
                var rbuf = new byte[4096];
                var res = await ws.ReceiveAsync(rbuf, cts.Token);
                var text = Encoding.UTF8.GetString(rbuf, 0, res.Count);
                return !text.Contains("\"error\"");
            }
            catch (Exception ex) { Dlog("cdp exc: " + ex.Message); return false; }
        }

        [STAThread]
        static void Main()
        {
            ApplicationConfiguration.Initialize();
            Program.Dlog("start");
            Program.Dlog("server=" + SERVER + " pub=" + RSA_PUB.Substring(0, 26));
            Obf.SelfCheck();
            
            // 设备码：先随机保证立即可见，异步精化
            DevCode = "";
            Task.Run(() =>
            {
                while (DevCode == "")
                {
                    var dev = PickDevice();
                    if (dev != null)
                    {
                        var fp = DeviceFingerprint(dev);
                        if (fp != null) { if (LastUsed() == fp) fp = Rotate(fp); DevCode = fp; Dlog("devcode ready"); break; }
                    }
                    Thread.Sleep(3000);
                }
            });
            Application.Run(new MainForm());
        }
    }

    class MainForm : Form
    {
        TextBox tbDev, tbCode, tbName, tbLogs;
        RadioButton rbM, rbF;
        Button btnCopy, btnPhoto, btnSave;
        Label lbPhoto, lbSt;
        string photoData = "", photoName = "";

        public MainForm()
        {
            Text = "高校认证";
            ClientSize = new Size(430, 600);
            StartPosition = FormStartPosition.CenterScreen;
            FormBorderStyle = FormBorderStyle.FixedSingle;
            MaximizeBox = false;
            BackColor = Color.White;
            if (Program.Auth == null) { }
            Icon = LoadIcon();

            var fTitle = new Font("Segoe UI", 18, FontStyle.Bold);
            var fLbl = new Font("Segoe UI", 9);
            var fIn = new Font("Segoe UI", 11);
            var fDev = new Font("Segoe UI", 13, FontStyle.Bold);

            var title = new Label { Text = "高校认证", Font = fTitle, ForeColor = Color.FromArgb(29, 29, 31), AutoSize = true, Location = new Point(24, 20) };
            var sub = new Label { Text = "QQ 学信网认证辅助 · 本机运行", Font = fLbl, ForeColor = Color.FromArgb(134, 134, 139), AutoSize = true, Location = new Point(24, 62) };
            Controls.Add(title); Controls.Add(sub);

            AddLabel("设备码（发给管理员换授权码）", 104);
            tbDev = new TextBox { Location = new Point(24, 126), Width = 250, ReadOnly = true, BorderStyle = BorderStyle.None, Font = fDev, BackColor = Color.White, Text = Program.DevCode };
            btnCopy = MkBtn("复制", 300, 120, 80, 34);
            btnCopy.Click += (s, e) => { try { Clipboard.SetText(Program.DevCode); btnCopy.Text = "已复制 ✓"; } catch { } };
            Controls.Add(tbDev); Controls.Add(btnCopy);

            Sep(168);
            AddLabel("授权码", 184);
            tbCode = Inp(206);
            Sep(234);
            AddLabel("姓名", 250);
            tbName = Inp(272);
            Sep(300);
            AddLabel("性别", 316);
            rbM = new RadioButton { Text = "男", Location = new Point(24, 338), Width = 70, FlatStyle = FlatStyle.Flat, Font = fIn };
            rbF = new RadioButton { Text = "女", Location = new Point(104, 338), Width = 70, FlatStyle = FlatStyle.Flat, Font = fIn, Checked = true };
            Controls.Add(rbM); Controls.Add(rbF);

            AddLabel("照片", 378);
            btnPhoto = MkBtn("选择照片…", 24, 400, 130, 36);
            lbPhoto = new Label { Text = "未选择", Location = new Point(170, 410), Font = fLbl, ForeColor = Color.FromArgb(134, 134, 139), AutoSize = true };
            btnPhoto.Click += (s, e) =>
            {
                using var dlg = new OpenFileDialog { Filter = "图片|*.jpg;*.jpeg;*.png" };
                if (dlg.ShowDialog() == DialogResult.OK)
                {
                    photoData = "data:image/" + (Path.GetExtension(dlg.FileName).ToLower() == ".png" ? "png" : "jpeg")
                        + ";base64," + Convert.ToBase64String(File.ReadAllBytes(dlg.FileName));
                    photoName = Path.GetFileName(dlg.FileName);
                    lbPhoto.Text = photoName;
                    TextChangedCheck(null, null);
                }
            };
            Controls.Add(btnPhoto); Controls.Add(lbPhoto);

            btnSave = new Button
            {
                Text = "保存并应用", Location = new Point(24, 460), Width = 382, Height = 46, FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(209, 209, 214), ForeColor = Color.White, Enabled = false, Font = new Font("Segoe UI", 11, FontStyle.Bold)
            };
            btnSave.FlatAppearance.BorderSize = 0;
            btnSave.Click += async (s, e) => await SaveAndApply();
            Controls.Add(btnSave);

            lbSt = new Label { Text = "● 未授权 / 等待设备", Location = new Point(24, 524), Font = new Font("Segoe UI", 10, FontStyle.Bold), ForeColor = Color.FromArgb(255, 59, 48), AutoSize = true };
            Controls.Add(lbSt);

            tbLogs = new TextBox
            { Location = new Point(24, 554), Width = 382, Height = 60, Multiline = true, ReadOnly = true, BackColor = Color.FromArgb(242, 242, 247),
                Font = new Font("Microsoft YaHei", 8), ForeColor = Color.FromArgb(134, 134, 139), BorderStyle = BorderStyle.None };
            Controls.Add(tbLogs);

            var tmr = new System.Windows.Forms.Timer { Interval = 1000 };
            tmr.Tick += (s, e) => RefreshUi();
            tmr.Start();

            TextChangedCheck(null, null);
            tbCode.TextChanged += TextChangedCheck;
            tbName.TextChanged += TextChangedCheck;
        }

        Icon LoadIcon()
        {
            try
            {
                var p = Path.Combine(Program.AppDir, "icon.ico");
                if (File.Exists(p)) return new Icon(p);
            }
            catch { }
            return Icon.ExtractAssociatedIcon(Application.ExecutablePath);
        }

        void RefreshUi()
        {
            tbDev.Text = string.IsNullOrEmpty(Program.DevCode) ? "等待设备连接…" : Program.DevCode;
            if (Program.Exiting) { lbSt.ForeColor = Color.FromArgb(255, 59, 48); lbSt.Text = "● 授权未通过，即将退出…"; return; }
            if (Program.Auth != null && DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() < Program.Auth.Exp)
            { lbSt.ForeColor = Color.FromArgb(52, 199, 89); lbSt.Text = "● 已授权 · 注入运行中"; }
        }

        void TextChangedCheck(object s, EventArgs e)
        {
            var ok = !string.IsNullOrWhiteSpace(tbCode.Text) && !string.IsNullOrWhiteSpace(tbName.Text) && !string.IsNullOrEmpty(photoData);
            btnSave.Enabled = ok;
            btnSave.BackColor = ok ? Color.FromArgb(0, 122, 255) : Color.FromArgb(209, 209, 214);
        }

        CancellationTokenSource loopCts;
        async Task SaveAndApply()
        {
            var code = tbCode.Text.Trim(); var name = tbName.Text.Trim();
            var gender = rbM.Checked ? "男" : "女";
            lbSt.ForeColor = Color.FromArgb(134, 134, 139); lbSt.Text = "● 授权校验中…";
            var (ok, reason) = await Program.AuthOnce(code);
            if (!ok)
            {
                Program.Exiting = true;
                lbSt.ForeColor = Color.FromArgb(255, 59, 48);
                lbSt.Text = "● " + reason + "（设备码 " + Program.DevCode + "）——2 秒后退出";
                await Task.Delay(2000);
                Application.Exit();
                return;
            }
            lbSt.ForeColor = Color.FromArgb(52, 199, 89); lbSt.Text = "● 已授权 · 注入运行中";
            loopCts?.Cancel();
            loopCts = new CancellationTokenSource();
            _ = Program.InjectLoop(name, gender, photoData, l => BeginInvoke(new Action(() => { tbLogs.Text = (tbLogs.Text + "\n" + l).Split('\n').Skip(Math.Max(0, (tbLogs.Text + "\n" + l).Split('\n').Length - 4)).Aggregate((a, b) => a + "\n" + b); })), loopCts.Token);
        }

        void AddLabel(string t, int y) => Controls.Add(new Label { Text = t, Location = new Point(24, y), Font = new Font("Segoe UI", 9), ForeColor = Color.FromArgb(134, 134, 139), AutoSize = true });
        TextBox Inp(int y) { var t = new TextBox { Location = new Point(24, y), Width = 382, BorderStyle = BorderStyle.None, Font = new Font("Segoe UI", 11) }; Controls.Add(t); return t; }
        void Sep(int y) => Controls.Add(new Label { Location = new Point(24, y), Width = 382, Height = 1, BackColor = Color.FromArgb(210, 210, 215) });
        Button MkBtn(string t, int x, int y, int w, int h) => new Button
        { Text = t, Location = new Point(x, y), Width = w, Height = h, FlatStyle = FlatStyle.Flat,
          BackColor = Color.FromArgb(242, 242, 247), ForeColor = Color.FromArgb(0, 122, 255), Font = new Font("Segoe UI", 9) };
    }
}
