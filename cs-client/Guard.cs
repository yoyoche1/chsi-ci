// Guard —— 防破解三件套（依据 PROTECTION.md 的正确顺序）：
//   ① 反调试探针（IsDebuggerPresent / 远程调试 / PEB+NtGlobalFlag / Dr0-3 硬件断点）
//   ② .text 区段自封签（构建后就地注入哈希，运行时比对；占位符方案避免自指死循环）
//   ③ 中毒策略：不立刻退出——授权静默失败 + 随机 15~40s 后安静退出（伪装成网络问题）
using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

static class Guard
{
    // 封签占位符：8 字节 magic + 64 字节 '0'（构建后由 seal.py 把 64 字节覆盖为 .text 的 sha256 hex）
    // 字节数组字面量：原始 ASCII 直接落进 PE 数据区（Encoding.GetBytes 只会留下 UTF-16 串，seal.py 找不到）
    static readonly byte[] SEAL_MAGIC = { 0x43, 0x48, 0x53, 0x49, 0x53, 0x45, 0x41, 0x4C };

    static int _compromised; // 0=ok 1=调试器 2=完整性
    public static bool Compromised => _compromised != 0;

    public static void Init()
    {
        try { if (AntiDebug()) _compromised = 1; } catch { }
        try { if (_compromised == 0 && !IntegrityOk()) _compromised = 2; } catch { _compromised = 2; }
        try { if (_compromised == 0 && BadParent()) _compromised = 3; } catch { }
        try { if (_compromised == 0 && TimeHooked()) _compromised = 4; } catch { }
        if (Compromised) PoisonExit();
        // 更难：运行 60s / 180s 后静默复检（中途attach调试器/补丁也能被逮）
        new Thread(() => { Thread.Sleep(60000); ReCheck(); }) { IsBackground = true }.Start();
        new Thread(() => { Thread.Sleep(180000); ReCheck(); }) { IsBackground = true }.Start();
    }

    static void ReCheck()
    {
        if (Compromised) return;
        bool bad = false;
        try { bad = AntiDebug() || !IntegrityOk() || BadParent() || TimeHooked(); } catch { bad = true; }
        if (bad) { _compromised = 5; PoisonExit(); }
    }

    static void PoisonExit()
    {
        // 中毒：授权静默失败（AuthOnce 查 Compromised），随机 15~40s 后安静退出，伪装网络问题
        new Thread(() => { try { Thread.Sleep(new Random().Next(15000, 40000)); } catch { } Environment.Exit(1); }) { IsBackground = true }.Start();
    }

    // 父进程黑名单：从调试器/注入器启动时 parent 不是 explorer
    static bool BadParent()
    {
        string[] bad = { "x64dbg", "x32dbg", "ollydbg", "dnspy", "cheatengine", "ida", "windbg", "gdb", "radare", "immunity", "x96dbg", "frida", "processhacker", "hacker" };
        try
        {
            int pid = -1;
            var pbi = new PROCESS_BASIC_INFORMATION(); int rl = 0;
            if (NtQueryInformationProcess(GetCurrentProcess(), 0, ref pbi, Marshal.SizeOf(pbi), ref rl) == 0)
                pid = pbi.InheritedFromUniqueProcessId.ToInt32();
            if (pid <= 4) return false;
            var pn = Process.GetProcessById(pid).ProcessName.ToLowerInvariant();
            foreach (var b in bad) if (pn.Contains(b)) return true;
        }
        catch { }
        return false;
    }

    // 计时探针：Sleep(100) 被偷（hook NtDelayExecution 加速跑）会低于阈值
    static bool TimeHooked()
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        Thread.Sleep(100);
        sw.Stop();
        return sw.ElapsedMilliseconds < 60;
    }

    // ===== ① 反调试探针（guard.go 等义移植）=====
    [DllImport("kernel32.dll")] static extern bool IsDebuggerPresent();
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, ref bool isDebugged);
    [DllImport("ntdll.dll")] static extern int NtQueryInformationProcess(IntPtr hProcess, int infoClass, ref PROCESS_BASIC_INFORMATION info, int length, ref int returnLength);
    [DllImport("kernel32.dll")] static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr baseAddress, byte[] buffer, IntPtr size, ref IntPtr bytesRead);
    [DllImport("kernel32.dll")] static extern bool GetThreadContext(IntPtr hThread, byte[] context);
    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentThread();

    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_BASIC_INFORMATION
    {
        public IntPtr ExitStatus;
        public IntPtr PebBaseAddress;
        public IntPtr AffinityMask;
        public int BasePriority;
        public IntPtr UniqueProcessId;
        public IntPtr InheritedFromUniqueProcessId;
    }

    static bool AntiDebug()
    {
        if (Debugger.IsAttached) return true;
        if (IsDebuggerPresent()) return true;
        bool dbg = false;
        try { CheckRemoteDebuggerPresent(GetCurrentProcess(), ref dbg); } catch { }
        if (dbg) return true;

        var pbi = new PROCESS_BASIC_INFORMATION();
        int rl = 0;
        if (NtQueryInformationProcess(GetCurrentProcess(), 0, ref pbi, Marshal.SizeOf(pbi), ref rl) == 0 && pbi.PebBaseAddress != IntPtr.Zero)
        {
            var buf = new byte[4];
            var rd = IntPtr.Zero;
            // PEB+0x02 = BeingDebugged
            if (ReadProcessMemory(GetCurrentProcess(), pbi.PebBaseAddress + 2, buf, (IntPtr)1, ref rd) && buf[0] != 0) return true;
            // PEB->NtGlobalFlag (x64 +0xBC)，调试器会打开 FLG_HEAP_* 位
            rd = IntPtr.Zero;
            if (ReadProcessMemory(GetCurrentProcess(), pbi.PebBaseAddress + 0xBC, buf, (IntPtr)4, ref rd) && (BitConverter.ToUInt32(buf, 0) & 0x70) != 0) return true;
        }

        // 硬件断点 Dr0-3（x64 CONTEXT 1232B；flags@0x30 = AMD64|DEBUG_REGISTERS；Dr@0x48..0x60）
        var ctx = new byte[1232];
        BitConverter.GetBytes(0x00100010u).CopyTo(ctx, 0x30);
        try
        {
            if (GetThreadContext(GetCurrentThread(), ctx))
                for (int off = 0x48; off <= 0x60; off += 8)
                    if (BitConverter.ToUInt64(ctx, off) != 0) return true;
        }
        catch { }
        return false;
    }

    // ===== ② .text 区段自封签 =====
    static int IndexOf(byte[] hay, byte[] needle)
    {
        for (int i = 0; i + needle.Length <= hay.Length; i++)
        {
            bool ok = true;
            for (int j = 0; j < needle.Length; j++) if (hay[i + j] != needle[j]) { ok = false; break; }
            if (ok) return i;
        }
        return -1;
    }

    static bool IntegrityOk()
    {
        string path;
        try { path = Process.GetCurrentProcess().MainModule.FileName; } catch { return false; }
        byte[] all;
        try { all = File.ReadAllBytes(path); } catch { return false; }

        int idx = IndexOf(all, SEAL_MAGIC);
        if (idx < 0 || idx + 72 > all.Length) return false;          // 未封签 = 拒绝
        string stored;
        try { stored = Encoding.ASCII.GetString(all, idx + 8, 64); } catch { return false; }
        if (stored.Any(ch => !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f')))) return false;
        return ComputeSealedHash(all, idx) == stored;
    }

    // v4.4.5：全文件哈希（封签区清零后）——bundle/overlay 被改也必然露馅
    // （.text 校验拦不住"槽位覆盖"攻击：托管 dll 在 PE 尾部 overlay，改它不碰代码段）
    public static string ComputeSealedHash(byte[] all, int idx)
        {
            var buf = (byte[])all.Clone();
            for (int i = idx + 8; i < idx + 72 && i < buf.Length; i++) buf[i] = 0x30;
            using var sha = SHA256.Create();
            var h = sha.ComputeHash(buf);
            return BitConverter.ToString(h).Replace("-", "").ToLowerInvariant();
        }

        // 授权握手用的自身哈希（原样，含封签值）——服务端白名单比对的依据
        public static string SelfSha256()
        {
            try
            {
                var path = Process.GetCurrentProcess().MainModule.FileName;
                using var sha = SHA256.Create();
                return BitConverter.ToString(sha.ComputeHash(File.ReadAllBytes(path))).Replace("-", "").ToLowerInvariant();
            }
            catch { return ""; }
        }
}
