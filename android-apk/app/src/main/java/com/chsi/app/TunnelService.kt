package com.chsi.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.*
import okhttp3.MediaType.Companion.toMediaType
import android.content.Context
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.os.Handler
import android.os.Looper
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.security.MessageDigest
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

// v1.4：纯系统解析。原「优选 IP」把 CF 边缘 104.19.7.7 排在解析结果首位，
// 而服务器早已不在 CF（自签直连 :62747，CF 不监听该端口）→ 每次请求先对 CF
// 白等一个 connectTimeout(10s) 再回落真实地址，这就是「验证授权很慢」的根因。
object PrefDns : okhttp3.Dns {
    override fun lookup(hostname: String): List<java.net.InetAddress> =
        okhttp3.Dns.SYSTEM.lookup(hostname)
}

class TunnelService : Service() {
    companion object {
        const val CH_ID = "chsi_tunnel"
        const val EXTRA_CODE = "code"
        const val EXTRA_NAME = "name"
        const val EXTRA_GENDER = "gender"
        const val EXTRA_PHOTO = "photo"
        const val EXTRA_PAIR_PORT = "pair_port"
        const val EXTRA_PAIR_CODE = "pair_code"
        const val EXTRA_CONNECT_PORT = "connect_port"

        const val SERVER_HOST = "chsi.889678.xyz"
        // v4.9.13g：雨云VPS架构——自签证书 + SPKI pin（cf/雨云只见密文字节流）
        val SERVER_PIN = okhttp3.CertificatePinner.Builder()
            .add("chsi.889678.xyz", "sha256/hLQOuOytSGSsh+z8/6NQFhRMdLqNStzZyt8zTXtVeRw=")
            .build()
        const val SERVER_PORT = 62747

        @Volatile var status = "● 未运行"
        @Volatile var logBuf = StringBuilder()
        @Volatile var onLog: ((String) -> Unit)? = null
        @Volatile var onStatus: ((String) -> Unit)? = null

        fun appendLog(s: String) {
            logBuf.append(s).append('\n')
            if (logBuf.length > 8000) logBuf.delete(0, 2000)
            onLog?.invoke(s)
        }
    }

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var tunnel: TunnelClient? = null
    private var adb: AdbShell? = null

    private val http = OkHttpClient.Builder()
        // v1.3：雨云VPS 自签证书——系统信任必失败（Trust anchor not found），
        // 改用「整证书 SHA-256 当信任根」（见 PinnedTrust）
        .dns(PrefDns)
        .sslSocketFactory(PinnedTrust.sslContext.socketFactory, PinnedTrust.trustManager)
        .hostnameVerifier(PinnedTrust.hostVerifier)
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(15, TimeUnit.SECONDS)
        .build()

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startForeground(1, buildNotification("启动中…"))
        val code = intent?.getStringExtra(EXTRA_CODE) ?: ""
        val name = intent?.getStringExtra(EXTRA_NAME) ?: ""
        val gender = intent?.getStringExtra(EXTRA_GENDER) ?: "男"
        val photo = intent?.getStringExtra(EXTRA_PHOTO) ?: ""
        val pairPort = intent?.getIntExtra(EXTRA_PAIR_PORT, 0) ?: 0
        val pairCode = intent?.getStringExtra(EXTRA_PAIR_CODE) ?: ""
        val connectPort = intent?.getIntExtra(EXTRA_CONNECT_PORT, 0) ?: 0

        scope.launch {
            runCatching { runFlow(code, name, gender, photo, pairPort, pairCode, connectPort) }
                .onFailure { appendLog("错误：" + (it.message ?: it.javaClass.simpleName)); setStatus("● 失败") }
        }
        return START_STICKY
    }

    override fun onDestroy() {
        tunnel?.stop()
        scope.cancel()
        adb?.killServer()
        super.onDestroy()
    }

    private fun setStatus(s: String) {
        status = s
        onStatus?.invoke(s)
        updateNotification(s)
    }

    private suspend fun runFlow(code: String, name: String, gender: String, photo: String,
                                pairPort: Int, pairCode: String, connectPort: Int) {
        // v1.6：服务器固定默认（界面配置入口已按需求移除，不再读 prefs）
        val base = "https://$SERVER_HOST:$SERVER_PORT"
        val wsUrl = "wss://$SERVER_HOST:$SERVER_PORT/tunnel"
        appendLog("服务器：$SERVER_HOST:$SERVER_PORT")

        setStatus("● 初始化 adb…")
        val shell = AdbShell(this@TunnelService)
        adb = shell
        shell.startServer()

        var pPort = pairPort
        var pHost = "127.0.0.1"
        var cPort = connectPort
        if (pairCode.isNotBlank() && pPort <= 0) {
            setStatus("● 自动检测配对端口…")
            nsdDiscover("_adb-tls-pairing._tcp.", 5000)?.let { (h, p) ->
                pHost = h; pPort = p
                appendLog("已自动发现配对端口 $h:$p")
            } ?: appendLog("mDNS 未发现配对服务（配对对话框打开了吗？）")
        }
        if (pairCode.isNotBlank() && pPort > 0) {
            setStatus("● 无线调试配对…")
            appendLog("提示：『使用配对码配对设备』弹窗必须保持打开；端口/配对码每次打开弹窗都会变")
            var p = if (pHost == "127.0.0.1") shell.pair(pPort, pairCode) else shell.pairHost(pHost, pPort, pairCode)
            appendLog("配对：" + p.trim().ifBlank { "(无输出)" })
            // v1.5：mDNS 解析出的 host 常是 IPv6 链路本地地址，部分 ROM 上 adb 配对失败
            // → 同端口回落 127.0.0.1 重试（adbd 配对模式监听所有接口，回环必通）
            val pairOk = p.contains("uccess", true) || p.contains("成功")
            if (!pairOk && pHost != "127.0.0.1") {
                appendLog("配对未确认，用 127.0.0.1:$pPort 重试…")
                p = shell.pair(pPort, pairCode)
                appendLog("配对(回环重试)：" + p.trim().ifBlank { "(无输出)" })
            }
        }
        if (cPort <= 0) {
            autoDetectConnect(shell)?.let {
                cPort = it
                appendLog("已自动发现连接端口 $it")
            } ?: appendLog("自动检测未命中，请手动填连接端口")
        }
        if (cPort > 0) {
            setStatus("● 连接本机调试服务…")
            val c = shell.connect(cPort)
            appendLog("connect：" + c.trim().ifBlank { "(无输出)" })
        }
        val devs = shell.devices()
        if (!devs.contains("device")) {
            setStatus("● adb 未连接——请在开发者选项开启无线调试并配对")
            appendLog(devs.ifBlank { "adb devices 无输出" })
            appendLog("排查：①无线调试已开启？②『使用配对码配对设备』弹窗开着？③配对端口填的是弹窗里的端口（不是无线调试主页的端口）④6位码是否最新")
            return
        }

        setStatus("● 扫描调试口…")
        var socks = shell.findDevtoolsSockets()
        if (socks.isEmpty()) {
            appendLog("首次扫描无调试口——Inspector 只对重启后的新 webview 生效；请在 QQ 里打开目标网页，等待中…")
            var tries = 0
            while (socks.isEmpty() && tries < 10) {
                Thread.sleep(3000)
                socks = shell.findDevtoolsSockets()
                tries++
            }
        }
        if (socks.isEmpty()) {
            setStatus("● 未找到调试口（QQ 内 TBS Inspector 是否开启？）")
            appendLog("扫描约 30 秒无结果。排查：①debugtbs.qq.com 勾『打开TBS内核Inspector调试功能』后【彻底杀掉 QQ 重开】 ②QQ 里打开一个网页（webview 活着才有调试口） ③再点启动")
            val cand = shell.listSocketCandidates()
            if (cand.isNotEmpty()) appendLog("unix socket 候选（qq/tencent/x5/webview 相关）：\n  " + cand.joinToString("\n  "))
            return
        }
        val ports = mutableListOf<Int>()
        var p = 19222
        socks.take(8).forEach { sk ->
            shell.forward(p, sk)
            ports.add(p); p++
        }
        appendLog("已转发 ${ports.size} 个调试口")

        // 设备码：指纹 + 轮换计数（与 PC 行为一致，完成一次 +1）
        val prefs = getSharedPreferences("chsi", MODE_PRIVATE)
        val rot = prefs.getInt("used", 0)
        val device = DeviceId.fingerprint(this) + "-" + rot.toString(36).uppercase()

        // /check 验证
        setStatus("● 验证授权…")
        val exehash = apkCertHash()
        val nonce = "a" + System.currentTimeMillis()
        val checkBody = JSONObject().apply {
            put("platform", "android"); put("code", code); put("device", device)
            put("nonce", nonce); put("ver", "cs-apk-1.1"); put("exehash", exehash)
        }.toString()
        var resp = postJson("$base/check", checkBody)
        if (!resp.optBoolean("ok")) {
            val rs = resp.optString("reason")
            val msg = if (rs == "already_rewritten") "该码已完成改写，不能再用"
                      else if (rs == "locked") "尝试次数过多，联系客服解锁"
                      else rs
            setStatus("● 未授权：" + msg)
            appendLog("验证失败：" + msg)
            return
        }
        appendLog("验证通过")

        // /prepare 拿 token
        val prepBody = JSONObject().apply {
            put("device", device); put("code", code)
            put("nonce", "b" + System.currentTimeMillis()); put("ver", "cs-apk-1.1")
            put("exehash", exehash); put("name", name); put("gender", gender); put("photo", photo)
        }.toString()
        resp = postJson("$base/prepare", prepBody)
        if (!resp.optBoolean("ok")) {
            val rs2 = resp.optString("reason")
            val msg2 = if (rs2 == "already_rewritten") "该码已完成改写，不能再用"
                       else if (rs2 == "locked") "尝试次数过多，联系客服解锁"
                       else rs2
            setStatus("● 准备失败：" + msg2)
            appendLog(msg2)
            return
        }
        val token = resp.getString("token")
        appendLog("素材就绪")

        setStatus("● 注入运行中…")
        // 防护探测（对齐 exe）：调试器/注入框架/签名不符 → deg=1 → 云端静默毒化
        var deg = "0"
        val sigBad = !Guard.sigOk(this, "c43a4f1a72f4eeef262b0341cdaea516525560e3f7734bd6ca0fb8ec4e8046a9")
        if (Guard.hasTracer() || Guard.hasInjection() || sigBad) {
            deg = "1"
            appendLog("环境异常（静默降级）")
        }
        val t = TunnelClient(wsUrl, token, device, 19222, ports, deg,
            onLog = { appendLog(it) },
            onStatus = { setStatus(it) },
            onExit = {
                prefs.edit().putInt("used", rot + 1).apply()
                setStatus("● 已完成并退出")
                stopSelf()
            })
        tunnel = t
        t.start()

        // v4.9.4：周期重扫——QQ 重开后 webview 调试口（带 PID）会变，旧转发失效。
        thread(name = "sock-rescan") {
            while (true) {
                Thread.sleep(10_000)
                try {
                    val socks2 = shell.findDevtoolsSockets()
                    if (socks2.isEmpty()) continue
                    val newPorts = mutableListOf<Int>()
                    var p2 = 19222
                    socks2.take(8).forEach { sk ->
                        shell.forward(p2, sk)
                        newPorts.add(p2); p2++
                    }
                    if (newPorts != t.livePorts) {
                        t.sendPortUpdate(newPorts)
                        appendLog("调试口重扫：" + newPorts.size + " 个（已更新云端）")
                    }
                } catch (e: Exception) { /* 设备暂离，下轮再试 */ }
            }
        }
    }

    // ===== v4.9.13：无线调试自动检测 =====

    // mDNS 发现服务（配对/连接），超时返回 null
    private suspend fun nsdDiscover(serviceType: String, timeoutMs: Long): Pair<String, Int>? =
        kotlinx.coroutines.suspendCancellableCoroutine { cont ->
            val nsd = getSystemService(Context.NSD_SERVICE) as NsdManager
            var done = false
            lateinit var disc: NsdManager.DiscoveryListener
            fun finish(r: Pair<String, Int>?) {
                if (done) return
                done = true
                try { nsd.stopServiceDiscovery(disc) } catch (_: Exception) {}
                if (cont.isActive) cont.resume(r, null)
            }
            disc = object : NsdManager.DiscoveryListener {
                override fun onServiceFound(s: NsdServiceInfo) {
                    if (done) return
                    nsd.resolveService(s, object : NsdManager.ResolveListener {
                        override fun onServiceResolved(info: NsdServiceInfo) {
                            val host = info.host?.hostAddress ?: "127.0.0.1"
                            finish(Pair(host, info.port))
                        }
                        override fun onResolveFailed(info: NsdServiceInfo, errorCode: Int) { /* 等下一个或超时 */ }
                    })
                }
                override fun onServiceLost(s: NsdServiceInfo) {}
                override fun onDiscoveryStarted(t: String) {}
                override fun onDiscoveryStopped(t: String) {}
                override fun onStartDiscoveryFailed(t: String, e: Int) { finish(null) }
                override fun onStopDiscoveryFailed(t: String, e: Int) {}
            }
            try { nsd.discoverServices(serviceType, NsdManager.PROTOCOL_DNS_SD, disc) } catch (e: Exception) { finish(null) }
            Handler(Looper.getMainLooper()).postDelayed({ finish(null) }, timeoutMs)
        }

    // 连接端口自动检测：mDNS → 回环 adb 端口扫描兜底
    private suspend fun autoDetectConnect(shell: AdbShell): Int? {
        appendLog("自动检测：mDNS 发现 _adb-tls-connect …")
        nsdDiscover("_adb-tls-connect._tcp.", 4000)?.let { (h, p) ->
            appendLog("mDNS 发现 $h:$p，尝试 adb connect …")
            val out = shell.connectHost(h, p)
            appendLog("connect：" + out.trim().ifBlank { "(无输出)" })
            if (out.contains("connected to", true)) return p
        }
        appendLog("mDNS 未命中，回环扫描 adb 端口（约 20 秒）…")
        setStatus("● 回环扫描调试口…")
        val found = java.util.concurrent.atomic.AtomicInteger(-1)
        val pool = java.util.concurrent.Executors.newFixedThreadPool(256)
        val futures = mutableListOf<java.util.concurrent.Future<*>>()
        val pkt = java.nio.ByteBuffer.allocate(24)
        pkt.putInt(0x434E584E); pkt.putInt(0x01000001); pkt.putInt(0x00100000)
        pkt.putInt(0); pkt.putInt(0); pkt.putInt(0x434E584E.inv())
        val cnxn = pkt.array()
        for (p in 32768..60999) {
            futures.add(pool.submit {
                if (found.get() >= 0) return@submit
                try {
                    val s = java.net.Socket()
                    s.connect(java.net.InetSocketAddress("127.0.0.1", p), 120)
                    s.soTimeout = 250
                    s.getOutputStream().write(cnxn); s.getOutputStream().flush()
                    val rb = ByteArray(4)
                    val n = try { s.getInputStream().read(rb) } catch (_: Exception) { -1 }
                    s.close()
                    if (n == 4 && rb[0] == 'C'.code.toByte() && rb[1] == 'N'.code.toByte() && rb[2] == 'X'.code.toByte() && rb[3] == 'N'.code.toByte()) {
                        found.compareAndSet(-1, p)
                    }
                } catch (_: Exception) {}
            })
        }
        for (f in futures) try { f.get() } catch (_: Exception) {}
        pool.shutdown()
        val p = found.get()
        if (p > 0) {
            val out = shell.connect(p)
            appendLog("connect($p)：" + out.trim().ifBlank { "(无输出)" })
            if (out.contains("connected to", true)) return p
        }
        return null
    }

    private fun postJson(url: String, body: String): JSONObject {
        val req = Request.Builder().url(url)
            .post(body.toRequestBody("application/json".toMediaType()))
            .build()
        http.newCall(req).execute().use { r ->
            return JSONObject(r.body?.string() ?: "{}")
        }
    }

    private fun apkCertHash(): String {
        return try {
            val info = if (Build.VERSION.SDK_INT >= 28)
                packageManager.getPackageInfo(packageName, android.content.pm.PackageManager.GET_SIGNING_CERTIFICATES)
            else
                @Suppress("DEPRECATION") packageManager.getPackageInfo(packageName, android.content.pm.PackageManager.GET_SIGNATURES)
            val sigs: List<android.content.pm.Signature>? = if (Build.VERSION.SDK_INT >= 28)
                info.signingInfo?.apkContentsSigners?.toList()
            else
                @Suppress("DEPRECATION") info.signatures?.toList()
            val first = sigs?.firstOrNull() ?: return "unknown"
            MessageDigest.getInstance("SHA-256").digest(first.toByteArray())
                .joinToString("") { "%02x".format(it) }
        } catch (e: Exception) { "unknown" }
    }

    private fun buildNotification(text: String): Notification {
        val mgr = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        if (Build.VERSION.SDK_INT >= 26) {
            mgr.createNotificationChannel(NotificationChannel(CH_ID, "隧道服务", NotificationManager.IMPORTANCE_LOW))
        }
        val pi = PendingIntent.getActivity(this, 0,
            Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
        return NotificationCompat.Builder(this, CH_ID)
            .setSmallIcon(android.R.drawable.ic_lock_idle_lock)
            .setContentTitle("高校认证")
            .setContentText(text)
            .setContentIntent(pi)
            .setOngoing(true)
            .build()
    }

    private fun updateNotification(text: String) {
        val mgr = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        mgr.notify(1, buildNotification(text))
    }
}
