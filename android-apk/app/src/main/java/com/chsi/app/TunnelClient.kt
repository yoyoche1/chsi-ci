package com.chsi.app

import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okio.ByteString
import java.io.ByteArrayOutputStream
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

// 隧道客户端：协议与 PC Rust 端完全一致（帧加密 + LIST/OPEN/DATA/CLOSE/EXIT）
class TunnelClient(
    private val serverWs: String,      // wss://vip.bj.frp.one:50970/tunnel
    private val token: String,
    private val device: String,
    private val basePort: Int,         // 19222
    private val ports: List<Int>,      // 转发的全部端口
    private val deg: String,           // "1" = 疑似调试/注入环境 → 云端静默毒化
    private val onLog: (String) -> Unit,
    private val onStatus: (String) -> Unit,
    private val onExit: () -> Unit
) {
    @Volatile private var ws: WebSocket? = null
    @Volatile private var running = true
    @Volatile var livePorts: List<Int> = ports   // v4.9.4：周期重扫后可更新

    // v4.9.4：重扫后重发 LIST 帧（服务端更新端口表）
    fun sendPortUpdate(newPorts: List<Int>) {
        livePorts = newPorts
        val w = ws ?: return
        val list = "[" + newPorts.joinToString(",") + "]"
        sendFrame(w, frame(0x04, 0, list.toByteArray()))
    }
    private val streams = ConcurrentHashMap<Int, Socket>()
    private val key: ByteArray = Crypto.streamKey(token)

    private val client = OkHttpClient.Builder()
        .dns(PrefDns)
        .pingInterval(25, TimeUnit.SECONDS)
        .connectTimeout(10, TimeUnit.SECONDS)
        .build()

    fun start() {
        thread(name = "tunnel-retry") {
            while (running) {
                try { connectOnce() } catch (e: Exception) {
                    onStatus("● 隧道连接失败，3 秒后重试")
                    onLog("隧道错误：" + (e.message ?: e.javaClass.simpleName))
                }
                Thread.sleep(3000)
            }
        }
    }

    fun stop() {
        running = false
        ws?.close(1000, "stop")
        streams.values.forEach { try { it.close() } catch (_: Exception) {} }
        streams.clear()
    }

    private fun connectOnce() {
        val url = "$serverWs?token=$token&device=$device&sig=${Crypto.tunnelSig(token, device)}&deg=$deg"
        onStatus("● 连接隧道…")
        val latch = java.util.concurrent.CountDownLatch(1)
        var failed: Throwable? = null
        val w = client.newWebSocket(
            Request.Builder().url(url).build(),
            object : WebSocketListener() {
                override fun onOpen(webSocket: WebSocket, response: okhttp3.Response) {
                    ws = webSocket
                    onStatus("● 已授权 · 注入运行中")
                    // LIST 帧上报端口表（加密）
                    val list = "[" + ports.joinToString(",") + "]"
                    sendFrame(webSocket, frame(0x04, 0, list.toByteArray()))
                    onLog("隧道已连接（${ports.size} 个调试口）")
                    latch.countDown()
                }

                override fun onMessage(webSocket: WebSocket, bytes: ByteString) {
                    onRawFrame(bytes.toByteArray())
                }

                override fun onFailure(webSocket: WebSocket, t: Throwable, response: okhttp3.Response?) {
                    failed = t
                    latch.countDown()
                }

                override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
                    webSocket.close(code, reason)
                }
            })
        latch.await(15, TimeUnit.SECONDS)
        if (failed != null) throw failed!!
        // 阻塞直到 ws 断开
        while (running && ws === w) { Thread.sleep(500) }
    }

    private fun onRawFrame(raw: ByteArray) {
        val buf = Crypto.xorStream(raw, key)
        if (buf.size < 5) return
        val t = buf[0].toInt() and 0xFF
        val id = ((buf[1].toInt() and 0xFF) shl 24) or ((buf[2].toInt() and 0xFF) shl 16) or
                 ((buf[3].toInt() and 0xFF) shl 8) or (buf[4].toInt() and 0xFF)
        val body = buf.copyOfRange(5, buf.size)
        when (t) {
            0x01 -> openStream(id, body)
            0x02 -> streams[id]?.getOutputStream()?.write(body)
            0x03 -> { streams.remove(id)?.close() }
            0x05 -> {
                onStatus("● 全部注入完成")
                onLog("云端通知完成，退出")
                onExit()
            }
        }
    }

    private fun openStream(id: Int, body: ByteArray) {
        val port = if (body.size >= 2) ((body[0].toInt() and 0xFF) shl 8) or (body[1].toInt() and 0xFF) else basePort
        try {
            val s = Socket("127.0.0.1", port)
            streams[id] = s
            thread(name = "stream-$id") {
                val b = ByteArray(16384)
                while (true) {
                    val n = try { s.getInputStream().read(b) } catch (_: Exception) { -1 }
                    if (n <= 0) break
                    ws?.let { sendFrame(it, frame(0x02, id, b.copyOf(n))) } ?: break
                }
                streams.remove(id)
                try { s.close() } catch (_: Exception) {}
                ws?.let { sendFrame(it, frame(0x03, id, ByteArray(0))) }
            }
        } catch (e: Exception) {
            ws?.let { sendFrame(it, frame(0x03, id, ByteArray(0))) }
        }
    }

    private fun frame(t: Int, id: Int, body: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(t)
        out.write(byteArrayOf(
            (id ushr 24).toByte(), (id ushr 16).toByte(), (id ushr 8).toByte(), id.toByte()))
        out.write(body)
        return out.toByteArray()
    }

    @Synchronized
    private fun sendFrame(w: WebSocket, plain: ByteArray) {
        val enc = Crypto.xorStream(plain, key)
        w.send(ByteString.of(*enc))
    }
}
