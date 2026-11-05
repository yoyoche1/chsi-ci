package com.chsi.app

import android.content.Context
import java.io.File

// 内置 adb（jniLibs/arm64-v8a/libadb.so，extractNativeLibs=true 后可执行）
// v1.6 关键修复：adb 进程 HOME 默认落在 /data（不可写）→
//   `Cannot mkdir '/data/.android': Permission denied` → daemon 起不来 →
//   pair/connect/devices/forward 全部失败。
// 把 HOME/TMPDIR 显式指到 app cache（可写），adb 密钥与日志都落在那里。
class AdbShell(ctx: Context) {
    private val adb = File(ctx.applicationInfo.nativeLibraryDir, "libadb.so")
    private val home = ctx.cacheDir.absolutePath

    fun run(timeoutMs: Long, vararg args: String): String {
        return try {
            val p = ProcessBuilder(listOf(adb.absolutePath) + args)
                .redirectErrorStream(true)
                .apply {
                    environment()["HOME"] = home
                    environment()["TMPDIR"] = home
                }
                .start()
            val out = p.inputStream.readBytes()
            p.waitFor(timeoutMs, java.util.concurrent.TimeUnit.MILLISECONDS)
            if (p.isAlive) { p.destroy(); "" } else String(out)
        } catch (e: Exception) { "" }
    }

    fun pair(port: Int, code: String) = run(20000, "pair", "127.0.0.1:$port", code)
    fun connect(port: Int) = run(15000, "connect", "127.0.0.1:$port")
    // v4.9.13：mDNS 自动发现的 host:port 直连
    fun pairHost(host: String, port: Int, code: String) = run(20000, "pair", "$host:$port", code)
    fun connectHost(host: String, port: Int) = run(15000, "connect", "$host:$port")
    fun devices() = run(8000, "devices")
    fun forward(local: Int, sock: String) = run(8000, "forward", "tcp:$local", "localabstract:$sock")
    fun killServer() = run(3000, "kill-server")
    fun startServer() = run(3000, "start-server")

    // v1.8：放宽匹配——任何含 "devtools" 的 socket（QQ 可能走 XWeb 内核，
    // 名字未必是标准 devtools_remote）
    fun findDevtoolsSockets(): List<String> {
        val out = run(8000, "shell", "cat", "/proc/net/unix")
        return out.lineSequence()
            .filter { it.contains("devtools", true) }
            .mapNotNull { it.trim().split(Regex("\\s+")).lastOrNull() }
            .map { it.trimStart('@') }
            .filter { it.isNotBlank() }
            .distinct()
            .toList()
    }

    // v1.7：诊断用——找不到 devtools 口时，把疑似 QQ/TBS 的 unix socket 候选打出来
    fun listSocketCandidates(): List<String> {
        val out = run(8000, "shell", "cat", "/proc/net/unix")
        return out.lineSequence()
            .map { it.trim().split(Regex("\\s+")).lastOrNull() ?: "" }
            .filter {
                it.contains("qq", true) || it.contains("tencent", true) ||
                it.contains("x5", true) || it.contains("webview", true) ||
                it.contains("devtools", true) || it.contains("inspect", true)
            }
            .distinct()
            .take(20)
            .toList()
    }
}
