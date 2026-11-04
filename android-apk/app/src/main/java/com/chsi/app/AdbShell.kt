package com.chsi.app

import android.content.Context
import java.io.File

// 内置 adb（jniLibs/arm64-v8a/libadb.so，extractNativeLibs=true 后可执行）
class AdbShell(ctx: Context) {
    private val adb = File(ctx.applicationInfo.nativeLibraryDir, "libadb.so")

    fun run(timeoutMs: Long, vararg args: String): String {
        return try {
            val p = ProcessBuilder(listOf(adb.absolutePath) + args)
                .redirectErrorStream(true)
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

    fun findDevtoolsSockets(): List<String> {
        val out = run(8000, "shell", "cat", "/proc/net/unix")
        return out.lineSequence()
            .filter { it.contains("devtools_remote") }
            .mapNotNull { it.trim().split(Regex("\\s+")).lastOrNull() }
            .map { it.trimStart('@') }
            .distinct()
            .toList()
    }
}
