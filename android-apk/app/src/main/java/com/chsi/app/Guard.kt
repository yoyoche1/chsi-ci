package com.chsi.app

import java.io.File

// 防护探测（与 exe 的 Frida 探测同思路）：命中不崩溃，走 deg=1 → 云端静默毒化
// v1.13（L6/L7）：签名期望值与深度探测移入 libchsi.so
object Guard {
    fun hasTracer(): Boolean {
        return try {
            File("/proc/self/status").readLines().any {
                it.startsWith("TracerPid:") && it.trim().endsWith("0").not()
            }
        } catch (e: Exception) { false }
    }

    fun hasInjection(): Boolean {
        return try {
            val m = File("/proc/self/maps").readText()
            listOf("frida", "gum-js-loop", "gum-js", "Xposed", "LSPosed", "substrate", "edxposed")
                .any { m.contains(it, ignoreCase = true) }
        } catch (e: Exception) { false }
    }

    // v1.13（L7）：JNI 层深度探测（TracerPid/Frida 端口/maps 特征/进程停止态）
    fun nativeCompromised(): Boolean = try { Native.isCompromised() } catch (e: Throwable) { true }

    // APK 签名自校验：与构建证书不符 → 被重打包 → 静默毒化
    // v1.13（L6）：期望值改由 Native.expectedSig() 提供（XOR 混淆藏在 native），
    // jadx 里再也看不到期望哈希。keystore 已提交 CI 仓库，证书哈希跨构建稳定。
    fun sigOk(ctx: android.content.Context): Boolean {
        return try {
            val md = java.security.MessageDigest.getInstance("SHA-256")
            val info = if (android.os.Build.VERSION.SDK_INT >= 28)
                ctx.packageManager.getPackageInfo(ctx.packageName,
                    android.content.pm.PackageManager.GET_SIGNING_CERTIFICATES)
            else
                @Suppress("DEPRECATION") ctx.packageManager.getPackageInfo(ctx.packageName,
                    android.content.pm.PackageManager.GET_SIGNATURES)
            val sigs: List<android.content.pm.Signature>? = if (android.os.Build.VERSION.SDK_INT >= 28)
                info.signingInfo?.apkContentsSigners?.toList()
            else
                @Suppress("DEPRECATION") info.signatures?.toList()
            val first = sigs?.firstOrNull() ?: return false
            val h = md.digest(first.toByteArray()).joinToString("") { "%02x".format(it) }
            h.equals(Native.expectedSig(), ignoreCase = true)
        } catch (e: Exception) { false }
    }
}
