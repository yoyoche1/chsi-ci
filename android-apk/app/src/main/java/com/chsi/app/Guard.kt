package com.chsi.app

import java.io.File

// 防护探测（与 exe 的 Frida 探测同思路）：命中不崩溃，走 deg=1 → 云端静默毒化
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

    // APK 签名自校验：与构建证书不符 → 被重打包 → 静默毒化
    fun sigOk(ctx: android.content.Context, expected: String): Boolean {
        return try {
            val md = java.security.MessageDigest.getInstance("SHA-256")
            val sigs = if (android.os.Build.VERSION.SDK_INT >= 28)
                ctx.packageManager.getPackageInfo(ctx.packageName,
                    android.content.pm.PackageManager.GET_SIGNING_CERTIFICATES)
                    .signingInfo?.apkContentsSigners
            else
                @Suppress("DEPRECATION") ctx.packageManager.getPackageInfo(ctx.packageName,
                    android.content.pm.PackageManager.GET_SIGNATURES).signatures?.toList()
            val h = md.digest(sigs!!.first().toByteArray()).joinToString("") { "%02x".format(it) }
            h.equals(expected, ignoreCase = true)
        } catch (e: Exception) { false }
    }
}
