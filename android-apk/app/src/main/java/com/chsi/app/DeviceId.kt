package com.chsi.app

import android.content.Context
import android.os.Build
import android.provider.Settings
import java.security.MessageDigest

object DeviceId {
    fun fingerprint(ctx: Context): String {
        val parts = listOfNotNull(
            Settings.Secure.getString(ctx.contentResolver, Settings.Secure.ANDROID_ID),
            Build.FINGERPRINT,
            Build.BOARD, Build.BRAND, Build.DEVICE, Build.PRODUCT
        ).filter { it.isNotBlank() }
        val md = MessageDigest.getInstance("SHA-256")
        val h = md.digest(parts.joinToString("|").toByteArray())
        return h.joinToString("") { "%02X".format(it) }.take(16)
    }

    fun sha256Hex(b: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) }
}
