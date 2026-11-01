package com.chsi.app

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import java.security.MessageDigest

object Crypto {
    // 与服务器 / PC 端完全一致（TUNNEL_KEY 泄则隧道签名失守——v1 与 PC 同 key，后续可换）
    private const val TUNNEL_KEY = "7f3a91c25be04d68a1c9f2e8b6d47053"

    fun tunnelSig(token: String, device: String): String {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(TUNNEL_KEY.toByteArray(), "HmacSHA256"))
        val out = mac.doFinal("$token|$device".toByteArray())
        return out.joinToString("") { "%02x".format(it) }.take(32)
    }

    fun streamKey(token: String): ByteArray {
        val md = MessageDigest.getInstance("SHA-256")
        return md.digest("$TUNNEL_KEY|$token".toByteArray())
    }

    // 与服务器 xorStream 同算法：SHA256(key || counter_BE) 分块 XOR
    fun xorStream(buf: ByteArray, key: ByteArray): ByteArray {
        val out = ByteArray(buf.size)
        var counter = 0
        var off = 0
        val md = MessageDigest.getInstance("SHA-256")
        while (off < buf.size) {
            md.reset()
            md.update(key)
            md.update(byteArrayOf(
                (counter ushr 24).toByte(), (counter ushr 16).toByte(),
                (counter ushr 8).toByte(), counter.toByte()))
            val ks = md.digest()
            var i = 0
            while (i < 32 && off + i < buf.size) { out[off + i] = (buf[off + i].toInt() xor ks[i].toInt()).toByte(); i++ }
            counter++
            off += 32
        }
        return out
    }
}
