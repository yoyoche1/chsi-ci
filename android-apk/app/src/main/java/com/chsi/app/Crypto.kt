package com.chsi.app

import java.security.MessageDigest

object Crypto {
    // v1.13（L5）：密钥移入 libchsi.so——jadx 只见 external 声明，密钥分段 XOR 藏于 native。
    // APK 专用密钥，与 PC/iOS 的 TUNNEL_KEY 分离（服务端按 token 来源选择校验密钥）。

    fun tunnelSig(token: String, device: String): String = Native.tunnelSig(token, device)

    fun streamKey(token: String): ByteArray = Native.streamKey(token)

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
