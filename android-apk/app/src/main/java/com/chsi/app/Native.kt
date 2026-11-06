package com.chsi.app

// L5/L6/L7：实现全部在 libchsi.so（app/src/main/cpp/chsi.c）。
// jadx 只能看到 external 声明——密钥与签名期望值都藏在 native。
object Native {
    init { System.loadLibrary("chsi") }

    /** HMAC-SHA256(隧道密钥, "token|device") hex[:32]——隧道握手签名 */
    external fun tunnelSig(token: String, device: String): String

    /** SHA256(隧道密钥|token) 32 字节——隧道流 XOR 密钥 */
    external fun streamKey(token: String): ByteArray

    /** 签名证书 SHA-256 期望值（重打包检测） */
    external fun expectedSig(): String

    /** 反调试 / 反 Frida / 反注入框架 */
    external fun isCompromised(): Boolean
}
