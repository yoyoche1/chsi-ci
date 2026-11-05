package com.chsi.app

import android.util.Base64
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLHandshakeException
import javax.net.ssl.X509TrustManager

// v1.3：服务器（雨云VPS）= 自签证书（CN=chsi）。
// OkHttp 的 CertificatePinner 只是「在系统信任之上追加校验」，不能替代信任根：
// Android 系统信任库里没有这张自签 CA，握手在 pin 检查之前就报
// CertPathValidatorException: Trust anchor for certification path not found。
//
// 因此用「整证书 SHA-256 当信任根」：只认出示与内置 pin 一致的自签证书，
// pin 对上 = 连的就是那台服务器（身份校验内置），自签证书 CN 与域名不一致，
// 所以 hostname 一并放行（安全性由整证书 pin 保证）。
object PinnedTrust {
    // openssl x509 -inform DER -outform DER | openssl dgst -sha256 -binary | base64
    private const val PIN_B64 = "hLQOuOytSGSsh+z8/6NQFhRMdLqNStzZyt8zTXtVeRw="
    private val EXPECTED: ByteArray = Base64.decode(PIN_B64, Base64.NO_WRAP)

    val trustManager: X509TrustManager = object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<X509Certificate>?, authType: String?) {
            throw SSLHandshakeException("客户端不需要被信任")
        }

        override fun checkServerTrusted(chain: Array<X509Certificate>?, authType: String?) {
            val leaf = chain?.firstOrNull() ?: throw SSLHandshakeException("空证书链")
            val sha = MessageDigest.getInstance("SHA-256").digest(leaf.encoded)
            if (!sha.contentEquals(EXPECTED)) {
                throw SSLHandshakeException("服务器证书与内置 pin 不符")
            }
        }

        override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
    }

    val sslContext: SSLContext = SSLContext.getInstance("TLS").apply {
        init(null, arrayOf(trustManager), SecureRandom())
    }

    // 证书已按整证书哈希钉死，域名不校验
    val hostVerifier = HostnameVerifier { _, _ -> true }
}
