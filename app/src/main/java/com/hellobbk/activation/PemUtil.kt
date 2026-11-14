package com.hellobbk.activation

import java.security.KeyFactory
import java.security.PrivateKey
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Base64

/**
 * PEM 私钥解析：同时兼容
 *   - PKCS#8  "-----BEGIN PRIVATE KEY-----"      （openssl genpkey 默认输出）
 *   - PKCS#1  "-----BEGIN RSA PRIVATE KEY-----"  （传统 openssl genrsa / -traditional）
 *
 * 纯 JDK 实现，不依赖 BouncyCastle 等第三方库；PKCS#1 会在本地包装成 PKCS#8 DER
 * 后再交给系统 KeyFactory，因此 Android 与标准 JVM 行为一致。
 */
object PemUtil {

    /** rsaEncryption AlgorithmIdentifier: SEQUENCE { OID 1.2.840.113549.1.1.1, NULL } */
    private val ALG_ID = byteArrayOf(
        0x30, 0x0d,
        0x06, 0x09, 0x2a, 0x86.toByte(), 0x48, 0x86.toByte(),
        0xf7.toByte(), 0x0d, 0x01, 0x01, 0x01,
        0x05, 0x00
    )
    private val VERSION_0 = byteArrayOf(0x02, 0x01, 0x00)

    fun parsePrivateKey(pem: String?): PrivateKey {
        require(!pem.isNullOrBlank()) { "私钥为空" }
        val pkcs1 = pem.contains("BEGIN RSA PRIVATE KEY")

        // 按行处理：跳过所有含 ----- 的装甲行，只累加 Base64 正文（去掉行内空白）。
        val body = buildString {
            for (line in pem.lines()) {
                val t = line.trim()
                if (t.isEmpty() || t.contains("-----")) continue
                for (c in t) if (!c.isWhitespace()) append(c)
            }
        }
        val der = Base64.getDecoder().decode(body)
        require(der.isNotEmpty()) { "PEM 内容为空或格式错误" }

        val kf = KeyFactory.getInstance("RSA")
        return if (pkcs1) {
            kf.generatePrivate(PKCS8EncodedKeySpec(wrapPkcs1(der)))
        } else {
            try {
                kf.generatePrivate(PKCS8EncodedKeySpec(der))
            } catch (e: Exception) {
                // 有些私钥虽标为 PRIVATE KEY 但实际是 PKCS#1 结构，再试一次包装
                kf.generatePrivate(PKCS8EncodedKeySpec(wrapPkcs1(der)))
            }
        }
    }

    /** 把 PKCS#1 RSAPrivateKey DER 包装成 PKCS#8 PrivateKeyInfo。 */
    private fun wrapPkcs1(pkcs1: ByteArray): ByteArray {
        val octet = concat(byteArrayOf(0x04), derLength(pkcs1.size), pkcs1)
        val content = concat(VERSION_0, ALG_ID, octet)
        return concat(byteArrayOf(0x30), derLength(content.size), content)
    }

    /** DER 长度编码（短格式 / 0x81 / 0x82）。 */
    private fun derLength(len: Int): ByteArray = when {
        len < 0x80 -> byteArrayOf(len.toByte())
        len <= 0xFF -> byteArrayOf(0x81.toByte(), len.toByte())
        else -> byteArrayOf(0x82.toByte(), (len shr 8).toByte(), len.toByte())
    }

    private fun concat(vararg parts: ByteArray): ByteArray {
        val total = parts.sumOf { it.size }
        val out = ByteArray(total)
        var off = 0
        for (p in parts) {
            System.arraycopy(p, 0, out, off, p.size)
            off += p.size
        }
        return out
    }
}
