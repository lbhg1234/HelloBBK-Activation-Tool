package com.hellobbk.activation

import java.security.KeyFactory
import java.security.PrivateKey
import java.security.MessageDigest
import java.security.spec.PKCS8EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec
import java.util.Base64

/**
 * PEM 私钥解析（纯 JDK，无 BouncyCastle；Android 与 JVM 行为一致）。
 *
 * 支持：
 *  - PKCS#8   "-----BEGIN PRIVATE KEY-----"
 *  - PKCS#1   "-----BEGIN RSA PRIVATE KEY-----"
 *  - 加密 PKCS#8 "-----BEGIN ENCRYPTED PRIVATE KEY-----"（PBES2 / PBKDF2 + AES/DESede），需密码
 *  - 传统加密 PEM（含 DEK-Info:），EVP_BytesToKey 多策略尝试，需密码
 */
object PemUtil {

    private val ALG_ID = byteArrayOf(
        0x30, 0x0d,
        0x06, 0x09, 0x2a, 0x86.toByte(), 0x48, 0x86.toByte(),
        0xf7.toByte(), 0x0d, 0x01, 0x01, 0x01,
        0x05, 0x00
    )
    private val VERSION_0 = byteArrayOf(0x02, 0x01, 0x00)

    /** 兼容旧调用：无密码。 */
    fun parsePrivateKey(pem: String?): PrivateKey = parsePrivateKey(pem, "")

    /**
     * @param pem   PEM 文本
     * @param pass  私钥密码（可选；加密私钥必填）
     */
    fun parsePrivateKey(pem: String?, pass: String): PrivateKey {
        require(!pem.isNullOrBlank()) { "私钥为空" }
        val kf = KeyFactory.getInstance("RSA")

        // 传统加密 PEM：Proc-Type / DEK-Info
        if (pem.contains("DEK-Info:")) {
            require(pass.isNotEmpty()) { "该私钥已加密，请填写私钥密码" }
            val der = decryptTraditional(pem, pass.toCharArray())
            return toPrivateKey(der, isPkcs1 = true, kf) // 传统加密解密后通常是 PKCS#1
        }

        val body = buildString {
            for (line in pem.lines()) {
                val t = line.trim()
                if (t.isEmpty() || t.contains("-----")) continue
                for (c in t) if (!c.isWhitespace()) append(c)
            }
        }
        val der = Base64.getDecoder().decode(body)
        require(der.isNotEmpty()) { "PEM 内容为空或格式错误" }

        // 加密 PKCS#8（PBES2）
        if (pem.contains("ENCRYPTED PRIVATE KEY")) {
            require(pass.isNotEmpty()) { "该私钥已加密，请填写私钥密码" }
            val plain = decryptPbes2(der, pass.toCharArray())
            return toPrivateKey(plain, isPkcs1 = false, kf)
        }

        // 明文：PKCS#1 或 PKCS#8（自动兜底）
        return if (pem.contains("BEGIN RSA PRIVATE KEY")) {
            toPrivateKey(der, isPkcs1 = true, kf)
        } else {
            try {
                kf.generatePrivate(PKCS8EncodedKeySpec(der))
            } catch (e: Exception) {
                toPrivateKey(der, isPkcs1 = true, kf)
            }
        }
    }

    private fun toPrivateKey(der: ByteArray, isPkcs1: Boolean, kf: KeyFactory): PrivateKey =
        if (isPkcs1) kf.generatePrivate(PKCS8EncodedKeySpec(wrapPkcs1(der)))
        else kf.generatePrivate(PKCS8EncodedKeySpec(der))

    // ---------------- ASN.1 DER 极简 TLV ----------------

    private class Tlv(val tag: Int, val value: ByteArray)

    private fun readLen(d: ByteArray, pos: IntArray): Int {
        var p = pos[0]
        val b = d[p++].toInt() and 0xff
        if (b < 0x80) { pos[0] = p; return b }
        val n = b and 0x7f
        var len = 0
        repeat(n) { len = (len shl 8) or (d[p++].toInt() and 0xff) }
        pos[0] = p
        return len
    }

    private fun readTlv(d: ByteArray, pos: IntArray): Tlv {
        val tag = d[pos[0]++].toInt() and 0xff
        val len = readLen(d, pos)
        require(pos[0] + len <= d.size) { "ASN.1 长度越界" }
        val v = d.copyOfRange(pos[0], pos[0] + len)
        pos[0] += len
        return Tlv(tag, v)
    }

    private fun sequence(d: ByteArray): List<Tlv> {
        val out = ArrayList<Tlv>()
        var p = 0
        while (p < d.size) {
            val cur = intArrayOf(p)
            val t = readTlv(d, cur)
            out.add(t)
            p = cur[0]
        }
        return out
    }

    private fun oid(v: ByteArray): String {
        if (v.isEmpty()) return ""
        val parts = ArrayList<Long>()
        val first = v[0].toInt() and 0xff
        var x = first / 40L
        var y = first % 40L
        if (x > 2) { x = 2; y = first - 80L }
        parts.add(x); parts.add(y)
        var acc = 0L
        for (i in 1 until v.size) {
            acc = (acc shl 7) or (v[i].toInt() and 0x7f).toLong()
            if ((v[i].toInt() and 0x80) == 0) { parts.add(acc); acc = 0 }
        }
        return parts.joinToString(".")
    }

    private fun parseInt(v: ByteArray): Int {
        var x = 0
        for (b in v) x = (x shl 8) or (b.toInt() and 0xff)
        return x
    }

    // ---------------- 加密 PKCS#8: PBES2 ----------------

    /** 解密 EncryptedPrivateKeyInfo（PBES2 + PBKDF2 + AES/DESede-CBC），返回 PKCS#8 DER。 */
    private fun decryptPbes2(der: ByteArray, pass: CharArray): ByteArray {
        val top = sequence(readTlv(der, intArrayOf(0)).value)
        val alg = sequence(top[0].value)          // AlgorithmIdentifier
        val encrypted = top[1].value              // OCTET STRING
        require(oid(alg[0].value) == "1.2.840.113549.1.5.13") { "仅支持 PBES2 加密私钥" }
        val params = sequence(alg[1].value)        // PBES2-params

        val kdf = sequence(params[0].value)
        require(oid(kdf[0].value) == "1.2.840.113549.1.5.12") { "仅支持 PBKDF2 密钥派生" }
        val pb = sequence(kdf[1].value)
        val salt = pb[0].value
        val iter = parseInt(pb[1].value)
        var keyLen = 0
        var prf = "HmacSHA1"
        for (i in 2 until pb.size) {
            val t = pb[i]
            if (t.tag == 0x02) keyLen = parseInt(t.value)
            else if (t.tag == 0x30) {
                val prfAlg = sequence(t.value)
                prf = when (oid(prfAlg[0].value)) {
                    "1.2.840.113549.2.9" -> "HmacSHA256"
                    "1.2.840.113549.2.10" -> "HmacSHA384"
                    "1.2.840.113549.2.11" -> "HmacSHA512"
                    "1.2.840.113549.2.8" -> "HmacSHA224"
                    else -> "HmacSHA1"
                }
            }
        }

        val enc = sequence(params[1].value)
        val encOid = oid(enc[0].value)
        val iv = enc[1].value
        val cipherName: String
        when (encOid) {
            "2.16.840.1.101.3.4.1.42" -> { cipherName = "AES"; if (keyLen <= 0) keyLen = 32 }
            "2.16.840.1.101.3.4.1.22" -> { cipherName = "AES"; if (keyLen <= 0) keyLen = 24 }
            "2.16.840.1.101.3.4.1.2" -> { cipherName = "AES"; if (keyLen <= 0) keyLen = 16 }
            "1.2.840.113549.3.7" -> { cipherName = "DESede"; keyLen = 24 }
            else -> throw IllegalArgumentException("不支持的加密算法 OID: $encOid")
        }
        if (keyLen <= 0) keyLen = 32

        val skf = SecretKeyFactory.getInstance("PBKDF2With$prf")
        val pbeKey = skf.generateSecret(PBEKeySpec(pass, salt, iter, keyLen * 8))
        val key = SecretKeySpec(pbeKey.encoded, cipherName)
        val c = Cipher.getInstance("$cipherName/CBC/PKCS5Padding")
        c.init(Cipher.DECRYPT_MODE, key, IvParameterSpec(iv))
        return c.doFinal(encrypted)
    }

    // ---------------- 传统加密 PEM: DEK-Info / EVP_BytesToKey ----------------

    private fun decryptTraditional(pem: String, pass: CharArray): ByteArray {
        var dek: String? = null
        for (line in pem.lines()) {
            if (line.contains("DEK-Info:")) dek = line.substringAfter("DEK-Info:").trim()
        }
        require(dek != null) { "传统加密私钥缺少 DEK-Info" }
        val parts = dek!!.split(",")
        val cipherDesc = parts[0].trim()
        val headerIv = hex(parts[1].trim())
        val data = pemBody(pem)

        val (cipherName, keyLen) = when (cipherDesc) {
            "AES-256-CBC" -> "AES" to 32
            "AES-192-CBC" -> "AES" to 24
            "AES-128-CBC" -> "AES" to 16
            "DES-EDE3-CBC" -> "DESede" to 24
            else -> throw IllegalArgumentException("不支持的传统加密: $cipherDesc")
        }

        // 多策略尝试：openssl 1.x 用 EVP_BytesToKey(MD5, salt=headerIv, iv=headerIv)；
        // 部分实现用 SHA1/SHA256 或 iv=派生后16字节。逐一尝试，取能通过 padding 的结果。
        val strategies = ArrayList<Pair<ByteArray, ByteArray>>()
        for (digest in arrayOf("MD5", "SHA1", "SHA256")) {
            val keymat = evpBytesToKey(pass, headerIv, keyLen + 16, digest)
            val k = keymat.copyOfRange(0, keyLen)
            strategies.add(k to headerIv)                       // iv = DEK 头
            strategies.add(k to keymat.copyOfRange(keyLen, keyLen + 16)) // iv = 派生后 16 字节
        }
        // 部分 openssl 3 传统格式用 PBKDF2
        for (digest in arrayOf("HmacSHA256", "HmacSHA1")) {
            for (iter in intArrayOf(2048, 10000, 1)) {
                try {
                    val skf = SecretKeyFactory.getInstance("PBKDF2With$digest")
                    val pk = skf.generateSecret(PBEKeySpec(pass, headerIv, iter, keyLen * 8))
                    strategies.add(pk.encoded to headerIv)
                } catch (_: Exception) { }
            }
        }

        var last: Exception? = null
        for ((k, iv) in strategies) {
            try {
                val c = Cipher.getInstance("$cipherName/CBC/PKCS5Padding")
                c.init(Cipher.DECRYPT_MODE, SecretKeySpec(k, cipherName), IvParameterSpec(iv))
                val out = c.doFinal(data)
                // 粗校验：明文应是合理长度的 DER（PKCS#1 私钥以 0x30 开头）
                if (out.isNotEmpty() && (out[0].toInt() and 0xff) == 0x30) return out
            } catch (e: Exception) { last = e }
        }
        throw IllegalArgumentException("私钥密码错误或格式不支持（${last?.javaClass?.simpleName ?: "无策略匹配"}）")
    }

    private fun evpBytesToKey(pass: CharArray, salt: ByteArray, need: Int, digest: String): ByteArray {
        val pw = ByteArray(pass.size) { pass[it].toByte() }
        val md = MessageDigest.getInstance(digest)
        val out = ArrayList<Byte>()
        var d = ByteArray(0)
        while (out.size < need) {
            md.reset()
            if (d.isNotEmpty()) md.update(d)
            md.update(pw)
            if (salt.isNotEmpty()) md.update(salt)
            d = md.digest()
            out.addAll(d.asIterable())
        }
        return out.take(need).toByteArray()
    }

    private fun pemBody(pem: String): ByteArray {
        val body = buildString {
            for (line in pem.lines()) {
                val t = line.trim()
                if (t.isEmpty() || t.contains("-----") || t.contains(":")) continue
                for (c in t) if (!c.isWhitespace()) append(c)
            }
        }
        return Base64.getDecoder().decode(body)
    }

    private fun hex(s: String): ByteArray {
        val out = ByteArray(s.length / 2)
        for (i in out.indices) {
            out[i] = ((Character.digit(s[i * 2], 16) shl 4) + Character.digit(s[i * 2 + 1], 16)).toByte()
        }
        return out
    }

    // ---------------- 工具 ----------------

    private fun wrapPkcs1(pkcs1: ByteArray): ByteArray {
        val octet = concat(byteArrayOf(0x04), derLength(pkcs1.size), pkcs1)
        val content = concat(VERSION_0, ALG_ID, octet)
        return concat(byteArrayOf(0x30), derLength(content.size), content)
    }

    private fun derLength(len: Int): ByteArray = when {
        len < 0x80 -> byteArrayOf(len.toByte())
        len <= 0xFF -> byteArrayOf(0x81.toByte(), len.toByte())
        else -> byteArrayOf(0x82.toByte(), (len shr 8).toByte(), len.toByte())
    }

    private fun concat(vararg parts: ByteArray): ByteArray {
        val total = parts.sumOf { it.size }
        val out = ByteArray(total)
        var off = 0
        for (p in parts) { System.arraycopy(p, 0, out, off, p.size); off += p.size }
        return out
    }
}
