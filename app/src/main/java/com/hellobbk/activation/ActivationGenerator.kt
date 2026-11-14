package com.hellobbk.activation

import java.nio.charset.StandardCharsets
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.interfaces.RSAPrivateCrtKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.RSAPublicKeySpec
import java.util.Base64

/**
 * 激活码生成 + 自检。与宿主 com.system.toolbox.core.Activation.verify() 严格对齐：
 *
 * ```
 * payload = [2B 大端 SN长度][SN UTF-8][8B 大端过期时间戳(秒)][RSA 签名]
 * 签名内容 = SN 的 UTF-8 字节 + 过期时间戳的 8 字节大端表示
 * 签名算法 = SHA256withRSA（签名长度随密钥模长：2048→256B，4096→512B）
 * 激活码   = Base64 URL_SAFE / NO_WRAP / NO_PADDING (payload)
 * 校验     = SN 一致 && 签名有效 && 当前秒 <= 过期秒
 * ```
 *
 * 本类仅使用 JDK 标准库（java.security / java.util.Base64），不依赖 Android API，
 * 因此既能在 App 内运行，也能直接在 JVM 里做「生成 → 宿主等价验签」回环验证。
 */
object ActivationGenerator {

    const val TIME_SIZE = 8

    enum class Verify { SUCCESS, EXPIRED, INVALID }

    /** 结果封装 */
    data class Result(
        val code: String,
        val payload: ByteArray,
        val snLen: Int,
        val expiresAtSec: Long,
        val signatureSize: Int,
        val selfCheck: Verify
    )

    /**
     * 生成激活码，并用「从私钥推导出的公钥」按宿主逻辑做一次本地自检。
     *
     * @param sn           设备序列号（UTF-8，长度 1..128）
     * @param privateKey   RSA 私钥（须与宿主在线公钥成对）
     * @param expiresAtSec 过期时间，Unix 秒
     */
    fun generate(sn: String, privateKey: PrivateKey, expiresAtSec: Long): Result {
        require(sn.isNotEmpty()) { "SN 不能为空" }
        val snBytes = sn.toByteArray(StandardCharsets.UTF_8)
        require(snBytes.size <= 128) { "SN 超过 128 字节（宿主限制）" }

        val timeBytes = longTo8BytesBE(expiresAtSec)

        val signer = Signature.getInstance("SHA256withRSA")
        signer.initSign(privateKey)
        signer.update(snBytes)
        // 宿主是逐字节 update(payload[timeOff + i]) 共 8 次；整体 update 等价。
        signer.update(timeBytes)
        val sig = signer.sign()

        val payload = ByteArray(2 + snBytes.size + TIME_SIZE + sig.size)
        payload[0] = ((snBytes.size shr 8) and 0xFF).toByte()
        payload[1] = (snBytes.size and 0xFF).toByte()
        System.arraycopy(snBytes, 0, payload, 2, snBytes.size)
        System.arraycopy(timeBytes, 0, payload, 2 + snBytes.size, TIME_SIZE)
        System.arraycopy(sig, 0, payload, 2 + snBytes.size + TIME_SIZE, sig.size)

        val code = Base64.getUrlEncoder().withoutPadding().encodeToString(payload)

        val pub = derivePublic(privateKey)
        val check = if (pub != null) {
            verify(code, sn, pub, System.currentTimeMillis() / 1000L)
        } else {
            Verify.INVALID
        }
        // 签名长度就是本次签名字节数，等价于公钥模长/8。
        return Result(code, payload, snBytes.size, expiresAtSec, sig.size, check)
    }

    /** 从 CRT 私钥推导公钥（用于自检，无需用户额外提供公钥）。 */
    fun derivePublic(privateKey: PrivateKey): PublicKey? = try {
        val crt = privateKey as RSAPrivateCrtKey
        KeyFactory.getInstance("RSA").generatePublic(
            RSAPublicKeySpec(crt.modulus, crt.publicExponent)
        )
    } catch (e: Exception) {
        null
    }

    /**
     * 宿主 verify() 的等价复刻（Base64 用 java.util.Base64 URL decoder，与
     * android.util.Base64 URL_SAFE|NO_WRAP|NO_PADDING 解码结果一致）。
     * 供自检与 JVM 回环测试使用。
     */
    fun verify(code: String, sn: String, pub: PublicKey, nowSec: Long): Verify = try {
        val sigSize = (((pub as RSAPublicKey).modulus.bitLength()) + 7) / 8
        val payload = Base64.getUrlDecoder().decode(code.trim())
        if (payload.size < 2 + TIME_SIZE + sigSize) {
            Verify.INVALID
        } else {
            val snLen = ((payload[0].toInt() and 0xFF) shl 8) or (payload[1].toInt() and 0xFF)
            if (snLen <= 0 || snLen > 128 || payload.size != 2 + snLen + TIME_SIZE + sigSize) {
                Verify.INVALID
            } else {
                val snInCode = String(payload, 2, snLen, StandardCharsets.UTF_8)
                val timeOff = 2 + snLen
                val expire = bytes8ToLongBE(payload, timeOff)
                val sig = payload.copyOfRange(timeOff + TIME_SIZE, payload.size)

                if (snInCode != sn) {
                    Verify.INVALID
                } else {
                    val verifier = Signature.getInstance("SHA256withRSA")
                    verifier.initVerify(pub)
                    verifier.update(sn.toByteArray(StandardCharsets.UTF_8))
                    for (i in 0 until TIME_SIZE) verifier.update(payload[timeOff + i])
                    when {
                        !verifier.verify(sig) -> Verify.INVALID
                        nowSec > expire -> Verify.EXPIRED
                        else -> Verify.SUCCESS
                    }
                }
            }
        }
    } catch (e: Exception) {
        Verify.INVALID
    }

    fun longTo8BytesBE(v: Long): ByteArray {
        val b = ByteArray(TIME_SIZE)
        for (i in 0 until TIME_SIZE) b[i] = (v ushr (56 - 8 * i)).toByte()
        return b
    }

    fun bytes8ToLongBE(b: ByteArray, off: Int): Long {
        var v = 0L
        for (i in 0 until TIME_SIZE) v = (v shl 8) or (b[off + i].toLong() and 0xFF)
        return v
    }
}
