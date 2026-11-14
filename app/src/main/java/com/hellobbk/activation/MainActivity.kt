package com.hellobbk.activation

import android.app.Activity
import android.app.DatePickerDialog
import android.app.TimePickerDialog
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.text.method.ScrollingMovementMethod
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import java.nio.charset.StandardCharsets
import java.security.interfaces.RSAPrivateKey
import java.text.SimpleDateFormat
import java.util.Calendar
import java.util.Date
import java.util.Locale
import kotlin.concurrent.thread

/** 激活码生成工具主界面（纯 Android framework View，无 AndroidX / Compose 依赖）。 */
class MainActivity : Activity() {

    companion object {
        private const val PREFS = "activation_tool"
        private const val K_SN = "sn"
        private const val K_KEY = "key"
        private const val K_EXP = "exp"
        private const val REQ_OPEN_KEY = 1001
        private const val LONG_TERM_SEC = 4102444800L // 2100-01-01 00:00:00 UTC
    }

    private lateinit var etSn: EditText
    private lateinit var etKey: EditText
    private lateinit var etResult: EditText
    private lateinit var tvExpire: TextView
    private lateinit var tvStatus: TextView
    private var expiresAtSec: Long = 0L

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        etSn = findViewById(R.id.etSn)
        etKey = findViewById(R.id.etKey)
        etResult = findViewById(R.id.etResult)
        tvExpire = findViewById(R.id.tvExpire)
        tvStatus = findViewById(R.id.tvStatus)
        etKey.movementMethod = ScrollingMovementMethod()
        etResult.movementMethod = ScrollingMovementMethod()

        val prefs = getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        etSn.setText(prefs.getString(K_SN, ""))
        etKey.setText(prefs.getString(K_KEY, ""))
        val saved = prefs.getLong(K_EXP, 0L)
        expiresAtSec = if (saved > 0) saved else plusDays(365)
        updateExpireLabel()

        findViewById<android.view.View>(R.id.btnLoadKey).setOnClickListener { openKeyFile() }
        findViewById<android.view.View>(R.id.btnPickTime).setOnClickListener { pickDateTime() }
        findViewById<android.view.View>(R.id.btnD30).setOnClickListener { setQuick(plusDays(30)) }
        findViewById<android.view.View>(R.id.btnD90).setOnClickListener { setQuick(plusDays(90)) }
        findViewById<android.view.View>(R.id.btnD365).setOnClickListener { setQuick(plusDays(365)) }
        findViewById<android.view.View>(R.id.btnLong).setOnClickListener { setQuick(LONG_TERM_SEC) }
        findViewById<android.view.View>(R.id.btnGenerate).setOnClickListener { doGenerate() }
        findViewById<android.view.View>(R.id.btnCopy).setOnClickListener { doCopy() }
    }

    private fun plusDays(days: Int): Long =
        System.currentTimeMillis() / 1000L + days.toLong() * 86400L

    private fun setQuick(sec: Long) {
        expiresAtSec = sec
        updateExpireLabel()
    }

    private fun updateExpireLabel() {
        val fmt = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault())
            .format(Date(expiresAtSec * 1000L))
        tvExpire.text = "到期：$fmt  (epoch 秒 $expiresAtSec)"
    }

    private fun pickDateTime() {
        val c = Calendar.getInstance().apply { timeInMillis = expiresAtSec * 1000L }
        DatePickerDialog(
            this,
            { _, y, m, d ->
                TimePickerDialog(
                    this,
                    { _, hh, mm ->
                        val cal = Calendar.getInstance().apply {
                            set(y, m, d, hh, mm, 0)
                            set(Calendar.MILLISECOND, 0)
                        }
                        expiresAtSec = cal.timeInMillis / 1000L
                        updateExpireLabel()
                    },
                    c.get(Calendar.HOUR_OF_DAY), c.get(Calendar.MINUTE), true
                ).show()
            },
            c.get(Calendar.YEAR), c.get(Calendar.MONTH), c.get(Calendar.DAY_OF_MONTH)
        ).show()
    }

    private fun openKeyFile() {
        val i = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "*/*"
        }
        @Suppress("DEPRECATION")
        startActivityForResult(i, REQ_OPEN_KEY)
    }

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        @Suppress("DEPRECATION")
        super.onActivityResult(requestCode, resultCode, data)
        val uri = data?.data
        if (requestCode == REQ_OPEN_KEY && resultCode == RESULT_OK && uri != null) {
            try {
                contentResolver.openInputStream(uri)?.use { input ->
                    val sb = StringBuilder()
                    val chunk = ByteArray(4096)
                    var n: Int
                    while (input.read(chunk).also { n = it } > 0) {
                        sb.append(String(chunk, 0, n, StandardCharsets.UTF_8))
                    }
                    etKey.setText(sb.toString())
                    Toast.makeText(this, "已载入私钥文件", Toast.LENGTH_SHORT).show()
                } ?: throw Exception("无法打开")
            } catch (e: Exception) {
                Toast.makeText(this, "读取私钥文件失败：${e.message}", Toast.LENGTH_LONG).show()
            }
        }
    }

    private fun doGenerate() {
        val sn = etSn.text.toString().trim()
        val pem = etKey.text.toString()
        val exp = expiresAtSec

        if (sn.isEmpty()) { fail("请先填写设备序列号 SN"); return }
        if (pem.isBlank()) { fail("请先粘贴或选择 RSA 私钥 PEM"); return }

        getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putString(K_SN, sn).putString(K_KEY, pem).putLong(K_EXP, exp).apply()
        tvStatus.setTextColor(getColor(R.color.text_secondary))
        tvStatus.text = "正在签名…"

        thread(name = "gen-activation") {
            // 用 try/catch 表达式一次性求出三元组，避免 val 跨分支赋值。
            val (out, status, ok) = try {
                val key = PemUtil.parsePrivateKey(pem)
                val r = ActivationGenerator.generate(sn, key, exp)
                val bits = (key as RSAPrivateKey).modulus.bitLength()
                if (r.selfCheck == ActivationGenerator.Verify.SUCCESS) {
                    Triple(
                        r.code,
                        "✓ 生成成功并自检通过：RSA-$bits，签名 ${r.signatureSize}" +
                                " 字节，SN 长度 ${r.snLen}，过期秒 ${r.expiresAtSec}，" +
                                "激活码 ${r.code.length} 字符。",
                        true
                    )
                } else {
                    Triple(
                        "",
                        "✗ 自检未通过（${r.selfCheck}）：私钥结构异常或签名算法不匹配。",
                        false
                    )
                }
            } catch (e: Exception) {
                Triple(
                    "",
                    "✗ 生成失败：${e.javaClass.simpleName} - ${e.message}" +
                            "（请确认私钥为 RSA PEM、未加密、且与公钥配对）",
                    false
                )
            }
            runOnUiThread {
                etResult.setText(out)
                tvStatus.text = status
                tvStatus.setTextColor(
                    getColor(if (ok) R.color.accent else android.R.color.holo_red_dark)
                )
            }
        }
    }

    private fun fail(msg: String) {
        tvStatus.text = "✗ $msg"
        tvStatus.setTextColor(getColor(android.R.color.holo_red_dark))
    }

    private fun doCopy() {
        val code = etResult.text.toString().trim()
        if (code.isEmpty()) {
            Toast.makeText(this, "还没有激活码", Toast.LENGTH_SHORT).show(); return
        }
        val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        cm.setPrimaryClip(ClipData.newPlainText("activation_code", code))
        Toast.makeText(this, "已复制激活码", Toast.LENGTH_SHORT).show()
    }
}
