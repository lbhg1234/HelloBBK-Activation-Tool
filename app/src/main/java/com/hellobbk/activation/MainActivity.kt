package com.hellobbk.activation

import android.app.DatePickerDialog
import android.app.TimePickerDialog
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.text.method.ScrollingMovementMethod
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.chip.Chip
import org.json.JSONArray
import org.json.JSONObject
import java.nio.charset.StandardCharsets
import java.security.interfaces.RSAPrivateKey
import java.text.SimpleDateFormat
import java.util.Calendar
import java.util.Date
import java.util.Locale
import kotlin.concurrent.thread

/** 激活码生成工具主界面（Material 3 / AppCompat）。 */
class MainActivity : AppCompatActivity() {

    companion object {
        private const val PREFS = "activation_tool"
        private const val K_SN = "sn"
        private const val K_KEY = "key"
        private const val K_EXP = "exp"
        private const val K_KEYSTORE = "keystore"      // JSON 数组：名称/私钥/密码
        private const val REQ_OPEN_KEY = 1001
        private const val LONG_TERM_SEC = 4102444800L // 2100-01-01 00:00:00 UTC
    }

    /** 一条保存的私钥记忆 */
    private data class KeyEntry(val name: String, val pem: String, val pass: String)

    private val etSn by lazy { findViewById<com.google.android.material.textfield.TextInputEditText>(R.id.etSn) }
    private val etKey by lazy { findViewById<com.google.android.material.textfield.TextInputEditText>(R.id.etKey) }
    private val etKeyName by lazy { findViewById<com.google.android.material.textfield.TextInputEditText>(R.id.etKeyName) }
    private val etKeyPass by lazy { findViewById<com.google.android.material.textfield.TextInputEditText>(R.id.etKeyPass) }
    private val etResult by lazy { findViewById<com.google.android.material.textfield.TextInputEditText>(R.id.etResult) }
    private val tvExpire by lazy { findViewById<android.widget.TextView>(R.id.tvExpire) }
    private val tvStatus by lazy { findViewById<android.widget.TextView>(R.id.tvStatus) }
    private val chipKeyStore by lazy { findViewById<com.google.android.material.chip.ChipGroup>(R.id.chipKeyStore) }

    private var expiresAtSec: Long = 0L
    private var entries: MutableList<KeyEntry> = mutableListOf()
    private var loadingChips = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        etKey.movementMethod = ScrollingMovementMethod()
        etResult.movementMethod = ScrollingMovementMethod()

        val prefs = getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        etSn.setText(prefs.getString(K_SN, ""))
        etKey.setText(prefs.getString(K_KEY, ""))

        // 到期基准：优先用已保存值；否则默认"当前时间 + 30 天"
        val saved = prefs.getLong(K_EXP, 0L)
        expiresAtSec = if (saved > 0) saved else nowSec() + 30L * 86400L
        updateExpireLabel()

        // 载入私钥记忆
        loadEntries()
        renderChips()

        findViewById<android.view.View>(R.id.btnLoadKey).setOnClickListener { openKeyFile() }
        findViewById<android.view.View>(R.id.btnNow).setOnClickListener { setQuick(nowSec()) }
        findViewById<android.view.View>(R.id.btnPickTime).setOnClickListener { pickDateTime() }
        findViewById<android.view.View>(R.id.btnD2).setOnClickListener { addDays(2) }
        findViewById<android.view.View>(R.id.btnD5).setOnClickListener { addDays(5) }
        findViewById<android.view.View>(R.id.btnD15).setOnClickListener { addDays(15) }
        findViewById<android.view.View>(R.id.btnD30).setOnClickListener { addDays(30) }
        findViewById<android.view.View>(R.id.btnLong).setOnClickListener { setQuick(LONG_TERM_SEC) }
        findViewById<android.view.View>(R.id.btnGenerate).setOnClickListener { doGenerate() }
        findViewById<android.view.View>(R.id.btnCopy).setOnClickListener { doCopy() }
        findViewById<android.view.View>(R.id.btnSaveKey).setOnClickListener { saveCurrentKey() }
        findViewById<android.view.View>(R.id.btnDeleteKey).setOnClickListener { deleteSelectedKey() }
    }

    private fun nowSec(): Long = System.currentTimeMillis() / 1000L

    /** 一键累加：在当前到期基准上增加 N 天（而非覆盖）。 */
    private fun addDays(days: Int) {
        expiresAtSec += days.toLong() * 86400L
        updateExpireLabel()
    }

    /** 覆盖式设置基准（获取当前时间 / 长期 / 手动选择）。 */
    private fun setQuick(sec: Long) {
        expiresAtSec = sec
        updateExpireLabel()
    }

    private fun updateExpireLabel() {
        val fmt = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault())
            .format(Date(expiresAtSec * 1000L))
        val rel = when {
            expiresAtSec > nowSec() -> "距今 ${(expiresAtSec - nowSec()) / 86400L} 天"
            else -> "已过期"
        }
        tvExpire.text = "$fmt  ·  epoch $expiresAtSec  ·  $rel"
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
                        setQuick(cal.timeInMillis / 1000L)
                    },
                    c.get(Calendar.HOUR_OF_DAY), c.get(Calendar.MINUTE), true
                ).show()
            },
            c.get(Calendar.YEAR), c.get(Calendar.MONTH), c.get(Calendar.DAY_OF_MONTH)
        ).show()
    }

    // ---------- 私钥记忆 ----------

    private fun loadEntries() {
        val raw = getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getString(K_KEYSTORE, "") ?: ""
        entries.clear()
        if (raw.isBlank()) return
        try {
            val arr = JSONArray(raw)
            for (i in 0 until arr.length()) {
                val o = arr.getJSONObject(i)
                entries.add(
                    KeyEntry(
                        o.optString("name", ""),
                        o.optString("pem", ""),
                        o.optString("pass", "")
                    )
                )
            }
        } catch (_: Exception) { }
    }

    private fun persistEntries() {
        val arr = JSONArray()
        for (e in entries) {
            val o = JSONObject()
            o.put("name", e.name); o.put("pem", e.pem); o.put("pass", e.pass)
            arr.put(o)
        }
        getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putString(K_KEYSTORE, arr.toString()).apply()
    }

    private fun renderChips(selectedName: String? = null) {
        loadingChips = true
        chipKeyStore.removeAllViews()
        if (entries.isEmpty()) {
            val chip = Chip(this).apply {
                text = getString(R.string.keystore_empty)
                isCheckable = false
                isCloseIconVisible = false
                alpha = 0.7f
            }
            chipKeyStore.addView(chip)
        } else {
            for (e in entries) {
                val chip = Chip(this).apply {
                    text = e.name
                    isCheckable = true
                    isCloseIconVisible = false
                    setChipIconResource(R.drawable.ic_key_24)
                    setOnClickListener { loadKeyEntry(e) }
                }
                chipKeyStore.addView(chip)
            }
            if (selectedName != null) {
                for (i in 0 until chipKeyStore.childCount) {
                    val chip = chipKeyStore.getChildAt(i) as? Chip ?: continue
                    if (chip.text == selectedName) {
                        chipKeyStore.check(chip.id)
                        break
                    }
                }
            }
        }
        loadingChips = false
    }

    private fun loadKeyEntry(e: KeyEntry) {
        if (loadingChips) return
        etKey.setText(e.pem)
        etKeyName.setText(e.name)
        etKeyPass.setText(e.pass)
        toast("已载入「${e.name}」")
    }

    private fun saveCurrentKey() {
        val pem = etKey.text?.toString() ?: ""
        if (pem.isBlank()) { fail("请先粘贴或载入私钥，再保存"); return }
        var name = etKeyName.text?.toString()?.trim() ?: ""
        if (name.isBlank()) name = "私钥${entries.size + 1}"
        val pass = etKeyPass.text?.toString() ?: ""

        val idx = entries.indexOfFirst { it.name == name }
        val entry = KeyEntry(name, pem, pass)
        if (idx >= 0) entries[idx] = entry else entries.add(entry)
        persistEntries()
        etKeyName.setText(name)
        renderChips(name)
        toast("已保存${if (idx >= 0) "更新" else ""}「$name」")
    }

    private fun deleteSelectedKey() {
        val checkedId = chipKeyStore.checkedChipId
        if (checkedId == android.view.View.NO_ID) { toast("请先点选要删除的私钥"); return }
        val chip = chipKeyStore.findViewById<Chip>(checkedId) ?: return
        val name = chip.text?.toString() ?: return
        val before = entries.size
        entries.removeAll { it.name == name }
        if (entries.size == before) { toast("未找到对应记录"); return }
        persistEntries()
        renderChips()
        toast("已删除「$name」")
    }

    // ---------- 私钥文件 ----------

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
                    toast("已载入私钥文件")
                } ?: throw Exception("无法打开")
            } catch (e: Exception) {
                toast("读取私钥文件失败：${e.message}")
            }
        }
    }

    // ---------- 生成 ----------

    private fun doGenerate() {
        val sn = etSn.text?.toString()?.trim() ?: ""
        val pem = etKey.text?.toString() ?: ""
        val pass = etKeyPass.text?.toString() ?: ""
        val exp = expiresAtSec

        if (sn.isEmpty()) { fail("请先填写设备序列号 SN"); return }
        if (pem.isBlank()) { fail("请先粘贴或选择 RSA 私钥 PEM"); return }

        getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putString(K_SN, sn).putString(K_KEY, pem).putLong(K_EXP, exp).apply()
        tvStatus.setTextColor(getColor(R.color.md_on_surface_variant))
        tvStatus.text = "正在签名…"

        thread(name = "gen-activation") {
            val (out, status, ok) = try {
                val key = PemUtil.parsePrivateKey(pem, pass)
                val r = ActivationGenerator.generate(sn, key, exp)
                val bits = (key as RSAPrivateKey).modulus.bitLength()
                if (r.selfCheck == ActivationGenerator.Verify.SUCCESS) {
                    Triple(
                        r.code,
                        "✓ 生成成功并自检通过：RSA-$bits，签名 ${r.signatureSize} 字节，SN ${r.snLen}，" +
                            "过期秒 ${r.expiresAtSec}，激活码 ${r.code.length} 字符。",
                        true
                    )
                } else {
                    val reason = when (r.selfCheck) {
                        ActivationGenerator.Verify.EXPIRED ->
                            "到期时间早于当前时间，请把到期时间调到未来。"
                        else ->
                            "无法从这份私钥推导出配对公钥完成回验，通常私钥不完整或不是标准 RSA 私钥。" +
                                "加密私钥请确认密码正确；或改用「从文件选择」载入完整 .pem。"
                    }
                    Triple("", "✗ 自检未通过（${r.selfCheck}）：$reason", false)
                }
            } catch (e: Exception) {
                Triple(
                    "",
                    "✗ 生成失败：${e.javaClass.simpleName} - ${e.message}" +
                        "（请确认私钥为 RSA PEM，加密私钥需填写正确密码，且与宿主公钥配对）",
                    false
                )
            }
            runOnUiThread {
                etResult.setText(out)
                tvStatus.text = status
                tvStatus.setTextColor(getColor(if (ok) R.color.md_primary else R.color.md_error))
            }
        }
    }

    private fun fail(msg: String) {
        tvStatus.text = "✗ $msg"
        tvStatus.setTextColor(getColor(R.color.md_error))
    }

    private fun doCopy() {
        val code = etResult.text?.toString()?.trim() ?: ""
        if (code.isEmpty()) { toast("还没有激活码"); return }
        val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        cm.setPrimaryClip(ClipData.newPlainText("activation_code", code))
        toast("已复制激活码")
    }

    private fun toast(msg: String) = Toast.makeText(this, msg, Toast.LENGTH_SHORT).show()
}
