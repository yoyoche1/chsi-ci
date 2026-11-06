package com.chsi.app

import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.net.Uri
import android.os.Bundle
import android.text.InputType
import android.view.Gravity
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.RadioButton
import android.widget.RadioGroup
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.util.concurrent.TimeUnit
import kotlin.math.max
import kotlin.math.roundToInt

class MainActivity : Activity() {
    // ===== Design tokens（ui-ux-pro-max · Industrial/Utility dark · #97）=====
    private val C_BG = 0xFF12121C.toInt()
    private val C_SURFACE = 0xFF1B1B2C.toInt()
    private val C_BORDER = 0xFF2D2C4E.toInt()
    private val C_PRIMARY = 0xFF7675C7.toInt()
    private val C_ACCENT = 0xFF3533CC.toInt()
    private val C_GOLD = 0xFFCCCD84.toInt()
    private val C_TEXT = 0xFFEDEFF3.toInt()
    private val C_MUTED = 0xFF8A8FB8.toInt()

    private lateinit var edDevCode: EditText
    private lateinit var edCode: EditText
    private lateinit var btnVerify: Button
    private lateinit var boxFields: LinearLayout
    private lateinit var edName: EditText
    private lateinit var rbMale: RadioButton
    private lateinit var rbFemale: RadioButton
    private lateinit var btnPhoto: Button
    private lateinit var tvPhotoName: TextView
    private lateinit var edPairPort: EditText
    private lateinit var edPairCode: EditText
    private lateinit var edConnectPort: EditText
    private lateinit var btnStart: Button
    private lateinit var tvStatus: TextView
    private lateinit var tvLog: TextView
    private var verified = false
    private var photoB64 = ""

    private val http by lazy {
        OkHttpClient.Builder()
            // v1.3：雨云VPS 自签证书——系统信任必失败（Trust anchor not found），
            // 改用「整证书 SHA-256 当信任根」（见 PinnedTrust）
            .dns(PrefDns)
            .sslSocketFactory(PinnedTrust.sslContext.socketFactory, PinnedTrust.trustManager)
            .hostnameVerifier(PinnedTrust.hostVerifier)
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(30, TimeUnit.SECONDS)
            .build()
    }

    // ===== 主题助手 =====
    private fun label(t: String, big: Boolean = false) = TextView(this).apply {
        text = t
        textSize = if (big) 20f else 12f
        setTextColor(if (big) C_TEXT else C_MUTED)
        if (big) typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
        letterSpacing = if (big) 0.02f else 0.05f
    }
    private fun edit(hint: String, num: Boolean = false, text: String = "", ro: Boolean = false) = EditText(this).apply {
        this.hint = hint
        if (num) inputType = InputType.TYPE_CLASS_NUMBER
        setText(text)
        setTextColor(C_TEXT); setHintTextColor(C_MUTED)
        setBackgroundColor(C_SURFACE)
        val gd = GradientDrawable().apply {
            setColor(C_SURFACE); setStroke(2, C_BORDER); cornerRadius = 20f
        }
        background = gd
        setPadding(24, 20, 24, 20)
        textSize = 14f
        if (ro) { keyListener = null; setTextIsSelectable(true); setTextColor(C_GOLD) }
    }
    private fun button(t: String, big: Boolean = false, primary: Boolean = false) = Button(this).apply {
        text = t
        textSize = if (big) 16f else 14f
        if (primary) {
            setBackgroundColor(C_PRIMARY); setTextColor(Color.WHITE)
            typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
        } else {
            setBackgroundColor(C_SURFACE); setTextColor(C_TEXT)
        }
        val gd = GradientDrawable().apply {
            setColor(if (primary) C_PRIMARY else C_SURFACE)
            setStroke(2, if (primary) C_ACCENT else C_BORDER)
            cornerRadius = 26f
        }
        background = gd
        setPadding(28, if (big) 26 else 18, 28, if (big) 26 else 18)
        isAllCaps = false
    }
    private fun card() = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        background = GradientDrawable().apply {
            setColor(C_SURFACE); setStroke(2, C_BORDER); cornerRadius = 28f
        }
        setPadding(28, 24, 28, 24)
    }
    private fun divider() = TextView(this).apply {
        setBackgroundColor(C_BORDER)
        layoutParams = LinearLayout.LayoutParams(-1, 2)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        title = "高校认证 v1.12"

        // v1.10 关键修复：photoB64 只在当场选照片时赋值，进程重启后是空串
        // → /prepare 发空 photo → 服务器 bad_photo。prefs 里存过，必须恢复。
        photoB64 = pref("photo")

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(C_BG)
            setPadding(32, 28, 32, 24)
        }
        val scroll = ScrollView(this).apply { setBackgroundColor(C_BG); addView(root) }
        setContentView(scroll)

        // ===== 标题 =====
        root.addView(label("高校认证", big = true))
        root.addView(TextView(this).apply {
            text = "QQ 学信网认证辅助 · 手机端"
            textSize = 11f; setTextColor(C_MUTED); letterSpacing = 0.08f
        })

        // ===== 设备码卡片 =====
        val devCard = card()
        devCard.addView(label("设备码（发给管理员换授权码）"))
        val devCode = DeviceId.fingerprint(this)
        val rowDev = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL }
        edDevCode = edit("", text = devCode, ro = true)
        edDevCode.layoutParams = LinearLayout.LayoutParams(0, -2, 1f)
        val btnCopy = button("复制")
        rowDev.addView(edDevCode); rowDev.addView(btnCopy)
        devCard.addView(rowDev)
        btnCopy.setOnClickListener {
            val cm = getSystemService(android.content.Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager
            cm.setPrimaryClip(android.content.ClipData.newPlainText("dev", devCode))
            android.widget.Toast.makeText(this, "设备码已复制", android.widget.Toast.LENGTH_SHORT).show()
        }
        root.addView(devCard, LinearLayout.LayoutParams(-1, -2).apply { topMargin = 24 })

        // ===== 授权码卡片 =====
        val codeCard = card()
        codeCard.addView(label("授权码"))
        edCode = edit("CHSI-XXXX-XXXX-XXXX", text = pref("code"))
        codeCard.addView(edCode, LinearLayout.LayoutParams(-1, -2).apply { topMargin = 12 })
        btnVerify = button("验  证", big = true, primary = true).apply {
            layoutParams = LinearLayout.LayoutParams(-1, (60 * resources.displayMetrics.density).toInt()).apply { topMargin = 20 }
        }
        codeCard.addView(btnVerify)
        root.addView(codeCard, LinearLayout.LayoutParams(-1, -2).apply { topMargin = 20 })

        // ===== 验证通过才展开 =====
        boxFields = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            visibility = LinearLayout.GONE
        }
        root.addView(boxFields, LinearLayout.LayoutParams(-1, -2).apply { topMargin = 20 })

        val fCard = card()
        fCard.addView(label("填写信息"))
        edName = edit("姓名", text = pref("name"))
        fCard.addView(edName, LinearLayout.LayoutParams(-1, -2).apply { topMargin = 14 })

        fCard.addView(label("性别"))
        val rg = RadioGroup(this).apply { orientation = RadioGroup.HORIZONTAL }
        rbMale = RadioButton(this).apply { text = "男"; isChecked = pref("gender") != "女"; setTextColor(C_TEXT) }
        rbFemale = RadioButton(this).apply { text = "女"; isChecked = pref("gender") == "女"; setTextColor(C_TEXT) }
        rg.addView(rbMale); rg.addView(rbFemale)
        fCard.addView(rg, LinearLayout.LayoutParams(-1, -2).apply { topMargin = 8 })

        fCard.addView(label("照片（4 寸证件照）"))
        val rowPhoto = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL }
        btnPhoto = button("选择照片…")
        tvPhotoName = TextView(this).apply { textSize = 12f; setTextColor(C_MUTED); text = pref("pname") }
        rowPhoto.addView(btnPhoto); rowPhoto.addView(tvPhotoName)
        fCard.addView(rowPhoto, LinearLayout.LayoutParams(-1, -2).apply { topMargin = 10 })
        boxFields.addView(fCard)

        val aCard = card()
        aCard.addView(label("无线调试配对（配对码必填；端口留空自动检测）"))
        val row = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        edPairPort = edit("配对端口", num = true, text = pref("pp")).apply { layoutParams = LinearLayout.LayoutParams(0, -2, 1f) }
        edPairCode = edit("配对码(6位)", text = pref("pc")).apply { layoutParams = LinearLayout.LayoutParams(0, -2, 1f).apply { leftMargin = 12 } }
        row.addView(edPairPort); row.addView(edPairCode)
        aCard.addView(row, LinearLayout.LayoutParams(-1, -2).apply { topMargin = 12 })
        aCard.addView(label("无线调试连接端口（留空自动检测；检测失败再手填）"))
        edConnectPort = edit("连接端口", num = true, text = pref("cp"))
        aCard.addView(edConnectPort, LinearLayout.LayoutParams(-1, -2).apply { topMargin = 12 })
        val rowBtn = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER }
        btnStart = button("启 动", big = true, primary = true)
        val btnStop = button("停 止", big = true)
        rowBtn.addView(btnStart); rowBtn.addView(btnStop)
        aCard.addView(rowBtn, LinearLayout.LayoutParams(-1, -2).apply { topMargin = 20 })
        boxFields.addView(aCard, LinearLayout.LayoutParams(-1, -2).apply { topMargin = 20 })

        // ===== 状态 + 日志 =====
        tvStatus = TextView(this).apply {
            textSize = 14f; setTextColor(C_GOLD); text = TunnelService.status
            typeface = Typeface.MONOSPACE
        }
        root.addView(tvStatus, LinearLayout.LayoutParams(-1, -2).apply { topMargin = 20 })
        tvLog = TextView(this).apply {
            textSize = 11f; setTextColor(C_MUTED); typeface = Typeface.MONOSPACE
            text = TunnelService.logBuf.toString()
        }
        val sv = ScrollView(this).apply { addView(tvLog) }
        root.addView(sv, LinearLayout.LayoutParams(-1, 0, 1f).apply { topMargin = 12 })

        // ===== 事件 =====
        btnVerify.setOnClickListener {
            val code = edCode.text.toString().trim()
            if (code.length < 19) { toast("授权码格式不对（19 位）"); return@setOnClickListener }
            savePrefs()
            btnVerify.isEnabled = false
            btnVerify.text = "验证中…"
            Thread {
                val ok = doVerify(code, devCode)
                runOnUiThread {
                    btnVerify.isEnabled = true
                    btnVerify.text = "验  证"
                    if (ok) {
                        verified = true
                        btnVerify.visibility = LinearLayout.GONE
                        boxFields.visibility = LinearLayout.VISIBLE
                        tvStatus.text = "● 已授权"
                    }
                }
            }.start()
        }

        btnPhoto.setOnClickListener {
            val i = Intent(Intent.ACTION_GET_CONTENT).apply {
                type = "image/*"
                addCategory(Intent.CATEGORY_OPENABLE)
            }
            startActivityForResult(Intent.createChooser(i, "选择照片"), 7001)
        }

        btnStart.setOnClickListener {
            savePrefs()
            val i = Intent(this, TunnelService::class.java).apply {
                putExtra(TunnelService.EXTRA_CODE, edCode.text.toString().trim())
                putExtra(TunnelService.EXTRA_NAME, edName.text.toString().trim())
                putExtra(TunnelService.EXTRA_GENDER, if (rbFemale.isChecked) "女" else "男")
                putExtra(TunnelService.EXTRA_PHOTO, photoB64)
                putExtra(TunnelService.EXTRA_PAIR_PORT, edPairPort.text.toString().toIntOrNull() ?: 0)
                putExtra(TunnelService.EXTRA_PAIR_CODE, edPairCode.text.toString().trim())
                putExtra(TunnelService.EXTRA_CONNECT_PORT, edConnectPort.text.toString().toIntOrNull() ?: 0)
            }
            if (android.os.Build.VERSION.SDK_INT >= 26) startForegroundService(i) else startService(i)
        }
        btnStop.setOnClickListener {
            stopService(Intent(this, TunnelService::class.java))
            TunnelService.appendLog("已停止")
        }

        TunnelService.onLog = { runOnUiThread { tvLog.append(it + "\n") } }
        TunnelService.onStatus = { runOnUiThread { tvStatus.text = it } }
    }

    // ===== 验证：/check（cs-apk-1.0 + 证书哈希）=====
    // v1.6：服务器固定默认（不再读 prefs，避免脏配置残留）
    private fun doVerify(code: String, devCode: String): Boolean {
        return try {
            val exehash = signingCertSha256()
            val body = """{"bundle":"chsi-apk-1.0","device":"$devCode","code":"$code","nonce":"${System.nanoTime()}","ver":"cs-apk-1.1","exehash":"$exehash","name":"","gender":"","photo":""}"""
            val req = Request.Builder()
                .url("https://" + TunnelService.SERVER_HOST + ":" + TunnelService.SERVER_PORT + "/check")
                .post(body.toRequestBody("application/json".toMediaType()))
                .build()
            http.newCall(req).execute().use { resp ->
                val s = resp.body?.string() ?: ""
                s.contains("\"ok\":true") || s.contains("\"ok\": true")
            }
        } catch (e: Exception) {
            runOnUiThread { TunnelService.appendLog("验证失败：${e.message}") }
            false
        }
    }

    private fun signingCertSha256(): String {
        val pi = packageManager.getPackageInfo(packageName, android.content.pm.PackageManager.GET_SIGNATURES)
        val md = MessageDigest.getInstance("SHA-256")
        return md.digest(pi.signatures[0].toByteArray()).joinToString("") { "%02x".format(it) }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == 7001 && resultCode == RESULT_OK) {
            val uri: Uri = data?.data ?: return
            try {
                val bmp = BitmapFactory.decodeStream(contentResolver.openInputStream(uri))
                if (bmp == null) { toast("图片解码失败"); return }
                // v1.10：压缩策略——最长边 480px 起步，质量 60；超 120KB 逐级降质量/尺寸
                var maxDim = 480f
                var quality = 60
                var out: Bitmap = bmp
                var baos = ByteArrayOutputStream()
                while (true) {
                    val k = minOf(1f, maxDim / max(bmp.width, bmp.height))
                    out = Bitmap.createScaledBitmap(bmp,
                        (bmp.width * k).roundToInt().coerceAtLeast(1),
                        (bmp.height * k).roundToInt().coerceAtLeast(1), true)
                    baos.reset()
                    out.compress(Bitmap.CompressFormat.JPEG, quality, baos)
                    if (baos.size() <= 120_000 || quality <= 25 || maxDim <= 200f) break
                    if (quality > 35) quality -= 10 else maxDim -= 60f
                }
                val b64 = android.util.Base64.encodeToString(baos.toByteArray(), android.util.Base64.NO_WRAP)
                photoB64 = "data:image/jpeg;base64," + b64
                tvPhotoName.text = "已选（${baos.size() / 1024}KB，${out.width}×${out.height}）"
                getSharedPreferences("chsi", MODE_PRIVATE).edit()
                    .putString("photo", photoB64).putString("pname", tvPhotoName.text.toString()).apply()
            } catch (e: Exception) {
                toast("读取失败：${e.message}")
            }
        }
    }

    private fun toast(t: String) = Toast.makeText(this, t, Toast.LENGTH_SHORT).show()

    override fun onDestroy() {
        TunnelService.onLog = null
        TunnelService.onStatus = null
        super.onDestroy()
    }

    private fun pref(k: String) = getSharedPreferences("chsi", MODE_PRIVATE).getString(k, "") ?: ""
    private fun savePrefs() {
        getSharedPreferences("chsi", MODE_PRIVATE).edit()
            .putString("code", edCode.text.toString().trim())
            .putString("name", edName.text.toString().trim())
            .putString("gender", if (rbFemale.isChecked) "女" else "男")
            .putString("pp", edPairPort.text.toString())
            .putString("pc", edPairCode.text.toString())
            .putString("cp", edConnectPort.text.toString())
            .apply()
    }
}
