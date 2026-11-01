package com.chsi.app

import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Color
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
            .certificatePinner(okhttp3.CertificatePinner.Builder()
                .add(TunnelService.SERVER_HOST, TunnelService.SPKI_PIN).build())
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(30, TimeUnit.SECONDS)
            .build()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        title = "高校认证 v1.0"

        fun label(t: String, big: Boolean = false) = TextView(this).apply {
            text = t
            textSize = if (big) 15f else 12f
            setTextColor(if (big) Color.BLACK else Color.GRAY)
        }
        fun edit(hint: String, num: Boolean = false, text: String = "") = EditText(this).apply {
            this.hint = hint
            if (num) inputType = InputType.TYPE_CLASS_NUMBER
            setText(text)
        }
        fun button(t: String, big: Boolean = false) = Button(this).apply {
            text = t
            if (big) textSize = 15f
        }

        // ===== 主容器 =====
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(28, 20, 28, 20)
        }
        val scroll = ScrollView(this).apply { addView(root) }
        setContentView(scroll)

        // ===== 标题（对齐 exe）=====
        root.addView(label("高校认证", big = true))
        root.addView(TextView(this).apply {
            text = "QQ 学信网认证辅助 · 手机端"
            textSize = 11f; setTextColor(Color.GRAY)
        })

        // ===== 设备码（只读 + 复制）=====
        root.addView(label("设备码（发给管理员换授权码）"))
        val devCode = DeviceId.fingerprint(this)
        val rowDev = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        edDevCode = edit("", text = devCode).apply { keyListener = null; setTextIsSelectable(true) }
        edDevCode.layoutParams = LinearLayout.LayoutParams(0, -2, 1f)
        val btnCopy = button("复制")
        rowDev.addView(edDevCode); rowDev.addView(btnCopy)
        root.addView(rowDev)
        btnCopy.setOnClickListener {
            val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            cm.setPrimaryClip(ClipData.newPlainText("devcode", devCode))
            Toast.makeText(this, "已复制设备码", Toast.LENGTH_SHORT).show()
        }
        root.addView(divider())

        // ===== 授权码 =====
        root.addView(label("授权码"))
        edCode = edit("CHSI-XXXX-XXXX-XXXX", text = pref("code"))
        root.addView(edCode)

        btnVerify = button("验  证", big = true).apply {
            layoutParams = LinearLayout.LayoutParams(-1, (56 * resources.displayMetrics.density).toInt())
        }
        root.addView(btnVerify)

        // ===== 验证通过才展开的区域 =====
        boxFields = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            visibility = LinearLayout.GONE
        }
        root.addView(boxFields)

        boxFields.addView(label("姓名"))
        edName = edit("姓名", text = pref("name"))
        boxFields.addView(edName)

        boxFields.addView(label("性别"))
        val rg = RadioGroup(this).apply { orientation = RadioGroup.HORIZONTAL }
        rbMale = RadioButton(this).apply { text = "男"; isChecked = pref("gender") != "女" }
        rbFemale = RadioButton(this).apply { text = "女"; isChecked = pref("gender") == "女" }
        rg.addView(rbMale); rg.addView(rbFemale)
        boxFields.addView(rg)

        boxFields.addView(label("照片（4 寸证件照）"))
        val rowPhoto = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL }
        btnPhoto = button("选择照片…")
        tvPhotoName = TextView(this).apply { textSize = 12f; setTextColor(Color.GRAY); text = pref("pname") }
        rowPhoto.addView(btnPhoto)
        rowPhoto.addView(tvPhotoName)
        boxFields.addView(rowPhoto)

        val row = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        edPairPort = edit("配对端口", num = true, text = pref("pp")).apply { layoutParams = LinearLayout.LayoutParams(0, -2, 1f) }
        edPairCode = edit("配对码(6位)", text = pref("pc")).apply { layoutParams = LinearLayout.LayoutParams(0, -2, 1f) }
        row.addView(edPairPort); row.addView(edPairCode)
        boxFields.addView(label("无线调试配对（首次需填，配对后可清空）"))
        boxFields.addView(row)

        boxFields.addView(label("无线调试连接端口（无线调试页显示的 IP:端口 里的端口）"))
        edConnectPort = edit("连接端口", num = true, text = pref("cp"))
        boxFields.addView(edConnectPort)

        val rowBtn = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER }
        btnStart = button("启动")
        val btnStop = button("停止")
        rowBtn.addView(btnStart); rowBtn.addView(btnStop)
        boxFields.addView(rowBtn)

        // ===== 状态 + 日志 =====
        tvStatus = TextView(this).apply { textSize = 14f; setTextColor(Color.parseColor("#1565C0")); text = TunnelService.status }
        root.addView(tvStatus)
        tvLog = TextView(this).apply { textSize = 11f; text = TunnelService.logBuf.toString() }
        val sv = ScrollView(this).apply { addView(tvLog) }
        root.addView(sv, LinearLayout.LayoutParams(-1, 0, 1f))

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
    private fun doVerify(code: String, devCode: String): Boolean {
        return try {
            val exehash = signingCertSha256()
            val body = """{"bundle":"chsi-apk-1.0","device":"$devCode","code":"$code","nonce":"${System.nanoTime()}","ver":"cs-apk-1.0","exehash":"$exehash","name":"","gender":"","photo":""}"""
            val req = Request.Builder()
                .url(TunnelService.SERVER_CHECK)
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
                val maxDim = 160f
                val k = minOf(1f, maxDim / max(bmp.width, bmp.height))
                val out = Bitmap.createScaledBitmap(bmp,
                    (bmp.width * k).roundToInt().coerceAtLeast(1),
                    (bmp.height * k).roundToInt().coerceAtLeast(1), true)
                val baos = ByteArrayOutputStream()
                out.compress(Bitmap.CompressFormat.JPEG, 50, baos)
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

    private fun divider() = TextView(this).apply {
        setBackgroundColor(Color.parseColor("#DDDDDD"))
        layoutParams = LinearLayout.LayoutParams(-1, 2)
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
