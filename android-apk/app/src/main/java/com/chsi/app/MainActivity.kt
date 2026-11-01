package com.chsi.app

import android.app.Activity
import android.content.Intent
import android.graphics.Color
import android.os.Bundle
import android.text.InputType
import android.view.Gravity
import android.widget.*
import androidx.core.view.setPadding

class MainActivity : Activity() {
    private lateinit var edCode: EditText
    private lateinit var edName: EditText
    private lateinit var spGender: Spinner
    private lateinit var edPhoto: EditText
    private lateinit var edPairPort: EditText
    private lateinit var edPairCode: EditText
    private lateinit var edConnectPort: EditText
    private lateinit var tvStatus: TextView
    private lateinit var tvLog: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        title = "高校认证 v1.0"

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(24)
        }

        fun label(t: String) = TextView(this).apply { text = t; textSize = 12f; setTextColor(Color.GRAY) }
        fun edit(hint: String, num: Boolean = false, text: String = "") = EditText(this).apply {
            this.hint = hint
            if (num) inputType = InputType.TYPE_CLASS_NUMBER
            setText(text)
        }

        root.addView(label("授权码"))
        edCode = edit("CHSI-XXXX-XXXX-XXXX", text = pref("code"))
        root.addView(edCode)

        root.addView(label("姓名"))
        edName = edit("姓名", text = pref("name"))
        root.addView(edName)

        root.addView(label("性别"))
        spGender = Spinner(this).apply {
            adapter = ArrayAdapter(this@MainActivity, android.R.layout.simple_spinner_dropdown_item, listOf("男", "女"))
            setSelection(if (pref("gender") == "女") 1 else 0)
        }
        root.addView(spGender)

        root.addView(label("照片（data:image/jpeg;base64,...，可留空）"))
        edPhoto = edit("照片 base64", text = pref("photo"))
        edPhoto.minLines = 2
        root.addView(edPhoto)

        val row = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        edPairPort = edit("配对端口", num = true, text = pref("pp")).apply { layoutParams = LinearLayout.LayoutParams(0, -2, 1f) }
        edPairCode = edit("配对码(6位)").apply { layoutParams = LinearLayout.LayoutParams(0, -2, 1f) }
        row.addView(edPairPort); row.addView(edPairCode)
        root.addView(label("无线调试配对（首次需填，配对后可清空）"))
        root.addView(row)

        root.addView(label("无线调试连接端口（无线调试页显示的 IP:端口 里的端口）"))
        edConnectPort = edit("连接端口", num = true, text = pref("cp"))
        root.addView(edConnectPort)

        val rowBtn = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER }
        val btnStart = Button(this).apply { text = "启动" }
        val btnStop = Button(this).apply { text = "停止" }
        rowBtn.addView(btnStart); rowBtn.addView(btnStop)
        root.addView(rowBtn)

        tvStatus = TextView(this).apply { textSize = 14f; setTextColor(Color.parseColor("#1565C0")); text = TunnelService.status }
        root.addView(tvStatus)

        tvLog = TextView(this).apply { textSize = 11f; text = TunnelService.logBuf.toString() }
        val sv = ScrollView(this).apply { addView(tvLog) }
        root.addView(sv, LinearLayout.LayoutParams(-1, 0, 1f))

        setContentView(root)

        btnStart.setOnClickListener {
            savePrefs()
            val i = Intent(this, TunnelService::class.java).apply {
                putExtra(TunnelService.EXTRA_CODE, edCode.text.toString().trim())
                putExtra(TunnelService.EXTRA_NAME, edName.text.toString().trim())
                putExtra(TunnelService.EXTRA_GENDER, spGender.selectedItem.toString())
                putExtra(TunnelService.EXTRA_PHOTO, edPhoto.text.toString().trim())
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
            .putString("gender", spGender.selectedItem.toString())
            .putString("photo", edPhoto.text.toString().trim())
            .putString("pp", edPairPort.text.toString())
            .putString("cp", edConnectPort.text.toString())
            .apply()
    }
}
