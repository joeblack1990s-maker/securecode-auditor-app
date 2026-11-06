package com.joeblack.secureaudit

import android.os.Bundle
import android.text.Html
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import org.json.JSONArray
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

class CloudActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_cloud)

        val configEditText = findViewById<EditText>(R.id.configEditText)
        val scanButton = findViewById<Button>(R.id.scanCloudButton)
        val resultText = findViewById<TextView>(R.id.resultText)

        scanButton.setOnClickListener {
            val config = configEditText.text.toString()
            Thread {
                try {
                    val url = URL("http://127.0.0.1:5000/scan_cloud")
                    val conn = url.openConnection() as HttpURLConnection
                    conn.requestMethod = "POST"
                    conn.setRequestProperty("Content-Type", "application/json")
                    conn.setRequestProperty("Authorization", "Bearer super-secret-auditor-key-123")
                    conn.doOutput = true
                    val body = JSONObject().put("config", config).toString()
                    conn.outputStream.use { it.write(body.toByteArray()) }

                    val response = conn.inputStream.bufferedReader().readText()
                    val arr = JSONArray(response)
                    val sb = StringBuilder()
                    for (i in 0 until arr.length()) {
                        val obj = arr.getJSONObject(i)
                        sb.append(obj.optString("code")).append("<br><br>")
                    }
                    val html = if (sb.isEmpty()) "No misconfigurations found." else sb.toString()
                    runOnUiThread {
                        resultText.text = Html.fromHtml(html, Html.FROM_HTML_MODE_LEGACY)
                    }
                } catch (e: Exception) {
                    runOnUiThread {
                        resultText.text = "Error: ${e.message}"
                    }
                }
            }.start()
        }
    }
}
