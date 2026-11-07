package com.joeblack.secureaudit

import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.ProgressBar
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.text.HtmlCompat
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

class ReconActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        supportActionBar?.hide()
        setContentView(R.layout.activity_recon)

        val urlInput = findViewById<EditText>(R.id.urlInput)
        val runButton = findViewById<Button>(R.id.runButton)
        val progressBar = findViewById<ProgressBar>(R.id.progressBar)
        val reportText = findViewById<TextView>(R.id.reportText)

        runButton.setOnClickListener {
            val url = urlInput.text.toString().trim()
            reportText.text = ""
            progressBar.visibility = android.view.View.VISIBLE
            runButton.isEnabled = false

            Thread {
                try {
                    val conn = URL("http://127.0.0.1:5000/api/recon").openConnection() as HttpURLConnection
                    conn.requestMethod = "POST"
                    conn.setRequestProperty("Authorization", "Bearer super-secret-auditor-key-123")
                    conn.setRequestProperty("Content-Type", "application/json")
                    conn.doOutput = true
                    conn.connectTimeout = 30000
                    conn.readTimeout = 200000
                    val body = org.json.JSONObject().put("url", url).toString()
                    conn.outputStream.use { it.write(body.toByteArray()) }

                    val code = conn.responseCode
                    val responseText = (if (code in 200..299) conn.inputStream else conn.errorStream)?.bufferedReader()?.readText().orEmpty()
                    conn.disconnect()

                    val report = try {
                        org.json.JSONObject(responseText).optString("report", responseText)
                    } catch (e: Exception) {
                        responseText
                    }

                    runOnUiThread {
                        reportText.text = report
                        progressBar.visibility = android.view.View.GONE
                        runButton.isEnabled = true
                    }
                } catch (e: Exception) {
                    runOnUiThread {
                        reportText.text = "Error: ${e.message}"
                        progressBar.visibility = android.view.View.GONE
                        runButton.isEnabled = true
                    }
                }
            }.start()
        }
    }
}
EOF
echo done