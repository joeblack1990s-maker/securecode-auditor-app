package com.joeblack.secureaudit

import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.ProgressBar
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import org.json.JSONArray
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

class ReconActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        supportActionBar?.hide()
        setContentView(R.layout.activity_recon)

        val urlInput = findViewById<EditText>(R.id.urlInput)
        val domainInput = findViewById<EditText>(R.id.domainInput)
        val runButton = findViewById<Button>(R.id.runButton)
        val fuzzButton = findViewById<Button>(R.id.fuzzButton)
        val paramButton = findViewById<Button>(R.id.paramButton)
        val subdomainButton = findViewById<Button>(R.id.subdomainButton)
        val progressBar = findViewById<ProgressBar>(R.id.progressBar)
        val reportText = findViewById<TextView>(R.id.reportText)

        fun setEnabled(enabled: Boolean) {
            runButton.isEnabled = enabled
            fuzzButton.isEnabled = enabled
            paramButton.isEnabled = enabled
            subdomainButton.isEnabled = enabled
        }

        fun runScan(endpoint: String) {
            val url = urlInput.text.toString().trim()
            reportText.text = ""
            progressBar.visibility = android.view.View.VISIBLE
            setEnabled(false)

            Thread {
                try {
                    val conn = URL("http://127.0.0.1:5000$endpoint").openConnection() as HttpURLConnection
                    conn.requestMethod = "POST"
                    conn.setRequestProperty("Authorization", "Bearer super-secret-auditor-key-123")
                    conn.setRequestProperty("Content-Type", "application/json")
                    conn.doOutput = true
                    conn.connectTimeout = 30000
                    conn.readTimeout = 200000
                    val body = JSONObject().put("url", url).toString()
                    conn.outputStream.use { it.write(body.toByteArray()) }

                    val code = conn.responseCode
                    val responseText = (if (code in 200..299) conn.inputStream else conn.errorStream)?.bufferedReader()?.readText().orEmpty()
                    conn.disconnect()

                    val display = try {
                        val json = JSONObject(responseText)
                        if (json.has("report")) json.optString("report") else responseText
                    } catch (e: Exception) {
                        responseText
                    }

                    runOnUiThread {
                        reportText.text = display
                        progressBar.visibility = android.view.View.GONE
                        setEnabled(true)
                    }
                } catch (e: Exception) {
                    runOnUiThread {
                        reportText.text = "Error: ${e.message}"
                        progressBar.visibility = android.view.View.GONE
                        setEnabled(true)
                    }
                }
            }.start()
        }

        fun runSubdomains() {
            val domain = domainInput.text.toString().trim()
            reportText.text = ""
            progressBar.visibility = android.view.View.VISIBLE
            setEnabled(false)

            Thread {
                try {
                    val conn = URL("http://127.0.0.1:5000/api/subdomains").openConnection() as HttpURLConnection
                    conn.requestMethod = "POST"
                    conn.setRequestProperty("Authorization", "Bearer super-secret-auditor-key-123")
                    conn.setRequestProperty("Content-Type", "application/json")
                    conn.doOutput = true
                    conn.connectTimeout = 30000
                    conn.readTimeout = 60000
                    val body = JSONObject().put("domain", domain).toString()
                    conn.outputStream.use { it.write(body.toByteArray()) }

                    val code = conn.responseCode
                    val responseText = (if (code in 200..299) conn.inputStream else conn.errorStream)?.bufferedReader()?.readText().orEmpty()
                    conn.disconnect()

                    val display = try {
                        val arr = JSONArray(responseText)
                        val sb = StringBuilder()
                        for (i in 0 until arr.length()) {
                            sb.append(arr.getString(i)).append("\n")
                        }
                        if (sb.isEmpty()) "No subdomains found." else sb.toString()
                    } catch (e: Exception) {
                        responseText
                    }

                    runOnUiThread {
                        reportText.text = display
                        progressBar.visibility = android.view.View.GONE
                        setEnabled(true)
                    }
                } catch (e: Exception) {
                    runOnUiThread {
                        reportText.text = "Error: ${e.message}"
                        progressBar.visibility = android.view.View.GONE
                        setEnabled(true)
                    }
                }
            }.start()
        }

        runButton.setOnClickListener { runScan("/api/recon") }
        fuzzButton.setOnClickListener { runScan("/api/fuzz") }
        paramButton.setOnClickListener { runScan("/api/paramspider") }
        subdomainButton.setOnClickListener { runSubdomains() }
    }
}
