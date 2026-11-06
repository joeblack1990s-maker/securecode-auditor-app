package com.joeblack.secureaudit

import android.net.Uri
import android.os.Bundle
import android.util.Log
import android.widget.Button
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.text.HtmlCompat
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.HttpURLConnection
import java.net.URL

class ReverseActivity : AppCompatActivity() {
    private lateinit var resultText: TextView
    private lateinit var statusText: TextView
    private lateinit var selectButton: Button

    private val maxFindings = 30
    private val baseUrl = "http://127.0.0.1:5000"
    private val authToken = "Bearer super-secret-auditor-key-123"

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        supportActionBar?.hide()
        setContentView(R.layout.activity_reverse)

        resultText = findViewById(R.id.resultText)
        statusText = findViewById(R.id.statusText)
        selectButton = findViewById(R.id.selectApkButton)

        val picker = registerForActivityResult(ActivityResultContracts.GetContent()) { uri: Uri? ->
            uri?.let { auditApk(it) }
        }

        selectButton.setOnClickListener {
            picker.launch("*/*")
        }
    }

    private fun auditApk(uri: Uri) {
        resultText.text = ""
        statusText.text = "Uploading APK to server..."
        selectButton.isEnabled = false

        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val apkFile = File(cacheDir, "input.apk")
                contentResolver.openInputStream(uri)?.use { input ->
                    FileOutputStream(apkFile).use { output -> input.copyTo(output) }
                }

                val boundary = "----SecureAuditBoundary${System.currentTimeMillis()}"
                val url = URL("$baseUrl/scan_apk")
                val conn = url.openConnection() as HttpURLConnection
                conn.requestMethod = "POST"
                conn.setRequestProperty("Authorization", authToken)
                conn.setRequestProperty("Content-Type", "multipart/form-data; boundary=$boundary")
                conn.doOutput = true
                conn.connectTimeout = 30000
                conn.readTimeout = 60000

                val outputStream = conn.outputStream
                val writer = outputStream.bufferedWriter()
                writer.write("--$boundary\r\n")
                writer.write("Content-Disposition: form-data; name=\"file\"; filename=\"${apkFile.name}\"\r\n")
                writer.write("Content-Type: application/octet-stream\r\n\r\n")
                writer.flush()
                FileInputStream(apkFile).use { it.copyTo(outputStream) }
                outputStream.flush()
                writer.write("\r\n--$boundary--\r\n")
                writer.flush()
                writer.close()

                val responseCode = conn.responseCode
                val responseBody = if (responseCode in 200..299) {
                    conn.inputStream.bufferedReader().readText()
                } else {
                    conn.errorStream?.bufferedReader()?.readText() ?: ""
                }
                conn.disconnect()

                if (responseCode !in 200..299) {
                    throw Exception("Server error $responseCode: $responseBody")
                }

                val taskJson = JSONObject(responseBody)
                val taskId = taskJson.optString("task_id")
                if (taskId.isEmpty()) {
                    throw Exception("No task_id returned: $responseBody")
                }

                runOnUiThread {
                    statusText.text = "Scanning on server... (may take up to 2 minutes)"
                }

                var done = false
                var resultsJson: JSONArray? = null
                var lastError: String? = null
                while (!done) {
                    Thread.sleep(2000)
                    val statusUrl = URL("$baseUrl/status/$taskId")
                    val statusConn = statusUrl.openConnection() as HttpURLConnection
                    statusConn.requestMethod = "GET"
                    statusConn.setRequestProperty("Authorization", authToken)
                    statusConn.connectTimeout = 15000
                    statusConn.readTimeout = 30000
                    val code = statusConn.responseCode
                    val body = if (code in 200..299) {
                        statusConn.inputStream.bufferedReader().readText()
                    } else {
                        statusConn.errorStream?.bufferedReader()?.readText() ?: ""
                    }
                    statusConn.disconnect()
                    val json = JSONObject(body)
                    val status = json.optString("status")
                    when (status) {
                        "done" -> {
                            done = true
                            resultsJson = json.optJSONArray("results")
                        }
                        "error" -> {
                            done = true
                            lastError = json.optString("message", "Unknown server error")
                        }
                        else -> {
                            val stage = json.optString("stage")
                            val progress = json.optInt("progress", 0)
                            runOnUiThread {
                                statusText.text = "$stage ($progress%)"
                            }
                        }
                    }
                }

                if (lastError != null) {
                    throw Exception(lastError)
                }

                val html = formatResults(resultsJson)
                runOnUiThread {
                    statusText.text = "Done."
                    resultText.text = HtmlCompat.fromHtml(html, HtmlCompat.FROM_HTML_MODE_LEGACY)
                    selectButton.isEnabled = true
                }
            } catch (e: Exception) {
                Log.e("REVERSE_DEBUG", "Scan failed", e)
                runOnUiThread {
                    statusText.text = "Error: ${e.message}"
                    resultText.text = HtmlCompat.fromHtml(escape(e.message ?: "Unknown error"), HtmlCompat.FROM_HTML_MODE_LEGACY)
                    selectButton.isEnabled = true
                }
            }
        }
    }

    private fun formatResults(arr: JSONArray?): String {
        if (arr == null || arr.length() == 0) {
            return "Found 0 vulnerabilities<br><br>No secrets found."
        }
        val sb = StringBuilder()
        sb.append("<b><font color='#00FFFF'>=== EXECUTIVE SUMMARY ===</font></b><br><br>")
        val limit = minOf(arr.length(), maxFindings)
        for (i in 0 until limit) {
            val o = arr.getJSONObject(i)
            val type = o.optString("vulnerability_type")
            val file = o.optString("file_path")
            val fileName = file.substringAfterLast("/")
            val tag = tagFor(type)
            sb.append("${i + 1}. $tag $type - $fileName<br>")
        }
        sb.append("<br><b><font color='#00FFFF'>=== DETAILED FINDINGS ===</font></b><br><br>")
        for (i in 0 until limit) {
            val o = arr.getJSONObject(i)
            val type = o.optString("vulnerability_type")
            val file = o.optString("file_path")
            val line = o.optInt("line_number")
            val codeField = o.optString("code")
            val snippet = stripTag(codeField)
            sb.append("<b>Vulnerability #${i + 1}</b><br>")
            sb.append("Type: $type<br>")
            sb.append("File: $file | Line: $line<br>")
            sb.append("Code: <font color='#FFFFFF'>$snippet</font><br><br>")
        }
        if (arr.length() > maxFindings) {
            sb.append("... (limit reached)")
        }
        return sb.toString()
    }

    private fun tagFor(type: String): String {
        return when (type) {
            "Hardcoded Credential" -> "<font color='#FF3333'><b>[CRITICAL]</b></font>"
            "Insecure Logging" -> "<font color='#FFCC00'><b>[WARNING]</b></font>"
            "Insecure HTTP URLs" -> "<font color='#00FFFF'><b>[INFO]</b></font>"
            else -> ""
        }
    }

    private fun stripTag(code: String): String {
        return code.replace(Regex("^<font[^>]*><b>\\[[A-Z ]+\\]</b></font>\\s*"), "").trim()
    }

    private fun escape(text: String): String {
        return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    }
}
