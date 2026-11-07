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
    private val subdomains = mutableListOf<String>()
    private var lastMassResults: JSONArray? = null

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
        val massScanButton = findViewById<Button>(R.id.massScanButton)
        val reportButton = findViewById<Button>(R.id.reportButton)
        val progressBar = findViewById<ProgressBar>(R.id.progressBar)
        val reportText = findViewById<TextView>(R.id.reportText)

        fun setEnabled(enabled: Boolean) {
            runButton.isEnabled = enabled
            fuzzButton.isEnabled = enabled
            paramButton.isEnabled = enabled
            subdomainButton.isEnabled = enabled
            massScanButton.isEnabled = enabled
            reportButton.isEnabled = enabled
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
            subdomains.clear()

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
                            val item = arr.getString(i)
                            subdomains.add(item)
                            sb.append(item).append("\n")
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

        fun runMassScan() {
            val targets = if (subdomains.isNotEmpty()) subdomains.toList() else reportText.text.toString().lines().filter { it.isNotBlank() }
            if (targets.isEmpty()) {
                reportText.text = "No subdomains to scan. Run subdomain enumeration first."
                return
            }
            reportText.text = "Scanning ${targets.size} subdomains..."
            progressBar.visibility = android.view.View.VISIBLE
            setEnabled(false)

            Thread {
                try {
                    val conn = URL("http://127.0.0.1:5000/api/mass_scan").openConnection() as HttpURLConnection
                    conn.requestMethod = "POST"
                    conn.setRequestProperty("Authorization", "Bearer super-secret-auditor-key-123")
                    conn.setRequestProperty("Content-Type", "application/json")
                    conn.doOutput = true
                    conn.connectTimeout = 30000
                    conn.readTimeout = 300000
                    val arr = JSONArray()
                    for (t in targets) arr.put(t)
                    val body = JSONObject().put("subdomains", arr).toString()
                    conn.outputStream.use { it.write(body.toByteArray()) }

                    val code = conn.responseCode
                    val responseText = (if (code in 200..299) conn.inputStream else conn.errorStream)?.bufferedReader()?.readText().orEmpty()
                    conn.disconnect()

                    var parsedArray: JSONArray? = null
                    val display = try {
                        val arr2 = JSONArray(responseText)
                        parsedArray = arr2
                        val sb = StringBuilder()
                        for (i in 0 until arr2.length()) {
                            val o = arr2.getJSONObject(i)
                            sb.append(o.optString("subdomain"))
                                .append(" | ")
                                .append(o.optString("status"))
                                .append(" | ")
                                .append(o.optString("type"))
                                .append(" | ")
                                .append(o.optString("evidence"))
                                .append("\n")
                        }
                        if (sb.isEmpty()) "No results." else sb.toString()
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

        fun runReport() {
            reportText.text = ""
            progressBar.visibility = android.view.View.VISIBLE
            setEnabled(false)

            Thread {
                try {
                    val conn = URL("http://127.0.0.1:5000/api/generate_report").openConnection() as HttpURLConnection
                    conn.requestMethod = "POST"
                    conn.setRequestProperty("Authorization", "Bearer super-secret-auditor-key-123")
                    conn.setRequestProperty("Content-Type", "application/json")
                    conn.doOutput = true
                    conn.connectTimeout = 30000
                    conn.readTimeout = 60000
                    val arr = lastMassResults
                    var vulnType = "SSTI"
                    var url = "http://target.com/search?q="
                    var payload = "{{7*7}}"
                    var evidence = "Server returned 49"
                    if (arr != null) {
                        for (i in 0 until arr.length()) {
                            val o = arr.getJSONObject(i)
                            if (o.optString("status") == "vulnerable") {
                                vulnType = o.optString("type")
                                url = "http://" + o.optString("subdomain")
                                payload = o.optString("payload", payload)
                                if (payload.isBlank()) payload = "{{7*7}}"
                                evidence = o.optString("evidence")
                                break
                            }
                        }
                    }
                    val body = JSONObject()
                        .put("vuln_type", vulnType)
                        .put("url", url)
                        .put("payload", payload)
                        .put("evidence", evidence)
                        .toString()
                    conn.outputStream.use { it.write(body.toByteArray()) }

                    val code = conn.responseCode
                    val responseText = (if (code in 200..299) conn.inputStream else conn.errorStream)?.bufferedReader()?.readText().orEmpty()
                    conn.disconnect()

                    val display = try {
                        JSONObject(responseText).optString("report", responseText)
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
        massScanButton.setOnClickListener { runMassScan() }
        reportButton.setOnClickListener { runReport() }
    }
}
