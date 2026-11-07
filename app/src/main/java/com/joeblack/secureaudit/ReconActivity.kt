package com.joeblack.secureaudit

import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.ProgressBar
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import android.app.AlertDialog
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
                        if (sb.isEmpty()) {
                            if (domain.isNotBlank()) {
                                subdomains.add(domain)
                                "No subdomains found. Falling back to main domain: $domain"
                            } else {
                                "No subdomains found."
                            }
                        } else sb.toString()
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

        fun handleMassResults(arr: JSONArray) {
            val vulnIndices = (0 until arr.length()).filter { arr.getJSONObject(it).optString("status") == "vulnerable" }
            if (vulnIndices.isEmpty()) {
                val sb = StringBuilder()
                for (i in 0 until arr.length()) {
                    val o = arr.getJSONObject(i)
                    sb.append(o.optString("subdomain")).append(" | ")
                        .append(o.optString("status")).append(" | ")
                        .append(o.optString("type")).append(" | ")
                        .append(o.optString("tested_url")).append(" | ")
                        .append(o.optString("evidence")).append("\n")
                }
                reportText.text = if (sb.isEmpty()) "No results." else sb.toString()
                return
            }

            fun showNext(index: Int) {
                val next = vulnIndices.dropWhile { it < index }.firstOrNull()
                if (next == null) {
                    val sb = StringBuilder()
                    for (i in 0 until arr.length()) {
                        val o = arr.getJSONObject(i)
                        sb.append(o.optString("subdomain")).append(" | ")
                            .append(o.optString("status")).append(" | ")
                            .append(o.optString("type")).append(" | ")
                            .append(o.optString("tested_url")).append(" | ")
                            .append(o.optString("evidence")).append("\n")
                    }
                    reportText.text = if (sb.isEmpty()) "No results." else sb.toString()
                    return
                }
                val o = arr.getJSONObject(next)
                val type = o.optString("type")
                val url = o.optString("tested_url")
                AlertDialog.Builder(this@ReconActivity)
                    .setTitle("Vulnerability Found!")
                    .setMessage("A $type was found at $url. Do you have authorization to extract proof of concept?")
                    .setPositiveButton("PROCEED") { _, _ ->
                        progressBar.visibility = android.view.View.VISIBLE
                        setEnabled(false)
                        Thread {
                            try {
                                val conn = URL("http://127.0.0.1:5000/api/extract").openConnection() as HttpURLConnection
                                conn.requestMethod = "POST"
                                conn.setRequestProperty("Authorization", "Bearer super-secret-auditor-key-123")
                                conn.setRequestProperty("Content-Type", "application/json")
                                conn.doOutput = true
                                conn.connectTimeout = 30000
                                conn.readTimeout = 60000
                                val body = JSONObject().put("url", url).put("vuln_type", type).toString()
                                conn.outputStream.use { it.write(body.toByteArray()) }
                                val code = conn.responseCode
                                val responseText = (if (code in 200..299) conn.inputStream else conn.errorStream)?.bufferedReader()?.readText().orEmpty()
                                conn.disconnect()
                                val evidence = try { JSONObject(responseText).optString("evidence", responseText) } catch (e: Exception) { responseText }
                                o.put("evidence", evidence)
                            } catch (e: Exception) {
                                o.put("evidence", "Extract error: ${e.message}")
                            }
                            runOnUiThread {
                                progressBar.visibility = android.view.View.GONE
                                setEnabled(true)
                                showNext(next + 1)
                            }
                        }.start()
                    }
                    .setNegativeButton("SKIP") { _, _ ->
                        o.put("evidence", "Vulnerable - Not Exploited")
                        showNext(next + 1)
                    }
                    .setCancelable(false)
                    .show()
            }

            showNext(0)
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
                                .append(o.optString("tested_url"))
                                .append(" | ")
                                .append(o.optString("evidence"))
                                .append("\n")
                        }
                        if (sb.isEmpty()) "No results." else sb.toString()
                    } catch (e: Exception) {
                        responseText
                    }

                    lastMassResults = parsedArray
                    runOnUiThread {
                        progressBar.visibility = android.view.View.GONE
                        setEnabled(true)
                        if (parsedArray != null) {
                            handleMassResults(parsedArray!!)
                        } else {
                            reportText.text = display
                        }
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
                    if (arr == null) {
                        runOnUiThread {
                            reportText.text = "No vulnerable findings to report."
                            progressBar.visibility = android.view.View.GONE
                            setEnabled(true)
                        }
                        return@Thread
                    }
                    var vulnType = ""
                    var url = ""
                    var payload = ""
                    var evidence = ""
                    var found = false
                    if (arr != null) {
                        for (i in 0 until arr.length()) {
                            val o = arr.getJSONObject(i)
                            if (o.optString("status") == "vulnerable") {
                                vulnType = o.optString("type")
                                val tested = o.optString("tested_url")
                                url = if (tested.isNotBlank()) tested else "http://" + o.optString("subdomain")
                                payload = o.optString("payload", payload)
                                if (payload.isBlank()) payload = "N/A"
                                evidence = o.optString("evidence")
                                found = true
                                break
                            }
                        }
                    }
                    if (!found) {
                        runOnUiThread {
                            reportText.text = "No vulnerable findings to report."
                            progressBar.visibility = android.view.View.GONE
                            setEnabled(true)
                        }
                        return@Thread
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

        fun runExtract() {
            val arr = lastMassResults ?: return
            progressBar.visibility = android.view.View.VISIBLE
            setEnabled(false)
            Thread {
                try {
                    for (i in 0 until arr.length()) {
                        val o = arr.getJSONObject(i)
                        if (o.optString("status") != "vulnerable") continue
                        val url = o.optString("tested_url")
                        val type = o.optString("type")
                        val conn = URL("http://127.0.0.1:5000/api/extract").openConnection() as HttpURLConnection
                        conn.requestMethod = "POST"
                        conn.setRequestProperty("Authorization", "Bearer super-secret-auditor-key-123")
                        conn.setRequestProperty("Content-Type", "application/json")
                        conn.doOutput = true
                        conn.connectTimeout = 30000
                        conn.readTimeout = 60000
                        val body = JSONObject().put("url", url).put("vuln_type", type).toString()
                        conn.outputStream.use { it.write(body.toByteArray()) }
                        val code = conn.responseCode
                        val responseText = (if (code in 200..299) conn.inputStream else conn.errorStream)?.bufferedReader()?.readText().orEmpty()
                        conn.disconnect()
                        val evidence = try { JSONObject(responseText).optString("evidence", responseText) } catch (e: Exception) { responseText }
                        o.put("evidence", evidence)
                    }
                    val sb = StringBuilder()
                    for (i in 0 until arr.length()) {
                        val o = arr.getJSONObject(i)
                        sb.append(o.optString("subdomain"))
                            .append(" | ")
                            .append(o.optString("status"))
                            .append(" | ")
                            .append(o.optString("type"))
                            .append(" | ")
                            .append(o.optString("tested_url"))
                            .append(" | ")
                            .append(o.optString("evidence"))
                            .append("\n")
                    }
                    runOnUiThread {
                        reportText.text = sb.toString()
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
