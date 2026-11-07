package com.joeblack.secureaudit

import android.os.Bundle
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity

class ManualActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        supportActionBar?.hide()
        setContentView(R.layout.activity_manual)

        val manualText = findViewById<TextView>(R.id.manualText)
        manualText.text = """
SECURECODE AUDITOR - USER MANUAL

1. INITIATE CODE SCAN (SAST)
Opens Reverse Engineering flow. Upload an APK. The server decompiles it with JADX, scans Java/Kotlin/XML/native files for hardcoded secrets, high-entropy strings, manifest misconfigurations, and sends top findings to AI. Use for APK secret discovery.

2. DYNAMIC ANALYSIS (DAST)
Send HTTP requests to a target. Choose GET or POST, enter URL and optional JSON body. View status, headers, body. Use to test endpoints, manipulate parameters, and probe vulnerabilities.

3. REVERSE ENGINEERING
Same as code scan: upload APK, server decompiles and scans. Use to find passwords, API keys, tokens, and insecure configs.

4. CLOUD SECURITY SCAN
Paste cloud config (JSON/YAML) and scan for public buckets, wildcard IAM, hardcoded keys, unencrypted storage.

5. AUTOMATED RECON ENGINE
Enter a target URL and run:
- RUN RECON SCAN: fingerprints tech stack, WAF, suggests attacks and payloads.
- RUN DIRECTORY FUZZER: brute-forces common paths (admin, backup, config, etc.) and reports 200/302.
- RUN PARAM SPIDER: extracts URL parameters and endpoints from HTML.

USAGE TIPS:
- For DAST, use POST with JSON to test price manipulation, SQLi, SSTI, XSS.
- For APK scanning, ensure server is running on 127.0.0.1:5000.
- Review AI findings; verify manually before reporting.
""".trimIndent()
    }
}
