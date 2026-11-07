package com.joeblack.secureaudit

import android.os.Bundle
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.EditText
import android.widget.Spinner
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.text.HtmlCompat
import java.net.HttpURLConnection
import java.net.URL

class DastActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        supportActionBar?.hide()
        setContentView(R.layout.activity_dast)

        val urlInput = findViewById<EditText>(R.id.urlInput)
        val methodSpinner = findViewById<Spinner>(R.id.methodSpinner)
        val bodyInput = findViewById<EditText>(R.id.body_input)
        val sendButton = findViewById<Button>(R.id.sendButton)
        val outputText = findViewById<TextView>(R.id.outputText)

        val methods = listOf("GET", "POST")
        methodSpinner.adapter = ArrayAdapter(this, android.R.layout.simple_spinner_item, methods).apply {
            setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        }

        methodSpinner.onItemSelectedListener = object : android.widget.AdapterView.OnItemSelectedListener {
            override fun onItemSelected(parent: android.widget.AdapterView<*>?, view: android.view.View?, position: Int, id: Long) {
                bodyInput.visibility = if (methods[position] == "POST") android.view.View.VISIBLE else android.view.View.GONE
            }
            override fun onNothingSelected(parent: android.widget.AdapterView<*>?) {}
        }

        sendButton.setOnClickListener {
            val url = urlInput.text.toString().trim()
            val method = methodSpinner.selectedItem.toString()
            val body = bodyInput.text.toString()
            outputText.text = "Sending request..."
            sendButton.isEnabled = false

            Thread {
                try {
                    val conn = URL(url).openConnection() as HttpURLConnection
                    conn.requestMethod = method
                    conn.connectTimeout = 15000
                    conn.readTimeout = 60000
                    if (method == "POST") {
                        conn.doOutput = true
                        conn.setRequestProperty("Content-Type", "application/json")
                        conn.outputStream.use { it.write(body.toByteArray()) }
                    }
                    val code = conn.responseCode
                    val responseText = try {
                        (if (code in 200..299) conn.inputStream else conn.errorStream)?.bufferedReader()?.readText().orEmpty()
                    } catch (e: Exception) {
                        e.message ?: ""
                    }
                    val headers = StringBuilder()
                    for (key in conn.headerFields.keys) {
                        if (key == null) continue
                        headers.append("$key: ${conn.headerFields[key]}\n")
                    }
                    conn.disconnect()

                    val html = buildString {
                        append("Status: $code\n\n")
                        append("Headers:\n$headers\n")
                        append("Body:\n$responseText")
                    }
                    runOnUiThread {
                        outputText.text = html
                        sendButton.isEnabled = true
                    }
                } catch (e: Exception) {
                    runOnUiThread {
                        outputText.text = "Error: ${e.message}"
                        sendButton.isEnabled = true
                    }
                }
            }.start()
        }
    }
}
