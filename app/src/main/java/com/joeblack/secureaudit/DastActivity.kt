package com.joeblack.secureaudit

import android.os.Bundle
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity

class DastActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        supportActionBar?.hide()
        setContentView(R.layout.activity_placeholder)
        findViewById<TextView>(R.id.placeholderText).text = "DAST Proxy Listener - Coming Soon"
    }
}
