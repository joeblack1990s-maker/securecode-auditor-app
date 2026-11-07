package com.joeblack.secureaudit

import android.content.Intent
import android.os.Bundle
import android.widget.Button
import androidx.appcompat.app.AppCompatActivity

class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val scanButton = findViewById<Button>(R.id.scanButton)
        val dastButton = findViewById<Button>(R.id.dastButton)
        val reverseButton = findViewById<Button>(R.id.reverseButton)
        val cloudButton = findViewById<Button>(R.id.button4)
        val reconButton = findViewById<Button>(R.id.reconButton)

        scanButton.setOnClickListener {
            startActivity(Intent(this, ReverseActivity::class.java))
        }

        dastButton.setOnClickListener {
            startActivity(Intent(this, DastActivity::class.java))
        }

        reverseButton.setOnClickListener {
            startActivity(Intent(this, ReverseActivity::class.java))
        }

        cloudButton.setOnClickListener {
            startActivity(Intent(this, CloudActivity::class.java))
        }

        reconButton.setOnClickListener {
            startActivity(Intent(this, ReconActivity::class.java))
        }
    }
}
