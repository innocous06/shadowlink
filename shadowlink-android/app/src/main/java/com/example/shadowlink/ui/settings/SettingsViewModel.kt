package com.example.shadowlink.ui.settings

import android.app.Application
import android.content.Context
import androidx.lifecycle.AndroidViewModel
import kotlinx.coroutines.flow.MutableStateFlow

class SettingsViewModel(application: Application) : AndroidViewModel(application) {
    val serverAddr = MutableStateFlow("1.2.3.4:443")
    val sniHostname = MutableStateFlow("www.microsoft.com")
    val serverPubKey = MutableStateFlow("")

    init {
        val prefs = application.getSharedPreferences("shadowlink", Context.MODE_PRIVATE)
        serverAddr.value = prefs.getString("serverAddr", "1.2.3.4:443") ?: "1.2.3.4:443"
        sniHostname.value = prefs.getString("sniHostname", "www.microsoft.com") ?: "www.microsoft.com"
        serverPubKey.value = prefs.getString("serverPubKey", "") ?: ""
    }

    fun saveSettings() {
        val prefs = getApplication<Application>().getSharedPreferences("shadowlink", Context.MODE_PRIVATE)
        prefs.edit().apply {
            putString("serverAddr", serverAddr.value)
            putString("sniHostname", sniHostname.value)
            putString("serverPubKey", serverPubKey.value)
            apply()
        }
    }
}
