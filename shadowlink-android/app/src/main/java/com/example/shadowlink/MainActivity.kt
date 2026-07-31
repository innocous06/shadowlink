package com.example.shadowlink

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.net.VpnService
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.net.InetAddress

class MainActivity : ComponentActivity() {

    private var vpnStatus by mutableStateOf("Disconnected")
    private var pingResult by mutableStateOf("Ping: ---")

    private lateinit var prefs: SharedPreferences

    private var serverAddr by mutableStateOf("")
    private var clientPriv by mutableStateOf("")
    private var serverPub by mutableStateOf("")

    private val vpnLauncher = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            startVpnService()
        } else {
            Toast.makeText(this, "VPN Permission Denied", Toast.LENGTH_SHORT).show()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        prefs = getSharedPreferences("shadowlink_prefs", Context.MODE_PRIVATE)
        serverAddr = prefs.getString("serverAddr", "") ?: ""
        clientPriv = prefs.getString("clientPriv", "") ?: ""
        serverPub = prefs.getString("serverPub", "") ?: ""

        setContent {
            MaterialTheme(colorScheme = darkColorScheme()) {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    VpnUI(
                        status = vpnStatus,
                        pingText = pingResult,
                        serverAddr = serverAddr,
                        clientPriv = clientPriv,
                        serverPub = serverPub,
                        onServerAddrChange = { 
                            serverAddr = it
                            prefs.edit().putString("serverAddr", it).apply()
                        },
                        onClientPrivChange = { 
                            clientPriv = it
                            prefs.edit().putString("clientPriv", it).apply()
                        },
                        onServerPubChange = { 
                            serverPub = it
                            prefs.edit().putString("serverPub", it).apply()
                        },
                        onConnectClick = { prepareVpn() },
                        onDisconnectClick = { stopVpnService() },
                        onPingClick = { pingVps() }
                    )
                }
            }
        }
    }

    private fun prepareVpn() {
        if (serverAddr.isBlank() || clientPriv.isBlank() || serverPub.isBlank()) {
            Toast.makeText(this, "Please enter all configuration values", Toast.LENGTH_SHORT).show()
            return
        }
        val intent = VpnService.prepare(this)
        if (intent != null) {
            vpnLauncher.launch(intent)
        } else {
            startVpnService()
        }
    }

    private fun startVpnService() {
        val intent = Intent(this, ShadowLinkVpnService::class.java).apply {
            putExtra("SERVER_ADDR", serverAddr)
            putExtra("CLIENT_PRIV", clientPriv)
            putExtra("SERVER_PUB", serverPub)
        }
        startService(intent)
        vpnStatus = "Connected"
    }

    private fun stopVpnService() {
        val intent = Intent(this, ShadowLinkVpnService::class.java).apply {
            action = "STOP"
        }
        startService(intent)
        vpnStatus = "Disconnected"
    }

    private fun pingVps() {
        pingResult = "Pinging..."
        kotlinx.coroutines.CoroutineScope(Dispatchers.IO).launch {
            try {
                val start = System.currentTimeMillis()
                val reachable = InetAddress.getByName("10.8.0.1").isReachable(3000)
                val end = System.currentTimeMillis()
                
                withContext(Dispatchers.Main) {
                    if (reachable) {
                        pingResult = "Ping: ${end - start} ms"
                    } else {
                        pingResult = "Ping: Timeout"
                    }
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    pingResult = "Ping: Error"
                }
            }
        }
    }
}

@Composable
fun VpnUI(
    status: String,
    pingText: String,
    serverAddr: String,
    clientPriv: String,
    serverPub: String,
    onServerAddrChange: (String) -> Unit,
    onClientPrivChange: (String) -> Unit,
    onServerPubChange: (String) -> Unit,
    onConnectClick: () -> Unit,
    onDisconnectClick: () -> Unit,
    onPingClick: () -> Unit
) {
    Column(
        modifier = Modifier.fillMaxSize().padding(16.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text(text = "ShadowLink", style = MaterialTheme.typography.headlineLarge)
        Spacer(modifier = Modifier.height(16.dp))
        
        OutlinedTextField(
            value = serverAddr,
            onValueChange = onServerAddrChange,
            label = { Text("Server Address (IP:PORT)") },
            modifier = Modifier.fillMaxWidth()
        )
        Spacer(modifier = Modifier.height(8.dp))
        
        OutlinedTextField(
            value = clientPriv,
            onValueChange = onClientPrivChange,
            label = { Text("Client Private Key (Base64)") },
            modifier = Modifier.fillMaxWidth()
        )
        Spacer(modifier = Modifier.height(8.dp))
        
        OutlinedTextField(
            value = serverPub,
            onValueChange = onServerPubChange,
            label = { Text("Server Public Key (Base64)") },
            modifier = Modifier.fillMaxWidth()
        )
        Spacer(modifier = Modifier.height(32.dp))
        
        Text(text = "Status: $status", style = MaterialTheme.typography.titleMedium)
        Spacer(modifier = Modifier.height(16.dp))
        
        Row {
            Button(onClick = onConnectClick, modifier = Modifier.padding(8.dp)) {
                Text("Connect")
            }
            Button(onClick = onDisconnectClick, modifier = Modifier.padding(8.dp)) {
                Text("Disconnect")
            }
        }
        
        Spacer(modifier = Modifier.height(16.dp))
        
        Button(onClick = onPingClick) {
            Text("Test Ping (10.8.0.1)")
        }
        Spacer(modifier = Modifier.height(8.dp))
        Text(text = pingText, style = MaterialTheme.typography.bodyLarge)
    }
}

