package com.example.shadowlink.ui.settings

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel

@Composable
fun SettingsScreen(viewModel: SettingsViewModel = viewModel()) {
    val serverAddr by viewModel.serverAddr.collectAsStateWithLifecycle()
    val sniHostname by viewModel.sniHostname.collectAsStateWithLifecycle()
    val serverPubKey by viewModel.serverPubKey.collectAsStateWithLifecycle()
    
    Column(modifier = Modifier.padding(16.dp)) {
        Text("Server Configuration", style = MaterialTheme.typography.titleMedium)
        Spacer(Modifier.height(8.dp))
        
        OutlinedTextField(
            value = serverAddr,
            onValueChange = { viewModel.serverAddr.value = it },
            label = { Text("Server Address") },
            modifier = Modifier.fillMaxWidth()
        )
        Spacer(Modifier.height(8.dp))
        
        OutlinedTextField(
            value = sniHostname,
            onValueChange = { viewModel.sniHostname.value = it },
            label = { Text("SNI Hostname") },
            modifier = Modifier.fillMaxWidth()
        )
        Spacer(Modifier.height(8.dp))
        
        OutlinedTextField(
            value = serverPubKey,
            onValueChange = { viewModel.serverPubKey.value = it },
            label = { Text("Server Public Key") },
            modifier = Modifier.fillMaxWidth()
        )
        Spacer(Modifier.height(16.dp))
        
        Button(onClick = { viewModel.saveSettings() }, modifier = Modifier.fillMaxWidth()) {
            Text("Save")
        }
    }
}
