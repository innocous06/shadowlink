package com.example.shadowlink.ui.main

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.Button
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation3.runtime.NavKey
import com.example.shadowlink.data.DefaultDataRepository
import com.example.shadowlink.theme.ShadowLinkTheme

@Composable
fun MainScreen(
  onItemClick: (NavKey) -> Unit,
  modifier: Modifier = Modifier,
  viewModel: MainScreenViewModel = viewModel { MainScreenViewModel(DefaultDataRepository()) },
) {
  val state by viewModel.uiState.collectAsStateWithLifecycle()
  Column(modifier = modifier.padding(16.dp)) {
      when (state) {
        MainScreenUiState.Loading -> {
          // Blank
        }
        is MainScreenUiState.Success -> {
          MainScreen(data = (state as MainScreenUiState.Success).data, modifier = modifier)
        }
        is MainScreenUiState.Error -> {
          Text("Error loading data: ${(state as MainScreenUiState.Error).throwable.message}")
        }
      }
           val context = androidx.compose.ui.platform.LocalContext.current
      val prefs = android.preference.PreferenceManager.getDefaultSharedPreferences(context)
      
      var serverAddr by androidx.compose.runtime.remember {
          androidx.compose.runtime.mutableStateOf(prefs.getString("SERVER_ADDR", "") ?: "")
      }
      var clientPriv by androidx.compose.runtime.remember {
          androidx.compose.runtime.mutableStateOf(prefs.getString("CLIENT_PRIV", "") ?: "")
      }
      var serverPub by androidx.compose.runtime.remember {
          androidx.compose.runtime.mutableStateOf(prefs.getString("SERVER_PUB", "") ?: "")
      }

      fun savePrefs() {
          prefs.edit()
              .putString("SERVER_ADDR", serverAddr)
              .putString("CLIENT_PRIV", clientPriv)
              .putString("SERVER_PUB", serverPub)
              .apply()
      }

      val vpnPermissionLauncher = androidx.activity.compose.rememberLauncherForActivityResult(
          androidx.activity.result.contract.ActivityResultContracts.StartActivityForResult()
      ) { result ->
          if (result.resultCode == android.app.Activity.RESULT_OK) {
              savePrefs()
              val intent = android.content.Intent(context, com.example.shadowlink.ShadowLinkVpnService::class.java).apply {
                  putExtra("SERVER_ADDR", serverAddr)
                  putExtra("CLIENT_PRIV", clientPriv)
                  putExtra("SERVER_PUB", serverPub)
              }
              context.startForegroundService(intent)
          }
      }

      androidx.compose.material3.OutlinedTextField(
          value = serverAddr,
          onValueChange = { serverAddr = it },
          label = { androidx.compose.material3.Text("Server (host:port)") },
          modifier = androidx.compose.ui.Modifier.fillMaxWidth()
      )
      androidx.compose.foundation.layout.Spacer(Modifier.height(8.dp))
      androidx.compose.material3.OutlinedTextField(
          value = clientPriv,
          onValueChange = { clientPriv = it },
          label = { androidx.compose.material3.Text("Client Private Key (Base64)") },
          modifier = androidx.compose.ui.Modifier.fillMaxWidth()
      )
      androidx.compose.foundation.layout.Spacer(Modifier.height(8.dp))
      androidx.compose.material3.OutlinedTextField(
          value = serverPub,
          onValueChange = { serverPub = it },
          label = { androidx.compose.material3.Text("Server Public Key (Base64)") },
          modifier = androidx.compose.ui.Modifier.fillMaxWidth()
      )

      androidx.compose.foundation.layout.Spacer(Modifier.height(16.dp))
      androidx.compose.material3.Button(
          onClick = {
              savePrefs()
              val prepareIntent = android.net.VpnService.prepare(context)
              if (prepareIntent != null) {
                  vpnPermissionLauncher.launch(prepareIntent)
              } else {
                  val intent = android.content.Intent(context, com.example.shadowlink.ShadowLinkVpnService::class.java).apply {
                      putExtra("SERVER_ADDR", serverAddr)
                      putExtra("CLIENT_PRIV", clientPriv)
                      putExtra("SERVER_PUB", serverPub)
                  }
                  context.startForegroundService(intent)
              }
          },
          modifier = androidx.compose.ui.Modifier.fillMaxWidth()
      ) { androidx.compose.material3.Text("Connect VPN") }

      androidx.compose.foundation.layout.Spacer(Modifier.height(8.dp))
      androidx.compose.material3.Button(
          onClick = {
              val intent = android.content.Intent(context, com.example.shadowlink.ShadowLinkVpnService::class.java).apply { action = "STOP" }
              context.startService(intent)
          },
          colors = androidx.compose.material3.ButtonDefaults.buttonColors(containerColor = androidx.compose.material3.MaterialTheme.colorScheme.error),
          modifier = androidx.compose.ui.Modifier.fillMaxWidth()
      ) { androidx.compose.material3.Text("Disconnect") }
  }
}

@Composable
internal fun MainScreen(data: List<String>, modifier: Modifier = Modifier) {
  Column(modifier) { data.forEach { Greeting(it) } }
}

@Composable
fun Greeting(name: String, modifier: Modifier = Modifier) {
  Text(text = "Hello $name!", modifier = modifier)
}

@Preview(showBackground = true)
@Composable
fun MainScreenPreview() {
  ShadowLinkTheme { MainScreen(listOf("Android")) }
}

@Preview(showBackground = true, widthDp = 340)
@Composable
fun MainScreenPortraitPreview() {
  ShadowLinkTheme { MainScreen(listOf("Android")) }
}

