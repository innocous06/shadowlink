package com.example.shadowlink.ui.main

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.example.shadowlink.data.DataRepository
import com.example.shadowlink.ui.main.MainScreenUiState.Success
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.catch

import android.content.Context
import android.content.Intent
import com.example.shadowlink.ShadowLinkVpnService
import kotlinx.coroutines.flow.MutableStateFlow

sealed class VpnState {
    object Disconnected : VpnState()
    object Connecting : VpnState()
    data class Connected(val serverAddr: String) : VpnState()
    data class Error(val message: String) : VpnState()
}

class MainScreenViewModel(dataRepository: DataRepository) : ViewModel() {
  val uiState: StateFlow<MainScreenUiState> =
    dataRepository.data
      .map<List<String>, MainScreenUiState>(::Success)
      .catch { emit(MainScreenUiState.Error(it)) }
      .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), MainScreenUiState.Loading)
      
  val vpnState = MutableStateFlow<VpnState>(VpnState.Disconnected)

  fun connectVpn(context: Context, serverAddr: String, clientPriv: String, serverPub: String) {
      vpnState.value = VpnState.Connecting
      val intent = Intent(context, ShadowLinkVpnService::class.java).apply {
          putExtra("SERVER_ADDR", serverAddr)
          putExtra("CLIENT_PRIV", clientPriv)
          putExtra("SERVER_PUB", serverPub)
      }
      context.startForegroundService(intent)
      vpnState.value = VpnState.Connected(serverAddr)
  }

  fun disconnectVpn(context: Context) {
      val intent = Intent(context, ShadowLinkVpnService::class.java).apply { action = "STOP" }
      context.startService(intent)
      vpnState.value = VpnState.Disconnected
  }
      
}

sealed interface MainScreenUiState {
  object Loading : MainScreenUiState

  data class Error(val throwable: Throwable) : MainScreenUiState

  data class Success(val data: List<String>) : MainScreenUiState
}
