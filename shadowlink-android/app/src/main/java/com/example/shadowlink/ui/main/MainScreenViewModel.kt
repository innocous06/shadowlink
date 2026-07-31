package com.example.shadowlink.ui.main

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.example.shadowlink.data.DataRepository
import com.example.shadowlink.ui.main.MainScreenUiState.Success
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.BufferedReader
import java.io.InputStreamReader

class MainScreenViewModel(dataRepository: DataRepository) : ViewModel() {
  val uiState: StateFlow<MainScreenUiState> =
    dataRepository.data
      .map<List<String>, MainScreenUiState>(::Success)
      .catch { emit(MainScreenUiState.Error(it)) }
      .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), MainScreenUiState.Loading)
      
  val pingResult = MutableStateFlow<String>("")

  fun pingVps() {
      viewModelScope.launch {
          pingResult.value = "Pinging VPS..."
          val result = withContext(Dispatchers.IO) {
              try {
                  val process = Runtime.getRuntime().exec("ping -c 4 YOUR_VPS_IP_HERE")
                  val reader = BufferedReader(InputStreamReader(process.inputStream))
                  val output = StringBuilder()
                  var line: String?
                  while (reader.readLine().also { line = it } != null) {
                      output.append(line).append("\n")
                  }
                  process.waitFor()
                  if (output.isEmpty()) {
                      "Ping failed or blocked."
                  } else {
                      output.toString()
                  }
              } catch (e: Exception) {
                  "Error: ${e.message}"
              }
          }
          pingResult.value = result
      }
  }
}

sealed interface MainScreenUiState {
  object Loading : MainScreenUiState

  data class Error(val throwable: Throwable) : MainScreenUiState

  data class Success(val data: List<String>) : MainScreenUiState
}
