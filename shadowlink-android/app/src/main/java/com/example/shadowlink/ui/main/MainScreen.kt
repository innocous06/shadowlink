package com.example.shadowlink.ui.main

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
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
  val pingResult by viewModel.pingResult.collectAsStateWithLifecycle()
  
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
      
      Spacer(modifier = Modifier.height(32.dp))
      
      Button(onClick = { viewModel.pingVps() }) {
          Text("Ping VPS")
      }
      
      Spacer(modifier = Modifier.height(16.dp))
      
      Text(text = pingResult)
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
