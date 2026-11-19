package com.readroid.app.ui.main

import com.readroid.app.data.DataRepository
import junit.framework.TestCase.assertEquals
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.filterIsInstance
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.test.runTest
import org.junit.Test

class MainScreenViewModelTest {
  @Test
  fun uiState_initiallyLoading() = runTest {
    val viewModel = MainScreenViewModel(FakeMyModelRepository())
    assertEquals(viewModel.uiState.first(), MainScreenUiState.Loading)
  }

  @Test
  fun uiState_emitsDataFromRepository() = runTest {
    val viewModel = MainScreenViewModel(FakeMyModelRepository())
    val state = viewModel.uiState.filterIsInstance<MainScreenUiState.Success>().first()
    assertEquals(MainScreenUiState.Success(listOf("Sample")), state)
  }
}

private class FakeMyModelRepository : DataRepository {
  override val data: Flow<List<String>> = flow { emit(listOf("Sample")) }
}
