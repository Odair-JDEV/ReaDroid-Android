package com.readroid.app.ui.main

import androidx.activity.ComponentActivity
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithText
import com.readroid.app.ui.theme.ReaDroidTheme
import org.junit.Rule
import org.junit.Test

/** Interface do fluxo guiado: a primeira tela precisa ser óbvia para quem nunca analisou um APK. */
class MainScreenTest {

    @get:Rule
    val composeTestRule = createAndroidComposeRule<ComponentActivity>()

    private fun openHome() {
        composeTestRule.setContent {
            ReaDroidTheme(darkTheme = true) { MainScreen() }
        }
    }

    @Test
    fun home_explains_purpose_and_offers_first_action() {
        openHome()

        composeTestRule.onNodeWithText("ReaDroid").assertIsDisplayed()
        composeTestRule.onNodeWithText("Vamos entender um aplicativo juntos").assertIsDisplayed()
        composeTestRule.onNodeWithText("Escolher um APK").assertIsDisplayed()
    }

    @Test
    fun home_lists_the_three_steps() {
        openHome()

        composeTestRule.onNodeWithText("Escolher o arquivo").assertIsDisplayed()
        composeTestRule.onNodeWithText("Ler o que encontramos").assertIsDisplayed()
        composeTestRule.onNodeWithText("Ver um resumo fácil").assertIsDisplayed()
    }

    @Test
    fun home_shows_privacy_reassurance() {
        openHome()

        composeTestRule.onNodeWithText("O arquivo original nunca é alterado").assertIsDisplayed()
        composeTestRule.onNodeWithText("Nenhum aplicativo analisado é executado").assertIsDisplayed()
    }
}
