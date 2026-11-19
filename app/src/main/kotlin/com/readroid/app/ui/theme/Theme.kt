package com.readroid.app.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

private val ReaDroidDark = darkColorScheme(
    primary = Accent,
    onPrimary = Color.White,
    primaryContainer = AccentSoft,
    onPrimaryContainer = TextPrimary,
    secondary = Violet,
    onSecondary = Color.White,
    secondaryContainer = VioletSoft,
    onSecondaryContainer = TextPrimary,
    tertiary = Mint,
    onTertiary = Ink,
    tertiaryContainer = MintSoft,
    onTertiaryContainer = TextPrimary,
    background = Ink,
    onBackground = TextPrimary,
    surface = InkRaised,
    onSurface = TextPrimary,
    surfaceVariant = InkOverlay,
    onSurfaceVariant = TextSecondary,
    outline = InkBorder,
    error = Coral,
    onError = Color.White,
    errorContainer = CoralSoft,
    onErrorContainer = TextPrimary
)

private val ReaDroidLight = lightColorScheme(
    primary = PaperAccent,
    onPrimary = Color.White,
    primaryContainer = Color(0xFFDCE4FF),
    onPrimaryContainer = Color(0xFF0C1A4A),
    secondary = Color(0xFF6850B8),
    onSecondary = Color.White,
    tertiary = PaperMint,
    onTertiary = Color.White,
    background = Paper,
    onBackground = PaperTextPrimary,
    surface = PaperRaised,
    onSurface = PaperTextPrimary,
    surfaceVariant = Color(0xFFEEF1F7),
    onSurfaceVariant = PaperTextSecondary,
    outline = PaperBorder,
    error = PaperCoral,
    onError = Color.White,
    errorContainer = Color(0xFFFFDAD9),
    onErrorContainer = Color(0xFF410006)
)

@Composable
fun ReaDroidTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit
) {
    MaterialTheme(
        colorScheme = if (darkTheme) ReaDroidDark else ReaDroidLight,
        typography = Typography,
        content = content
    )
}
