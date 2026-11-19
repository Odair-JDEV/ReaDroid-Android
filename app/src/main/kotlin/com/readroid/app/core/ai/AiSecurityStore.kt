package com.readroid.app.core.ai

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKeys

data class AiSettings(
    val isEnabled: Boolean = false,
    val providerUrl: String = "https://openrouter.ai/api/v1",
    val modelName: String = "nvidia/nemotron-3.5-lightning:free",
    val apiKey: String = ""
)

/**
 * Gerenciador seguro de configurações e chaves de API de IA.
 * Utiliza o Android Keystore System via EncryptedSharedPreferences (criptografia AES-256 GCM)
 * para garantir que nenhuma chave fique exposta em texto puro no sistema de arquivos.
 */
class AiSecurityStore(private val context: Context) {

    private val masterKeyAlias = MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC)

    private val securePrefs by lazy {
        EncryptedSharedPreferences.create(
            "readroid_ai_secure_prefs",
            masterKeyAlias,
            context,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }

    fun loadSettings(): AiSettings {
        return AiSettings(
            isEnabled = securePrefs.getBoolean("ai_enabled", false),
            providerUrl = securePrefs.getString("ai_provider_url", "https://openrouter.ai/api/v1") ?: "https://openrouter.ai/api/v1",
            modelName = securePrefs.getString("ai_model_name", "nvidia/nemotron-3.5-lightning:free") ?: "nvidia/nemotron-3.5-lightning:free",
            apiKey = securePrefs.getString("ai_api_key", "") ?: ""
        )
    }

    fun saveSettings(settings: AiSettings) {
        securePrefs.edit()
            .putBoolean("ai_enabled", settings.isEnabled)
            .putString("ai_provider_url", settings.providerUrl)
            .putString("ai_model_name", settings.modelName)
            .putString("ai_api_key", settings.apiKey)
            .apply()
    }
}
