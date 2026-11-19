package com.readroid.app.core.ai

import org.json.JSONArray
import org.json.JSONObject
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URL

data class PromptTemplate(
    val id: String,
    val title: String,
    val description: String,
    val prompt: String,
    val warning: String? = null
)

object PromptLibrary {
    val TEMPLATES = listOf(
        PromptTemplate(
            id = "analise_seguranca",
            title = "Auditoria de Segurança do Manifesto",
            description = "Analisa permissões e componentes expostos buscando potenciais vulnerabilidades.",
            prompt = "Analise o relatório do AndroidManifest.xml deste aplicativo. Identifique permissões perigosas desnecessárias, componentes expostos sem controle de permissão e riscos de segurança associados a flags como debuggable ou allowBackup. Forneça recomendações práticas para mitigar cada risco."
        ),
        PromptTemplate(
            id = "explicar_urls",
            title = "Investigar URLs e Domínios Suspeitos",
            description = "Examina a lista de domínios e IPs extraídos do código para categorizar a finalidade.",
            prompt = "Examine a lista de URLs e domínios encontrados no código estático deste APK. Classifique-os em: serviços conhecidos (analítica, anúncios, CDN), APIs legítimas e endereços potencialmente desconhecidos ou suspeitos. Aponte se há comunicação em HTTP puro sem criptografia."
        ),
        PromptTemplate(
            id = "traduzir_interface",
            title = "Guia para Tradução de Interface",
            description = "Gera instruções e estrutura XML para tradução das strings do app.",
            prompt = "Com base no conteúdo de recursos do aplicativo, elabore um plano para tradução das strings de interface para português do Brasil (pt-BR). Indique como preservar marcadores de formatação (%s, %d) e quais chaves devem ser priorizadas."
        ),
        PromptTemplate(
            id = "otimizar_privacidade",
            title = "Recomendações de Privacidade do Usuário",
            description = "Sugere configurações do manifesto para atender às políticas da Google Play.",
            prompt = "Avalie este APK sob a perspectiva de privacidade e conformidade com as políticas do Google Play. Sugira quais permissões podem ser descartadas ou substituídas por APIs modernas (como photo picker ao invés de READ_EXTERNAL_STORAGE)."
        )
    )
}

/**
 * Cliente HTTP direto em Kotlin puro para gateways OpenAI-compatíveis e OpenRouter.
 * Não envia nenhum dado antes da confirmação explícita do usuário.
 */
object AiApiClient {

    fun executeChatCompletion(
        settings: AiSettings,
        systemPrompt: String,
        userPrompt: String,
        contextData: String
    ): String {
        require(settings.isEnabled) { "O recurso de IA está desativado." }
        require(settings.apiKey.isNotBlank()) { "Chave de API não informada." }

        val endpoint = if (settings.providerUrl.endsWith("/")) {
            "${settings.providerUrl}chat/completions"
        } else {
            "${settings.providerUrl}/chat/completions"
        }

        val url = URL(endpoint)
        val conn = url.openConnection() as HttpURLConnection
        conn.requestMethod = "POST"
        conn.setRequestProperty("Content-Type", "application/json; charset=UTF-8")
        conn.setRequestProperty("Authorization", "Bearer ${settings.apiKey.trim()}")
        conn.setRequestProperty("HTTP-Referer", "https://github.com/Odair-JDEV/Rea-APK-IA")
        conn.setRequestProperty("X-Title", "ReaDroid Android")
        conn.connectTimeout = 30000
        conn.readTimeout = 60000
        conn.doOutput = true

        val requestBody = JSONObject().apply {
            put("model", settings.modelName.trim())
            val messages = JSONArray().apply {
                put(JSONObject().apply {
                    put("role", "system")
                    put("content", systemPrompt)
                })
                put(JSONObject().apply {
                    put("role", "user")
                    put("content", "$userPrompt\n\n--- DADOS DE ANÁLISE ESTÁTICA DO APK ---\n$contextData")
                })
            }
            put("messages", messages)
            put("temperature", 0.3)
        }

        conn.outputStream.use { os ->
            os.write(requestBody.toString().toByteArray(Charsets.UTF_8))
        }

        val responseCode = conn.responseCode
        val inputStream = if (responseCode in 200..299) conn.inputStream else conn.errorStream
        val responseText = BufferedReader(InputStreamReader(inputStream, Charsets.UTF_8)).use { it.readText() }

        if (responseCode !in 200..299) {
            throw Exception("Erro da API de IA (HTTP $responseCode): $responseText")
        }

        val jsonResponse = JSONObject(responseText)
        val choices = jsonResponse.optJSONArray("choices")
        if (choices != null && choices.length() > 0) {
            val message = choices.getJSONObject(0).optJSONObject("message")
            return message?.optString("content") ?: "Resposta vazia da IA."
        }

        return "Nenhuma resposta retornada pelo modelo."
    }
}
