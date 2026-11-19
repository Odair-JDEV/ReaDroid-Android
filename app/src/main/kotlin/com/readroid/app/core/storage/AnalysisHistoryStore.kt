package com.readroid.app.core.storage

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/**
 * Registro de histórico de análises de APKs identificado por SHA-256.
 */
data class HistoryEntry(
    val sha256: String,
    val fileName: String,
    val fileSizeBytes: Long,
    val packageName: String?,
    val versionName: String?,
    val analyzedAt: Long,
    val reportFilePath: String? = null
)

/**
 * Gerenciador de histórico e cache local do ReaDroid.
 * Salva metadados em JSON local atômico no diretório interno do aplicativo (sem root e sem permissões extras).
 */
class AnalysisHistoryStore(private val context: Context) {

    private val historyFile: File by lazy {
        File(context.filesDir, "analysis_history.json")
    }

    /**
     * Carrega a lista completa de análises ordenadas da mais recente para a mais antiga.
     */
    @Synchronized
    fun getHistory(): List<HistoryEntry> {
        if (!historyFile.exists()) return emptyList()
        return try {
            val jsonStr = historyFile.readText(Charsets.UTF_8)
            val jsonArray = JSONArray(jsonStr)
            val list = mutableListOf<HistoryEntry>()
            for (i in 0 until jsonArray.length()) {
                val obj = jsonArray.getJSONObject(i)
                list.add(
                    HistoryEntry(
                        sha256 = obj.getString("sha256"),
                        fileName = obj.getString("fileName"),
                        fileSizeBytes = obj.getLong("fileSizeBytes"),
                        packageName = obj.optString("packageName").takeIf { it.isNotEmpty() },
                        versionName = obj.optString("versionName").takeIf { it.isNotEmpty() },
                        analyzedAt = obj.getLong("analyzedAt"),
                        reportFilePath = obj.optString("reportFilePath").takeIf { it.isNotEmpty() }
                    )
                )
            }
            list.sortedByDescending { it.analyzedAt }
        } catch (e: Exception) {
            emptyList()
        }
    }

    /**
     * Adiciona ou atualiza uma análise no histórico pelo SHA-256.
     */
    @Synchronized
    fun saveEntry(entry: HistoryEntry) {
        val current = getHistory().toMutableList()
        current.removeAll { it.sha256 == entry.sha256 }
        current.add(0, entry)

        // Mantém as 100 entradas mais recentes
        val trimmed = current.take(100)

        val jsonArray = JSONArray()
        for (item in trimmed) {
            val obj = JSONObject().apply {
                put("sha256", item.sha256)
                put("fileName", item.fileName)
                put("fileSizeBytes", item.fileSizeBytes)
                put("packageName", item.packageName ?: "")
                put("versionName", item.versionName ?: "")
                put("analyzedAt", item.analyzedAt)
                put("reportFilePath", item.reportFilePath ?: "")
            }
            jsonArray.put(obj)
        }

        val tempFile = File(context.filesDir, "analysis_history.json.tmp")
        tempFile.writeText(jsonArray.toString(2), Charsets.UTF_8)
        tempFile.renameTo(historyFile)
    }

    /**
     * Salva o relatório Markdown no diretório de relatórios do app.
     */
    fun saveReportMarkdown(sha256: String, markdown: String): File {
        val reportsDir = File(context.filesDir, "reports").apply { mkdirs() }
        val reportFile = File(reportsDir, "report_${sha256.take(12)}.md")
        reportFile.writeText(markdown, Charsets.UTF_8)
        return reportFile
    }

    /**
     * Limpa todo o histórico.
     */
    @Synchronized
    fun clearHistory() {
        if (historyFile.exists()) {
            historyFile.delete()
        }
        File(context.filesDir, "reports").deleteRecursively()
    }
}
