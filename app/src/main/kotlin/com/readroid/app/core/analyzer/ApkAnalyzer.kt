package com.readroid.app.core.analyzer

import com.readroid.app.core.axml.AxmlException
import com.readroid.app.core.axml.AxmlParser
import com.readroid.app.core.axml.ParsedManifest
import java.io.File
import java.io.InputStream
import java.security.MessageDigest
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipInputStream

data class ApkInspectionResult(
    val fileName: String,
    val fileSizeBytes: Long,
    val sha256: String,
    val zipEntryCount: Int,
    val dexFiles: List<String>,
    val nativeLibraries: List<String>,
    val resourceFileCount: Int,
    val assetFileCount: Int,
    val hasManifest: Boolean,
    val manifest: ParsedManifest? = null,
    val warnings: List<String> = emptyList()
)

data class StringScanResult(
    val urls: Set<String>,
    val domains: Set<String>,
    val ipv4Candidates: Set<String>,
    val isTruncated: Boolean,
    val scannedBytes: Long
)

/**
 * Motor de análise estática e segura de arquivos APK.
 * Opera estritamente em modo somente-leitura e offline.
 */
object ApkAnalyzer {

    private const val MAX_ENTRY_BYTES = 64L * 1024 * 1024 // 64 MB por entrada
    private const val MAX_TOTAL_SCAN_BYTES = 256L * 1024 * 1024 // 256 MB total
    private const val MAX_REPORT_ITEMS = 3000

    private val URL_REGEX = Regex("""https?://[^\s\x00"'<>]{4,500}""", RegexOption.IGNORE_CASE)

    // TLDs válidos conforme a regra do ReaDroid para evitar falsos positivos
    private const val TLDS = "com|net|org|io|dev|app|gov|edu|mil|info|biz|name|pro|xyz|top|online|site|club|vip|link|click|" +
            "shop|store|live|icu|buzz|cyou|work|space|tech|cc|ws|pw|su|me|co|ai|br|ru|cn|tk|ml|ga|cf|gq|" +
            "onion|duckdns|ngrok"

    private val DOMAIN_REGEX = Regex("""(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:$TLDS)\b""")
    private val IPV4_REGEX = Regex("""(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9.])""")

    private val NOT_DOMAIN_PREFIXES = listOf(
        "android.", "androidx.", "java.", "javax.", "kotlin.", "kotlinx.", "dalvik.",
        "com.android.", "com.google.android.", "org.apache.", "org.json.", "org.w3c.",
        "org.xml.", "sun.", "libcore."
    )

    /**
     * Calcula o SHA-256 de um InputStream sem carregar o arquivo todo em memória.
     */
    fun calculateSha256(inputStream: InputStream): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val buffer = ByteArray(1024 * 1024) // 1 MB buffer
        var bytesRead: Int
        while (inputStream.read(buffer).also { bytesRead = it } != -1) {
            digest.update(buffer, 0, bytesRead)
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }

    /**
     * Inspeciona a estrutura ZIP do APK e extrai metadados do AXML.
     */
    fun inspectApk(file: File): ApkInspectionResult {
        require(file.exists() && file.isFile) { "Arquivo APK não encontrado: ${file.path}" }
        require(file.length() > 0) { "O arquivo APK está vazio." }

        val warnings = mutableListOf<String>()
        val ext = file.extension.lowercase()
        if (ext !in listOf("apk", "apks", "xapk", "1")) {
            warnings.add("Extensão incomum (.$ext); analisando pelo conteúdo ZIP.")
        }

        val sha256 = file.inputStream().use { calculateSha256(it) }

        var entryCount = 0
        val dexFiles = mutableListOf<String>()
        val nativeLibs = mutableListOf<String>()
        var resCount = 0
        var assetCount = 0
        var manifestBytes: ByteArray? = null

        val dexRegex = Regex("""classes(?:\d+)?\.dex""")

        ZipFile(file).use { zip ->
            val entries = zip.entries()
            while (entries.hasMoreElements()) {
                val entry = entries.nextElement()
                entryCount++
                val name = entry.name

                if (dexRegex.matches(name)) {
                    dexFiles.add(name)
                } else if (name.startsWith("lib/") && name.endsWith(".so")) {
                    nativeLibs.add(name)
                } else if (name.startsWith("res/")) {
                    resCount++
                } else if (name.startsWith("assets/")) {
                    assetCount++
                } else if (name == "AndroidManifest.xml") {
                    if (entry.size in 1..MAX_ENTRY_BYTES || entry.size == -1L) {
                        manifestBytes = zip.getInputStream(entry)?.use { it.readBytes() }
                    }
                }
            }
        }

        var parsedManifest: ParsedManifest? = null
        manifestBytes?.let { bytes ->
            try {
                parsedManifest = AxmlParser.parse(bytes)
            } catch (e: Throwable) {
                warnings.add("Falha ao decodificar AXML nativo: ${e.message ?: e.javaClass.simpleName}")
            }
        }

        return ApkInspectionResult(
            fileName = file.name,
            fileSizeBytes = file.length(),
            sha256 = sha256,
            zipEntryCount = entryCount,
            dexFiles = dexFiles.sorted(),
            nativeLibraries = nativeLibs.sorted(),
            resourceFileCount = resCount,
            assetFileCount = assetCount,
            hasManifest = manifestBytes != null,
            manifest = parsedManifest,
            warnings = warnings
        )
    }

    /**
     * Realiza varredura de strings estáticas (URLs, domínios e IPs) respeitando quotas rígidas.
     */
    fun scanStrings(file: File): StringScanResult {
        val urls = LinkedHashSet<String>()
        val domains = LinkedHashSet<String>()
        val ips = LinkedHashSet<String>()
        var truncated = false
        var totalScanned = 0L

        ZipFile(file).use { zip ->
            val entries = zip.entries()
            while (entries.hasMoreElements()) {
                val entry = entries.nextElement()
                if (entry.isDirectory || (entry.size > MAX_ENTRY_BYTES && entry.size != -1L)) continue

                val lower = entry.name.lowercase()
                val isRelevant = lower.endsWith(".dex") || lower.endsWith(".xml") ||
                        lower.endsWith(".arsc") || lower.endsWith(".so") ||
                        lower.endsWith(".json") || lower.endsWith(".txt") ||
                        lower.startsWith("assets/")

                if (!isRelevant) continue
                if (totalScanned >= MAX_TOTAL_SCAN_BYTES) {
                    truncated = true
                    break
                }

                val stream = zip.getInputStream(entry) ?: continue
                val bytes = stream.use { it.readBytes() }
                totalScanned += bytes.size

                val text = String(bytes, Charsets.ISO_8859_1) // ISO-8859-1 preserva bytes 1:1

                URL_REGEX.findAll(text).forEach { match ->
                    if (urls.size < MAX_REPORT_ITEMS) urls.add(match.value) else truncated = true
                }

                DOMAIN_REGEX.findAll(text).forEach { match ->
                    val domain = match.value.lowercase()
                    val isBlacklisted = NOT_DOMAIN_PREFIXES.any { domain.startsWith(it) }
                    if (!isBlacklisted) {
                        if (domains.size < MAX_REPORT_ITEMS) domains.add(domain) else truncated = true
                    }
                }

                IPV4_REGEX.findAll(text).forEach { match ->
                    val ip = match.value
                    if (isValidIpv4(ip)) {
                        if (ips.size < MAX_REPORT_ITEMS) ips.add(ip) else truncated = true
                    }
                }
            }
        }

        return StringScanResult(
            urls = urls,
            domains = domains,
            ipv4Candidates = ips,
            isTruncated = truncated,
            scannedBytes = totalScanned
        )
    }

    private fun isValidIpv4(ip: String): Boolean {
        val parts = ip.split(".")
        if (parts.size != 4) return false
        return parts.all {
            val num = it.toIntOrNull() ?: return false
            num in 0..255 && (it == "0" || !it.startsWith("0"))
        }
    }

    /**
     * Inspeciona o string pool global do resources.arsc de forma limitada e somente leitura.
     * Retorna null quando o APK não contém a tabela de recursos.
     */
    fun inspectResourceTable(file: File): ResourceTableInspection? {
        ZipFile(file).use { zip ->
            val entry = zip.getEntry("resources.arsc") ?: return null
            val bytes = zip.getInputStream(entry).use { input ->
                val buffer = ByteArray(64 * 1024)
                val output = java.io.ByteArrayOutputStream()
                var total = 0L
                while (true) {
                    val read = input.read(buffer)
                    if (read < 0) break
                    total += read
                    require(total <= ResourceTableInspectorLimits.MAX_TABLE_BYTES) {
                        "resources.arsc excede o limite de leitura."
                    }
                    output.write(buffer, 0, read)
                }
                output.toByteArray()
            }
            return ResourceTableInspector.inspect(bytes)
        }
    }
}

/** Constantes compartilhadas de quota da tabela de recursos. */
private object ResourceTableInspectorLimits {
    const val MAX_TABLE_BYTES = 64L * 1024 * 1024
}
