package com.readroid.app.core.analyzer

import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipFile

/** Bounded, read-only inventory of one APK's ZIP entries. No content is read or extracted. */
data class ApkEntryInfo(
    val name: String,
    val kind: EntryKind,
    val compressedSize: Long,
    val size: Long,
    val method: Int,
    val crc32: Long
)

enum class EntryKind { DEX, NATIVE_LIB, RESOURCE, ASSET, MANIFEST, ARSC, OTHER }

data class ApkEntryInventory(
    val entries: List<ApkEntryInfo>,
    val declaredTotal: Int,
    val truncated: Boolean,
    val warning: String?
)

data class ApkEntryFilter(
    val query: String = "",
    val kind: EntryKind? = null
)

object ApkEntryInventoryReader {

    const val MAX_ENTRIES = 50_000
    private const val MAX_NAME_LENGTH = 4_096

    fun read(file: File, maxEntries: Int = MAX_ENTRIES): ApkEntryInventory {
        require(maxEntries > 0) { "maxEntries deve ser positivo." }
        val infos = ArrayList<ApkEntryInfo>(maxEntries.coerceAtMost(1_024))
        var declared = 0
        var truncated = false
        var warning: String? = null
        try {
            ZipFile(file).use { zip ->
                val it = zip.entries()
                while (it.hasMoreElements()) {
                    val entry: ZipEntry = it.nextElement()
                    declared++
                    if (infos.size >= maxEntries) {
                        truncated = true
                        warning = "Inventário truncado: o APK possui mais de $maxEntries entradas."
                        break
                    }
                    if (entry.name.length > MAX_NAME_LENGTH) {
                        truncated = true
                        warning = "Inventário truncado: nome de entrada excede $MAX_NAME_LENGTH caracteres."
                        break
                    }
                    infos += toInfo(entry)
                }
            }
        } catch (t: Throwable) {
            throw ApkEntryInventoryException("Não foi possível ler o inventário do APK: ${t.message ?: t.javaClass.simpleName}", t)
        }
        return ApkEntryInventory(entries = infos, declaredTotal = declared, truncated = truncated, warning = warning)
    }

    fun apply(inventory: ApkEntryInventory, filter: ApkEntryFilter): List<ApkEntryInfo> {
        val q = filter.query.trim().lowercase()
        return inventory.entries.asSequence()
            .filter { e -> filter.kind == null || e.kind == filter.kind }
            .filter { e -> q.isEmpty() || e.name.lowercase().contains(q) }
            .toList()
    }

    fun toInfo(entry: ZipEntry): ApkEntryInfo {
        val name = entry.name
        return ApkEntryInfo(
            name = name,
            kind = classify(name),
            compressedSize = entry.compressedSize,
            size = entry.size,
            method = entry.method,
            crc32 = entry.crc
        )
    }

    private fun classify(name: String): EntryKind = when {
        name == "AndroidManifest.xml" -> EntryKind.MANIFEST
        name == "resources.arsc" -> EntryKind.ARSC
        name.endsWith(".dex") -> EntryKind.DEX
        name.startsWith("lib/") && name.endsWith(".so") -> EntryKind.NATIVE_LIB
        name.startsWith("assets/") -> EntryKind.ASSET
        name.startsWith("res/") -> EntryKind.RESOURCE
        else -> EntryKind.OTHER
    }
}

class ApkEntryInventoryException(message: String, cause: Throwable) : Exception(message, cause)
