package com.readroid.app.core.analyzer

import java.nio.ByteBuffer
import java.nio.ByteOrder

/** Bounded, read-only observations from an Android resources.arsc table. */
data class ResourceString(
    val index: Int,
    val value: String
)

data class ResourceTableInspection(
    val stringPoolPresent: Boolean,
    val strings: List<ResourceString>,
    val packageCount: Int,
    val chunkCount: Int,
    val isTruncated: Boolean,
    val unsupportedChunks: List<Int> = emptyList(),
    val warnings: List<String> = emptyList()
)

class ResourceTableFormatException(message: String) : Exception(message)

object ResourceTableInspector {
    private const val TABLE_TYPE = 0x0002
    private const val STRING_POOL_TYPE = 0x0001
    private const val PACKAGE_TYPE = 0x0200
    private const val HEADER_SIZE = 12
    private const val STRING_POOL_HEADER_SIZE = 28
    private const val UTF8_FLAG = 0x100
    private const val DEFAULT_MAX_BYTES = 64L * 1024 * 1024
    private const val DEFAULT_MAX_CHUNKS = 100_000
    private const val DEFAULT_MAX_STRINGS = 50_000
    private const val MAX_STRING_BYTES = 1_048_576

    fun inspect(
        data: ByteArray,
        maxBytes: Long = DEFAULT_MAX_BYTES,
        maxChunks: Int = DEFAULT_MAX_CHUNKS,
        maxStrings: Int = DEFAULT_MAX_STRINGS
    ): ResourceTableInspection {
        require(maxBytes > 0 && maxChunks > 0 && maxStrings > 0)
        require(data.size.toLong() <= maxBytes) { "resources.arsc excede o limite de leitura." }
        if (data.size < HEADER_SIZE) throw ResourceTableFormatException("Tabela de recursos truncada.")

        val tableType = u16(data, 0)
        val headerSize = u16(data, 2)
        val tableSize = u32(data, 4)
        requireChunkBounds(0, headerSize, tableSize, data.size, "cabeçalho da tabela")
        if (tableType != TABLE_TYPE) throw ResourceTableFormatException("Tipo de tabela inválido: 0x${tableType.toString(16)}.")
        if (tableSize > data.size) throw ResourceTableFormatException("Tabela de recursos truncada no tamanho declarado.")

        var offset = headerSize
        var chunkCount = 0
        var packageCount = 0
        var truncated = false
        var stringPoolPresent = false
        val strings = mutableListOf<ResourceString>()
        val unsupported = linkedSetOf<Int>()
        val warnings = mutableListOf<String>()

        while (offset < tableSize) {
            if (++chunkCount > maxChunks) {
                truncated = true
                warnings += "Limite de chunks atingido."
                break
            }
            if (offset + 8 > tableSize) throw ResourceTableFormatException("Chunk truncado no offset $offset.")
            val type = u16(data, offset)
            val chunkHeader = u16(data, offset + 2)
            val chunkSize = u32(data, offset + 4)
            requireChunkBounds(offset, chunkHeader, chunkSize, tableSize, "chunk 0x${type.toString(16)}")
            when (type) {
                STRING_POOL_TYPE -> {
                    if (!stringPoolPresent) {
                        stringPoolPresent = true
                        val parsed = parseStringPool(data, offset, chunkHeader, chunkSize, maxStrings)
                        strings += parsed.strings
                        truncated = truncated || parsed.truncated
                        warnings += parsed.warnings
                    } else {
                        warnings += "Mais de um string pool no nível da tabela."
                    }
                }
                PACKAGE_TYPE -> packageCount++
                else -> unsupported += type
            }
            offset += chunkSize
        }

        return ResourceTableInspection(
            stringPoolPresent = stringPoolPresent,
            strings = strings,
            packageCount = packageCount,
            chunkCount = chunkCount,
            isTruncated = truncated,
            unsupportedChunks = unsupported.toList(),
            warnings = warnings
        )
    }

    private data class ParsedStrings(
        val strings: List<ResourceString>,
        val truncated: Boolean,
        val warnings: List<String>
    )

    private fun parseStringPool(
        data: ByteArray,
        offset: Int,
        headerSize: Int,
        chunkSize: Int,
        maxStrings: Int
    ): ParsedStrings {
        if (headerSize < STRING_POOL_HEADER_SIZE || chunkSize < headerSize) {
            throw ResourceTableFormatException("String pool com cabeçalho inválido.")
        }
        val chunkEnd = offset + chunkSize
        val count = u32(data, offset + 8)
        val flags = u32(data, offset + 16)
        val stringsStart = u32(data, offset + 20)
        val offsetsStart = offset + headerSize
        val offsetsBytes = count.toLong() * 4L
        if (count > maxStrings) {
            return ParsedStrings(emptyList(), true, listOf("String pool excede o limite de $maxStrings strings."))
        }
        require(offsetsStart.toLong() + offsetsBytes <= chunkEnd) { "Offsets do string pool truncados." }
        require(offset + stringsStart <= chunkEnd) { "Início do string pool inválido." }

        val stringsBase = offset + stringsStart
        val utf8 = flags and UTF8_FLAG != 0
        val result = ArrayList<ResourceString>(count)
        var truncated = false
        val warnings = mutableListOf<String>()
        for (index in 0 until count) {
            val relative = u32(data, offsetsStart + index * 4)
            val position = stringsBase.toLong() + relative
            if (position >= chunkEnd) throw ResourceTableFormatException("String $index fora do chunk.")
            val decoded = decodeString(data, position.toInt(), chunkEnd, utf8)
            if (decoded == null) {
                truncated = true
                warnings += "String $index truncada ou excede o limite."
                continue
            }
            result += ResourceString(index, decoded)
        }
        return ParsedStrings(result, truncated, warnings.distinct().take(32))
    }

    private fun decodeString(data: ByteArray, start: Int, end: Int, utf8: Boolean): String? {
        var cursor = start
        if (utf8) {
            val charLength = readLength8(data, cursor, end) ?: return null
            cursor = charLength.second
            val byteLength = readLength8(data, cursor, end) ?: return null
            cursor = byteLength.second
            if (byteLength.first > MAX_STRING_BYTES || cursor + byteLength.first > end) return null
            return String(data, cursor, byteLength.first, Charsets.UTF_8)
        }
        val length = readLength16(data, cursor, end) ?: return null
        cursor = length.second
        val byteLength = length.first.toLong() * 2L
        if (byteLength > MAX_STRING_BYTES || byteLength > Int.MAX_VALUE || cursor.toLong() + byteLength > end) return null
        return String(data, cursor, byteLength.toInt(), Charsets.UTF_16LE)
    }

    private fun readLength8(data: ByteArray, start: Int, end: Int): Pair<Int, Int>? {
        if (start >= end) return null
        val first = data[start].toInt() and 0xff
        if (first and 0x80 == 0) return first to (start + 1)
        if (start + 1 >= end) return null
        return (((first and 0x7f) shl 8) or (data[start + 1].toInt() and 0xff)) to (start + 2)
    }

    private fun readLength16(data: ByteArray, start: Int, end: Int): Pair<Int, Int>? {
        if (start + 2 > end) return null
        val first = u16(data, start)
        if (first and 0x8000 == 0) return first to (start + 2)
        if (start + 4 > end) return null
        val second = u16(data, start + 2)
        return (((first and 0x7fff) shl 16) or second) to (start + 4)
    }

    private fun requireChunkBounds(offset: Int, headerSize: Int, chunkSize: Int, limit: Int, label: String) {
        require(headerSize >= 8 && chunkSize >= headerSize && offset >= 0 && offset.toLong() + chunkSize <= limit) {
            "${label} com limites inválidos."
        }
    }

    private fun u16(data: ByteArray, offset: Int): Int {
        require(offset >= 0 && offset + 2 <= data.size) { "Leitura fora dos limites." }
        return (data[offset].toInt() and 0xff) or ((data[offset + 1].toInt() and 0xff) shl 8)
    }

    private fun u32(data: ByteArray, offset: Int): Int {
        require(offset >= 0 && offset + 4 <= data.size) { "Leitura fora dos limites." }
        return u16(data, offset) or (u16(data, offset + 2) shl 16)
    }
}
