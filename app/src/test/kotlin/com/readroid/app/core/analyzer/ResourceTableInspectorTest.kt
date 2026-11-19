package com.readroid.app.core.analyzer

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream

class ResourceTableInspectorTest {
    @Test
    fun readsBoundedUtf8GlobalStringPoolAndCountsPackages() {
        val table = table(stringPoolUtf8(listOf("hello", "res/name")), packageCount = 1)
        val result = ResourceTableInspector.inspect(table)
        assertTrue(result.stringPoolPresent)
        assertEquals(listOf("hello", "res/name"), result.strings.map { it.value })
        assertEquals(listOf(0, 1), result.strings.map { it.index })
        assertEquals(1, result.packageCount)
        assertFalse(result.isTruncated)
    }

    @Test
    fun readsUtf16PoolAndReportsUnknownChunksWithoutInterpretingThem() {
        val unknown = chunk(0x9999, byteArrayOf(1, 2, 3, 4))
        val table = table(stringPoolUtf16(listOf("á")), extra = unknown)
        val result = ResourceTableInspector.inspect(table)
        assertEquals(listOf("á"), result.strings.map { it.value })
        assertEquals(listOf(0x9999), result.unsupportedChunks)
    }

    @Test
    fun rejectsTruncatedChunkAndInvalidTableType() {
        val truncated = byteArrayOf(2, 0, 12, 0, 40, 0, 0, 0, 0, 0, 0, 0, 1, 2)
        try {
            ResourceTableInspector.inspect(truncated)
            throw AssertionError("truncated table must fail")
        } catch (_: IllegalArgumentException) { }

        val invalid = table(stringPoolUtf8(listOf("x"))).copyOf().also { it[0] = 3 }
        try {
            ResourceTableInspector.inspect(invalid)
            throw AssertionError("invalid table type must fail")
        } catch (_: ResourceTableFormatException) { }
    }

    @Test
    fun stringLimitIsExplicitlyTruncated() {
        val table = table(stringPoolUtf8(listOf("a", "b", "c")))
        val result = ResourceTableInspector.inspect(table, maxStrings = 2)
        assertTrue(result.isTruncated)
        assertTrue(result.strings.isEmpty())
        assertTrue(result.warnings.any { it.contains("2 strings") })
    }

    @Test
    fun malformedStringOffsetFailsClosed() {
        val pool = stringPoolUtf8(listOf("x")).copyOf()
        // first offset is immediately after the pool header and points outside the chunk
        val offsetPosition = 28
        pool[offsetPosition] = 0x7f
        pool[offsetPosition + 1] = 0x7f
        pool[offsetPosition + 2] = 0x7f
        pool[offsetPosition + 3] = 0x7f
        try {
            ResourceTableInspector.inspect(table(pool))
            throw AssertionError("invalid string offset must fail")
        } catch (_: ResourceTableFormatException) { }
    }

    private fun table(pool: ByteArray, packageCount: Int = 0, extra: ByteArray = byteArrayOf()): ByteArray {
        val packages = (0 until packageCount)
            .map { header(0x0200, 12) + int(0x7f000000) }
            .fold(byteArrayOf()) { a, b -> a + b }
        val body = pool + packages + extra
        return header(0x0002, 12 + body.size, packageCount) + body
    }

    private fun stringPoolUtf8(values: List<String>): ByteArray {
        val encoded = values.map { value ->
            val bytes = value.toByteArray(Charsets.UTF_8)
            // Formato Android: charLength u8, byteLength u8, dados UTF-8, terminador NUL.
            byteArrayOf(bytes.size.toByte()) + byteArrayOf(bytes.size.toByte()) + bytes + byteArrayOf(0)
        }
        val offsets = ByteArray(values.size * 4)
        var cursor = 0
        for (i in encoded.indices) {
            writeInt(offsets, i * 4, cursor)
            cursor += encoded[i].size
        }
        val stringsStart = 28 + offsets.size
        val body = offsets + encoded.fold(byteArrayOf()) { a, b -> a + b }
        return header(0x0001, 28 + body.size, values.size, flags = 0x100, stringsStart = stringsStart) + body
    }

    private fun stringPoolUtf16(values: List<String>): ByteArray {
        val encoded = values.map { value ->
            val bytes = value.toByteArray(Charsets.UTF_16LE)
            byteArrayOf((bytes.size / 2).toByte(), 0) + bytes + byteArrayOf(0, 0)
        }
        val offsets = ByteArray(values.size * 4)
        var cursor = 0
        for (i in encoded.indices) {
            writeInt(offsets, i * 4, cursor)
            cursor += encoded[i].size
        }
        val stringsStart = 28 + offsets.size
        val body = offsets + encoded.fold(byteArrayOf()) { a, b -> a + b }
        return header(0x0001, 28 + body.size, values.size, stringsStart = stringsStart) + body
    }

    private fun chunk(type: Int, payload: ByteArray): ByteArray = header(type, 8 + payload.size) + payload

    private fun header(type: Int, size: Int, count: Int = 0, flags: Int = 0, stringsStart: Int = 0): ByteArray {
        val out = ByteArrayOutputStream()
        val headerSize = when (type) {
            1 -> 28
            2 -> 12
            else -> 8
        }
        out.write(short(type)); out.write(short(headerSize)); out.write(int(size))
        if (type == 1) {
            out.write(int(count)); out.write(int(0)); out.write(int(flags)); out.write(int(stringsStart)); out.write(int(0))
        } else if (type == 2) {
            out.write(int(count))
        }
        return out.toByteArray()
    }

    private fun short(value: Int) = byteArrayOf(value.toByte(), (value ushr 8).toByte())
    private fun int(value: Int) = byteArrayOf(value.toByte(), (value ushr 8).toByte(), (value ushr 16).toByte(), (value ushr 24).toByte())
    private fun writeInt(bytes: ByteArray, offset: Int, value: Int) {
        val encoded = int(value)
        encoded.copyInto(bytes, offset)
    }
}
