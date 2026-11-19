package com.readroid.app.core.editor

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * O editor roda sobre bytes de um APK de terceiros, então ele precisa recusar
 * entradas inválidas sem lançar exceção e sem alterar o conteúdo recebido.
 */
class AxmlEditorTest {

    @Test
    fun rejectsPayloadTooSmallToHoldAnAxmlHeader() {
        val garbage = byteArrayOf(0x03, 0x00)

        val result = AxmlEditor.applyQuickEdits(garbage, QuickEditsConfig(setDebuggable = true))

        assertFalse(result.isModified)
        assertTrue(result.appliedChanges.isEmpty())
        assertArrayEquals(garbage, result.modifiedBytes)
    }

    @Test
    fun rejectsDataWithoutAxmlMagicAndReturnsItUntouched() {
        val notAxml = ByteArray(64) { 0x2A }

        val result = AxmlEditor.applyQuickEdits(notAxml, QuickEditsConfig(setAllowBackup = false))

        assertFalse(result.isModified)
        assertTrue(result.appliedChanges.isEmpty())
        assertArrayEquals(notAxml, result.modifiedBytes)
    }

    @Test
    fun emptyConfigNeverReportsChanges() {
        val header = byteArrayOf(0x03, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00)

        val result = AxmlEditor.applyQuickEdits(header, QuickEditsConfig())

        assertFalse(result.isModified)
        assertEquals(0, result.appliedChanges.size)
    }

    @Test
    fun flipsExistingBooleanAttributeAndReportsTheChange() {
        val axml = manifestWithApplicationAttributes(
            "debuggable" to 0,
            "allowBackup" to 1
        )

        val result = AxmlEditor.applyQuickEdits(axml, QuickEditsConfig(setDebuggable = true))

        assertTrue(result.isModified)
        assertEquals(listOf("android:debuggable = true"), result.appliedChanges)
        assertTrue(result.missingChanges.isEmpty())
        assertEquals(0, readApplicationBoolean(axml, "debuggable"))
        assertEquals(1, readApplicationBoolean(result.modifiedBytes, "debuggable"))
        assertEquals(1, readApplicationBoolean(result.modifiedBytes, "allowBackup"))
    }

    @Test
    fun requestedAttributeAbsentIsReportedAsMissingAndBytesStayUntouched() {
        val axml = manifestWithApplicationAttributes("allowBackup" to 1)

        val result = AxmlEditor.applyQuickEdits(axml, QuickEditsConfig(setDebuggable = true))

        assertFalse("flag ausente não pode ser contada como alteração", result.isModified)
        assertTrue(result.appliedChanges.isEmpty())
        assertEquals(listOf("android:debuggable"), result.missingChanges)
        assertArrayEquals(axml, result.modifiedBytes)
    }

    @Test
    fun requestingTheCurrentBooleanValueReportsNoChange() {
        val axml = manifestWithApplicationAttributes("allowBackup" to 1)

        val result = AxmlEditor.applyQuickEdits(axml, QuickEditsConfig(setAllowBackup = true))

        assertFalse("pedir o valor atual não é uma edição", result.isModified)
        assertTrue(result.appliedChanges.isEmpty())
        assertTrue(result.missingChanges.isEmpty())
    }

    @Test
    fun editOnlyTheRequestedFlagsLeavesTheOthersIntact() {
        val axml = manifestWithApplicationAttributes(
            "debuggable" to 0,
            "allowBackup" to 1
        )

        val result = AxmlEditor.applyQuickEdits(axml, QuickEditsConfig(setAllowBackup = false))

        assertTrue(result.isModified)
        assertEquals(listOf("android:allowBackup = false"), result.appliedChanges)
        assertEquals(0, readApplicationBoolean(result.modifiedBytes, "allowBackup"))
        assertEquals(0, readApplicationBoolean(result.modifiedBytes, "debuggable"))
    }

    @Test
    fun mixedResultReportsAppliedAndMissingSeparately() {
        val axml = manifestWithApplicationAttributes(
            "allowBackup" to 0,
            "usesCleartextTraffic" to 0
        )

        val result = AxmlEditor.applyQuickEdits(
            axml,
            QuickEditsConfig(setAllowBackup = true, setCleartextTraffic = false, setDebuggable = true)
        )

        assertTrue(result.isModified)
        assertEquals(listOf("android:allowBackup = true"), result.appliedChanges)
        assertEquals(listOf("android:debuggable"), result.missingChanges)
    }

    // ------------------------------------------------------------------
    // Construção de um AXML mínimo com <application> e atributos booleanos.
    // ------------------------------------------------------------------

    private fun manifestWithApplicationAttributes(vararg attributes: Pair<String, Int>): ByteArray {
        val strings = listOf("manifest", "application") + attributes.map { it.first }
        val stringPool = buildStringPool(strings)
        val startElement = buildStartElement(strings.indexOf("application"), attributes.map { (name, value) ->
            Triple(strings.indexOf(name), value, 0)
        })
        val endNamespace = buildChunk(0x0103, ByteArray(24))

        val out = ByteArrayOutputStream()
        out.write(byteArrayOf(0x03, 0x00, 0x08, 0x00)) // header: tipo 3, tamanho 8

        val bodyBytes = stringPool + buildResourceMap(strings.size) + startElement + endNamespace
        out.write(intToLe(8 + bodyBytes.size))
        out.write(bodyBytes)

        return out.toByteArray()
    }

    private fun buildStringPool(strings: List<String>): ByteArray {
        val encoded = strings.map { value ->
            val utf16 = value.toByteArray(Charsets.UTF_16LE)
            val head = byteArrayOf((utf16.size / 2).toByte(), 0x00)
            head + utf16 + byteArrayOf(0x00, 0x00)
        }
        val headerSize = 28
        val offsetsSection = ByteArray(strings.size * 4)
        var offset = 0
        for (i in encoded.indices) {
            val offsetBytes = intToLe(offset)
            System.arraycopy(offsetBytes, 0, offsetsSection, i * 4, 4)
            offset += encoded[i].size
        }
        val stringsSection = encoded.reduce { a, b -> a + b }
        val chunkSize = headerSize + offsetsSection.size + stringsSection.size
        val chunk = ByteArrayOutputStream()
        chunk.write(shortToLe(0x0001))
        chunk.write(shortToLe(headerSize))
        chunk.write(intToLe(chunkSize))
        chunk.write(intToLe(strings.size))
        chunk.write(intToLe(0)) // styleCount
        chunk.write(intToLe(0x00000000)) // flags: UTF-16, não ordenado
        chunk.write(intToLe(headerSize + offsetsSection.size)) // stringsStart
        chunk.write(intToLe(0)) // stylesStart
        chunk.write(offsetsSection)
        chunk.write(stringsSection)
        return chunk.toByteArray()
    }

    private fun buildResourceMap(count: Int): ByteArray {
        val payload = ByteArray(count * 4)
        return buildChunk(0x0180, payload)
    }

    private fun buildStartElement(nameIndex: Int, attributes: List<Triple<Int, Int, Int>>): ByteArray {
        val attrSize = 20
        val attrStart = 20
        val chunkSize = 36 + attributes.size * attrSize
        val chunk = ByteArrayOutputStream()
        chunk.write(shortToLe(0x0102))
        chunk.write(shortToLe(16)) // headerSize
        chunk.write(intToLe(chunkSize))
        chunk.write(intToLe(0)) // lineNumber
        chunk.write(intToLe(-1)) // comment
        chunk.write(intToLe(-1)) // ns
        chunk.write(intToLe(nameIndex))
        chunk.write(shortToLe(attrStart))
        chunk.write(shortToLe(attrSize))
        chunk.write(shortToLe(attributes.size))
        chunk.write(shortToLe(0)) // idIndex
        chunk.write(shortToLe(0)) // classIndex
        chunk.write(shortToLe(0)) // styleIndex
        for ((nameIdx, dataValue, rawValueIdx) in attributes) {
            chunk.write(intToLe(-1)) // ns
            chunk.write(intToLe(nameIdx))
            chunk.write(intToLe(rawValueIdx))
            chunk.write(shortToLe(attrSize)) // typedValue size
            chunk.write(byteArrayOf(0x00, 0x12)) // res0 + dataType = TYPE_INT_BOOLEAN
            chunk.write(intToLe(dataValue))
        }
        return chunk.toByteArray()
    }

    private fun buildChunk(type: Int, payload: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(shortToLe(type))
        out.write(shortToLe(payload.size + 8))
        out.write(intToLe(payload.size + 8))
        out.write(payload)
        return out.toByteArray()
    }

    private fun readApplicationBoolean(axml: ByteArray, attributeName: String): Int {
        val buffer = ByteBuffer.wrap(axml).order(ByteOrder.LITTLE_ENDIAN)
        var pos = 8
        var stringPool: List<String> = emptyList()
        while (pos + 8 <= axml.size) {
            buffer.position(pos)
            val chunkType = buffer.short.toInt() and 0xFFFF
            val headerSize = buffer.short.toInt() and 0xFFFF
            val chunkSize = buffer.int
            if (chunkSize < 8) break
            when (chunkType) {
                0x0001 -> stringPool = com.readroid.app.core.axml.AxmlParser.parseStringPool(axml, pos)
                0x0102 -> {
                    buffer.position(pos + 20)
                    val nameIdx = buffer.int
                    val attrStart = buffer.short.toInt() and 0xFFFF
                    val attrSize = buffer.short.toInt() and 0xFFFF
                    val attrCount = buffer.short.toInt() and 0xFFFF
                    if (stringPool.getOrElse(nameIdx) { "" } == "application") {
                        for (i in 0 until attrCount) {
                            val attrPos = pos + 16 + attrStart + i * attrSize
                            buffer.position(attrPos + 4)
                            val nIdx = buffer.int
                            buffer.position(attrPos + 15)
                            val dataType = buffer.get().toInt() and 0xFF
                            buffer.position(attrPos + 16)
                            val dataVal = buffer.int
                            if (stringPool.getOrElse(nIdx) { "" } == attributeName && dataType == 0x12) {
                                return dataVal
                            }
                        }
                    }
                }
            }
            pos += chunkSize
        }
        error("atributo $attributeName não encontrado no manifesto de teste")
    }

    private fun intToLe(value: Int): ByteArray = byteArrayOf(
        (value and 0xFF).toByte(),
        ((value shr 8) and 0xFF).toByte(),
        ((value shr 16) and 0xFF).toByte(),
        ((value shr 24) and 0xFF).toByte()
    )

    private fun shortToLe(value: Int): ByteArray = byteArrayOf(
        (value and 0xFF).toByte(),
        ((value shr 8) and 0xFF).toByte()
    )
}
