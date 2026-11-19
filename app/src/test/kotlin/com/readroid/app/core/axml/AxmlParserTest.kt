package com.readroid.app.core.axml

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.ByteBuffer
import java.nio.ByteOrder

class AxmlParserTest {

    private fun buildMinimalAxml(): ByteArray {
        val strings = listOf(
            "http://schemas.android.com/apk/res/android",
            "manifest",
            "package",
            "com.example.testapp",
            "versionCode",
            "versionName",
            "1.0",
            "application",
            "label",
            "TestApp",
            "debuggable",
            "activity",
            "name",
            ".MainActivity",
            "exported"
        )

        // Monta o pool de strings
        val strOffsets = mutableListOf<Int>()
        val strBytesList = mutableListOf<ByteArray>()
        var offset = 0
        for (s in strings) {
            strOffsets.add(offset)
            val b = s.toByteArray(Charsets.UTF_8)
            val entry = byteArrayOf(s.length.toByte(), b.size.toByte()) + b + byteArrayOf(0)
            strBytesList.add(entry)
            offset += entry.size
        }
        val allStringsBytes = strBytesList.reduce { acc, bytes -> acc + bytes }

        val stringPoolHeaderSize = 28
        val stringPoolSize = stringPoolHeaderSize + (strings.size * 4) + allStringsBytes.size
        val stringPoolBuffer = ByteBuffer.allocate(stringPoolSize).order(ByteOrder.LITTLE_ENDIAN)
        stringPoolBuffer.putShort(0x0001.toShort()) // RES_STRING_POOL_TYPE
        stringPoolBuffer.putShort(stringPoolHeaderSize.toShort())
        stringPoolBuffer.putInt(stringPoolSize)
        stringPoolBuffer.putInt(strings.size)
        stringPoolBuffer.putInt(0) // style count
        stringPoolBuffer.putInt(0x100) // UTF-8 flag
        stringPoolBuffer.putInt(stringPoolHeaderSize + (strings.size * 4)) // strings start
        stringPoolBuffer.putInt(0) // styles start
        for (off in strOffsets) {
            stringPoolBuffer.putInt(off)
        }
        stringPoolBuffer.put(allStringsBytes)

        // Eventos XML
        fun makeStartElement(nameIdx: Int, attrs: List<IntArray>): ByteArray {
            val attrSize = 20
            val chunkSize = 36 + (attrs.size * attrSize)
            val buf = ByteBuffer.allocate(chunkSize).order(ByteOrder.LITTLE_ENDIAN)
            buf.putShort(0x0102.toShort())
            buf.putShort(16.toShort())
            buf.putInt(chunkSize)
            buf.putInt(1) // line
            buf.putInt(-1) // comment
            buf.putInt(-1) // ns
            buf.putInt(nameIdx)
            buf.putShort(20.toShort()) // attrStart
            buf.putShort(attrSize.toShort())
            buf.putShort(attrs.size.toShort())
            buf.putShort(0.toShort())
            buf.putShort(0.toShort())
            buf.putShort(0.toShort())
            for (attr in attrs) {
                buf.putInt(attr[0]) // ns
                buf.putInt(attr[1]) // name
                buf.putInt(attr[2]) // rawValue
                buf.putShort(8.toShort()) // size
                buf.put(0.toByte()) // res0
                buf.put(attr[3].toByte()) // dataType
                buf.putInt(attr[4]) // dataVal
            }
            return buf.array()
        }

        fun makeEndElement(nameIdx: Int): ByteArray {
            val buf = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN)
            buf.putShort(0x0103.toShort())
            buf.putShort(16.toShort())
            buf.putInt(24)
            buf.putInt(1)
            buf.putInt(-1)
            buf.putInt(-1)
            buf.putInt(nameIdx)
            return buf.array()
        }

        // <manifest package="com.example.testapp" versionCode=42 versionName="1.0">
        val startManifest = makeStartElement(
            1, listOf(
                intArrayOf(-1, 2, 3, 0x03, 3), // package
                intArrayOf(0, 4, -1, 0x10, 42), // versionCode
                intArrayOf(0, 5, 6, 0x03, 6)   // versionName
            )
        )

        // <application label="TestApp" debuggable=true>
        val startApp = makeStartElement(
            7, listOf(
                intArrayOf(0, 8, 9, 0x03, 9),
                intArrayOf(0, 10, -1, 0x12, 1)
            )
        )

        // <activity name=".MainActivity" exported=true>
        val startActivity = makeStartElement(
            11, listOf(
                intArrayOf(0, 12, 13, 0x03, 13),
                intArrayOf(0, 14, -1, 0x12, 1)
            )
        )

        val endActivity = makeEndElement(11)
        val endApp = makeEndElement(7)
        val endManifest = makeEndElement(1)

        val header = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN)
        header.putShort(0x0003.toShort())
        header.putShort(8.toShort())
        val totalSize = 8 + stringPoolSize + startManifest.size + startApp.size + startActivity.size + endActivity.size + endApp.size + endManifest.size
        header.putInt(totalSize)

        return header.array() + stringPoolBuffer.array() + startManifest + startApp + startActivity + endActivity + endApp + endManifest
    }

    @Test
    fun testParseMinimalAxml() {
        val axmlData = buildMinimalAxml()
        val parsed = AxmlParser.parse(axmlData)

        assertEquals("com.example.testapp", parsed.packageName)
        assertEquals("42", parsed.versionCode)
        assertEquals("1.0", parsed.versionName)
        assertEquals("TestApp", parsed.application.label)
        assertEquals(true, parsed.application.isDebuggable)

        assertEquals(1, parsed.components.size)
        val activity = parsed.components[0]
        assertEquals(ComponentType.ACTIVITY, activity.type)
        assertEquals(".MainActivity", activity.name)
        assertEquals(true, activity.exported)

        assertNotNull(parsed.rawXml)
        assertTrue(parsed.rawXml!!.contains("<manifest"))
        assertTrue(parsed.rawXml!!.contains("package=\"com.example.testapp\""))
    }
}
